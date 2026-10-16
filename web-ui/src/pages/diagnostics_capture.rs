//! Diagnostics: packet capture with a filter builder, a live view and a pcap
//! download.
//!
//! The filter is a list of groups; a packet must match every group, and a group
//! matches when any of its rows does. Rows are typed and are turned into
//! `keystone_core::capture` conditions. The expression shown under the builder is
//! produced by the same function the daemon uses, so what is previewed is what
//! tcpdump will be given. The daemon takes one capture at a time and keeps its
//! file until the next one starts.

use crate::api;
use crate::components::download_bytes;
use crate::components::form_utils::{event_target_checked, event_target_value};
use gloo_timers::callback::{Interval, Timeout};
use keystone_core::capture::{
    CaptureClause, CaptureDetail, CaptureDirection, CaptureFilter, CaptureGroup, CaptureInfo,
    CaptureLine, CaptureProtocol, CaptureRequest, CaptureState, DEFAULT_PACKETS, DEFAULT_SECONDS,
    DEFAULT_SNAPLEN, DhcpMessageType, FilterTerm, MAX_CLAUSES, MAX_GROUPS,
};
use leptos::prelude::*;
use leptos::task::spawn_local;

/// How often the live view asks the daemon for new lines.
const POLL_MS: u32 = 1_000;
/// Lines kept in the page. Older ones scroll out; the download has them all.
const MAX_PAGE_LINES: usize = 3_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RowKind {
    Protocol,
    Host,
    Net,
    Port,
    Mac,
    Dhcp,
}

impl RowKind {
    const ALL: [RowKind; 6] = [
        RowKind::Protocol,
        RowKind::Host,
        RowKind::Net,
        RowKind::Port,
        RowKind::Mac,
        RowKind::Dhcp,
    ];

    fn value(self) -> &'static str {
        match self {
            RowKind::Protocol => "protocol",
            RowKind::Host => "host",
            RowKind::Net => "net",
            RowKind::Port => "port",
            RowKind::Mac => "mac",
            RowKind::Dhcp => "dhcp",
        }
    }

    fn label(self) -> &'static str {
        match self {
            RowKind::Protocol => "Protocol",
            RowKind::Host => "IP address",
            RowKind::Net => "Network",
            RowKind::Port => "Port",
            RowKind::Mac => "MAC address",
            RowKind::Dhcp => "DHCPv4 message",
        }
    }

    fn from_value(value: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|kind| kind.value() == value)
            .unwrap_or(RowKind::Protocol)
    }

    fn placeholder(self) -> &'static str {
        match self {
            RowKind::Protocol | RowKind::Dhcp => "",
            RowKind::Host => "192.168.1.20 or 2001:db8::1",
            RowKind::Net => "192.168.1.0/24",
            RowKind::Port => "53",
            RowKind::Mac => "aa:bb:cc:dd:ee:ff",
        }
    }

    /// What a new row of this kind starts with.
    fn default_value(self) -> &'static str {
        match self {
            RowKind::Protocol => "tcp",
            RowKind::Dhcp => "discover",
            _ => "",
        }
    }
}

/// One filter row as plain data.
#[derive(Clone, PartialEq, Debug)]
struct ClauseSpec {
    negate: bool,
    kind: RowKind,
    direction: CaptureDirection,
    value: String,
    /// End of a port range; empty for a single port.
    last: String,
}

impl ClauseSpec {
    fn new(kind: RowKind, value: &str) -> Self {
        Self {
            negate: false,
            kind,
            direction: CaptureDirection::Any,
            value: value.to_string(),
            last: String::new(),
        }
    }
}

/// The option value used for a DHCP message type in the page.
fn dhcp_value(message: DhcpMessageType) -> String {
    message.label().to_lowercase()
}

fn parse_port(text: &str) -> Result<u16, String> {
    text.trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("'{}' is not a port (1-65535)", text.trim()))
}

/// Turn a row into a clause, or say what is wrong with it. The clause is also
/// run through the daemon's own expression builder, so a row that previews
/// fine is a row the daemon accepts.
fn clause_from_spec(spec: &ClauseSpec) -> Result<CaptureClause, String> {
    let term = match spec.kind {
        RowKind::Protocol => FilterTerm::Protocol {
            protocol: CaptureProtocol::ALL
                .into_iter()
                .find(|protocol| protocol.as_str() == spec.value)
                .ok_or_else(|| "choose a protocol".to_string())?,
        },
        RowKind::Host => FilterTerm::Host {
            direction: spec.direction,
            address: spec.value.clone(),
        },
        RowKind::Net => FilterTerm::Net {
            direction: spec.direction,
            network: spec.value.clone(),
        },
        RowKind::Port => FilterTerm::Port {
            direction: spec.direction,
            first: parse_port(&spec.value)?,
            last: match spec.last.trim() {
                "" => None,
                last => Some(parse_port(last)?),
            },
        },
        RowKind::Mac => FilterTerm::Mac {
            direction: spec.direction,
            address: spec.value.clone(),
        },
        RowKind::Dhcp => FilterTerm::DhcpMessage {
            message_type: DhcpMessageType::ALL
                .into_iter()
                .find(|message| dhcp_value(*message) == spec.value)
                .ok_or_else(|| "choose a DHCP message type".to_string())?,
        },
    };
    term.to_expression()?;
    Ok(CaptureClause {
        negate: spec.negate,
        term,
    })
}

/// Rows of which at least one must match.
#[derive(Clone, PartialEq, Debug)]
struct GroupSpec {
    /// Inverts the whole group. Only meaningful for more than one row; a
    /// single row is negated on the row itself.
    negate: bool,
    any: Vec<ClauseSpec>,
}

impl GroupSpec {
    fn one(spec: ClauseSpec) -> Self {
        Self {
            negate: false,
            any: vec![spec],
        }
    }

    fn any_of(any: Vec<ClauseSpec>) -> Self {
        Self { negate: false, any }
    }
}

/// Turn a group into a core group, or say what is wrong. `number` is the
/// group's place in the filter, for the message.
fn group_from_spec(spec: &GroupSpec, number: usize) -> Result<CaptureGroup, String> {
    let many = spec.any.len() > 1;
    let any = spec
        .any
        .iter()
        .enumerate()
        .map(|(index, row)| {
            clause_from_spec(row).map_err(|error| {
                if many {
                    format!("condition {number}, alternative {}: {error}", index + 1)
                } else {
                    format!("condition {number}: {error}")
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CaptureGroup {
        negate: spec.negate,
        any,
    })
}

/// A ready-made filter.
struct Preset {
    label: &'static str,
    /// Shown as a tooltip.
    hint: &'static str,
    groups: Vec<GroupSpec>,
    /// Decode detail and MAC display to switch to, when the filter needs them
    /// to be useful.
    detail: Option<CaptureDetail>,
    link_level: Option<bool>,
}

fn port_spec(first: &str, last: &str) -> ClauseSpec {
    ClauseSpec {
        last: last.to_string(),
        ..ClauseSpec::new(RowKind::Port, first)
    }
}

fn dhcp_spec(message: DhcpMessageType) -> ClauseSpec {
    ClauseSpec::new(RowKind::Dhcp, &dhcp_value(message))
}

fn protocol_spec(protocol: &str) -> ClauseSpec {
    ClauseSpec::new(RowKind::Protocol, protocol)
}

/// Conditions that are added to the filter, so they combine with a host or
/// anything else already there.
fn add_ons() -> Vec<Preset> {
    let plain = |label, hint, groups| Preset {
        label,
        hint,
        groups,
        detail: None,
        link_level: None,
    };
    vec![
        plain("DNS", "Port 53", vec![GroupSpec::one(port_spec("53", ""))]),
        plain(
            "DHCPv4 ports",
            "UDP ports 67 and 68",
            vec![GroupSpec::one(port_spec("67", "68"))],
        ),
        plain(
            "NTP",
            "Port 123",
            vec![GroupSpec::one(port_spec("123", ""))],
        ),
        plain(
            "ARP",
            "Address resolution",
            vec![GroupSpec::one(protocol_spec("arp"))],
        ),
        plain(
            "Ping",
            "ICMPv4 echo and friends",
            vec![GroupSpec::one(protocol_spec("icmp"))],
        ),
        plain(
            "Not SSH",
            "Hide port 22, such as your own session",
            vec![GroupSpec::one(ClauseSpec {
                negate: true,
                ..port_spec("22", "")
            })],
        ),
    ]
}

/// Filters for chasing the ISP's DHCPv4 and IPv4 fault. Each replaces the
/// filter. Run them on the WAN interface. See what the router sends after a
/// restart: a DISCOVER with no option 50 is the case that goes wrong, an
/// INIT-REBOOT REQUEST (it carries option 50) is the safe one.
fn scenarios() -> Vec<Preset> {
    let dhcp = |label, hint, groups| Preset {
        label,
        hint,
        groups,
        detail: Some(CaptureDetail::Verbose),
        link_level: Some(true),
    };
    vec![
        dhcp(
            "DHCPv4 exchange",
            "Every DHCPv4 packet in both directions, with options (53, 50, 61)",
            vec![
                GroupSpec::one(protocol_spec("udp")),
                GroupSpec::one(port_spec("67", "68")),
            ],
        ),
        dhcp(
            "DISCOVER",
            "Fresh DISCOVERs only. A DISCOVER while the ISP still holds the lease is the trigger",
            vec![GroupSpec::one(dhcp_spec(DhcpMessageType::Discover))],
        ),
        dhcp(
            "REQUEST",
            "REQUESTs only. With option 50 it is an INIT-REBOOT or SELECTING request",
            vec![GroupSpec::one(dhcp_spec(DhcpMessageType::Request))],
        ),
        dhcp(
            "RELEASE",
            "DHCPRELEASE only, to confirm one is really on the wire",
            vec![GroupSpec::one(dhcp_spec(DhcpMessageType::Release))],
        ),
        dhcp(
            "Server replies",
            "OFFER, ACK and NAK from the ISP",
            vec![GroupSpec::any_of(vec![
                dhcp_spec(DhcpMessageType::Offer),
                dhcp_spec(DhcpMessageType::Ack),
                dhcp_spec(DhcpMessageType::Nak),
            ])],
        ),
        dhcp(
            "DHCPv4 + DHCPv6",
            "Both clients restarting together, ports 67-68 and 546-547",
            vec![GroupSpec::any_of(vec![
                port_spec("67", "68"),
                port_spec("546", "547"),
            ])],
        ),
        Preset {
            label: "ARP + ping",
            hint: "Gateway reachability while broken: ARP answered but ICMP silent",
            groups: vec![GroupSpec::any_of(vec![
                protocol_spec("arp"),
                protocol_spec("icmp"),
            ])],
            detail: Some(CaptureDetail::Normal),
            link_level: Some(true),
        },
        Preset {
            label: "IPv4 without DHCP",
            hint: "The IPv4 data path, with the DHCP chatter removed",
            groups: vec![
                GroupSpec::one(protocol_spec("ip")),
                GroupSpec::one(ClauseSpec {
                    negate: true,
                    ..port_spec("67", "68")
                }),
            ],
            detail: Some(CaptureDetail::Normal),
            link_level: Some(false),
        },
    ]
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let bytes = bytes as f64;
    if bytes < KIB {
        format!("{bytes:.0} B")
    } else if bytes < KIB * KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{:.1} MiB", bytes / (KIB * KIB))
    }
}

/// A sentence for the status line.
fn status_text(info: &CaptureInfo) -> String {
    let base = match info.state {
        CaptureState::Running => "Capturing".to_string(),
        CaptureState::Finished => "Finished: packet limit reached".to_string(),
        CaptureState::Stopped => {
            format!("Stopped: {}", info.message.as_deref().unwrap_or("stopped"))
        }
        CaptureState::Failed => format!(
            "Failed: {}",
            info.message.as_deref().unwrap_or("unknown error")
        ),
    };
    format!(
        "{base} on {}: {} packets, {}",
        info.request.interface,
        info.packets,
        format_bytes(info.bytes)
    )
}

/// A filter row whose fields are signals, so typing in one never rebuilds the
/// others.
#[derive(Clone, Copy)]
struct ClauseRow {
    id: u32,
    negate: RwSignal<bool>,
    kind: RwSignal<RowKind>,
    direction: RwSignal<CaptureDirection>,
    value: RwSignal<String>,
    last: RwSignal<String>,
}

impl ClauseRow {
    fn new(id: u32, spec: ClauseSpec) -> Self {
        Self {
            id,
            negate: RwSignal::new(spec.negate),
            kind: RwSignal::new(spec.kind),
            direction: RwSignal::new(spec.direction),
            value: RwSignal::new(spec.value),
            last: RwSignal::new(spec.last),
        }
    }

    fn spec(&self) -> ClauseSpec {
        ClauseSpec {
            negate: self.negate.get(),
            kind: self.kind.get(),
            direction: self.direction.get(),
            value: self.value.get(),
            last: self.last.get(),
        }
    }
}

/// A group of rows, any one of which may match.
#[derive(Clone, Copy)]
struct GroupRow {
    id: u32,
    negate: RwSignal<bool>,
    rows: RwSignal<Vec<ClauseRow>>,
}

impl GroupRow {
    fn spec(&self) -> GroupSpec {
        GroupSpec {
            negate: self.negate.get(),
            any: self.rows.get().iter().map(ClauseRow::spec).collect(),
        }
    }
}

/// Hands out ids for rows and groups, which only need to differ from each other.
#[derive(Clone, Copy)]
struct Ids(StoredValue<u32>);

impl Ids {
    fn next(self) -> u32 {
        let id = self.0.get_value();
        self.0.set_value(id + 1);
        id
    }

    fn group(self, spec: GroupSpec) -> GroupRow {
        GroupRow {
            id: self.next(),
            negate: RwSignal::new(spec.negate),
            rows: RwSignal::new(
                spec.any
                    .into_iter()
                    .map(|row| ClauseRow::new(self.next(), row))
                    .collect(),
            ),
        }
    }
}

fn direction_value(direction: CaptureDirection) -> &'static str {
    match direction {
        CaptureDirection::Any => "any",
        CaptureDirection::Src => "src",
        CaptureDirection::Dst => "dst",
    }
}

fn direction_from_value(value: &str) -> CaptureDirection {
    match value {
        "src" => CaptureDirection::Src,
        "dst" => CaptureDirection::Dst,
        _ => CaptureDirection::Any,
    }
}

fn detail_value(detail: CaptureDetail) -> &'static str {
    match detail {
        CaptureDetail::Normal => "normal",
        CaptureDetail::Verbose => "verbose",
        CaptureDetail::VeryVerbose => "very_verbose",
    }
}

fn detail_from_value(value: &str) -> CaptureDetail {
    match value {
        "verbose" => CaptureDetail::Verbose,
        "very_verbose" => CaptureDetail::VeryVerbose,
        _ => CaptureDetail::Normal,
    }
}

const INPUT_CLASS: &str =
    "px-2 py-1.5 bg-gray-700 text-gray-200 rounded border border-gray-600 text-sm";
const BUTTON_CLASS: &str = "px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-100 rounded border border-gray-600 text-sm disabled:opacity-50";
const PRIMARY_BUTTON_CLASS: &str =
    "px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm disabled:opacity-50";
const CHIP_CLASS: &str = "px-2 py-1 bg-gray-700/60 hover:bg-gray-600 text-gray-200 rounded text-xs border border-gray-600";

#[component]
pub fn DiagnosticsCapturePage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());

    let interfaces = RwSignal::new(vec!["any".to_string()]);
    let interface = RwSignal::new(String::new());
    let groups = RwSignal::new(Vec::<GroupRow>::new());
    let ids = Ids(StoredValue::new(0u32));
    let packets = RwSignal::new(DEFAULT_PACKETS.to_string());
    let seconds = RwSignal::new(DEFAULT_SECONDS.to_string());
    let snaplen = RwSignal::new(DEFAULT_SNAPLEN.to_string());
    let detail = RwSignal::new(CaptureDetail::Normal);
    let link_level = RwSignal::new(false);

    let info = RwSignal::new(None::<CaptureInfo>);
    let lines = RwSignal::new(Vec::<CaptureLine>::new());
    let lost = RwSignal::new(0u64);
    let follow = RwSignal::new(true);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    // Whether the live view is still asking for lines, and where it is up to.
    let polling = RwSignal::new(false);
    let in_flight = StoredValue::new(false);
    let cursor = StoredValue::new(0u64);
    let output = NodeRef::<leptos::html::Div>::new();

    let running = move || {
        info.with(|info| {
            info.as_ref()
                .is_some_and(|info| info.state == CaptureState::Running)
        })
    };

    let report = move |message: String| {
        if message.contains("Unauthorized") {
            on_unauthorized.run(());
        } else {
            error.set(Some(message));
        }
    };

    // Add groups to the filter, refusing to go past the limits.
    let add_groups = move |specs: Vec<GroupSpec>| {
        let existing = groups.with_untracked(|groups| groups.len());
        let terms: usize = groups.with_untracked(|groups| {
            groups
                .iter()
                .map(|group| group.rows.with_untracked(|rows| rows.len()))
                .sum()
        });
        let adding: usize = specs.iter().map(|group| group.any.len()).sum();
        if existing + specs.len() > MAX_GROUPS || terms + adding > MAX_CLAUSES {
            error.set(Some(format!(
                "A filter may have at most {MAX_GROUPS} groups and {MAX_CLAUSES} conditions"
            )));
            return;
        }
        groups.update(|groups| {
            groups.extend(specs.into_iter().map(|spec| ids.group(spec)));
        });
    };

    // The filter, or the first row's problem.
    let filter = Memo::new(move |_| {
        groups
            .get()
            .iter()
            .enumerate()
            .map(|(index, group)| group_from_spec(&group.spec(), index + 1))
            .collect::<Result<Vec<_>, String>>()
            .map(|groups| CaptureFilter { groups })
    });
    let expression = Memo::new(move |_| filter.get().and_then(|filter| filter.to_expression()));

    // Learn the interfaces, and pick up a capture that is already there.
    Effect::new(move |_| {
        let token_value = token.get();
        if token_value.is_empty() {
            return;
        }
        spawn_local(async move {
            match api::fetch_capture_state(&token_value).await {
                Ok(state) => {
                    if interface.get_untracked().is_empty() {
                        let first = state
                            .interfaces
                            .iter()
                            .find(|name| *name != "any")
                            .or(state.interfaces.first())
                            .cloned()
                            .unwrap_or_default();
                        interface.set(first);
                    }
                    interfaces.set(state.interfaces);
                    if state.capture.is_some() {
                        info.set(state.capture);
                        polling.set(true);
                    }
                }
                Err(message) => report(message),
            }
        });
    });

    let poll = move || {
        if !polling.get_untracked() || in_flight.get_value() {
            return;
        }
        let token_value = token.get_untracked();
        if token_value.is_empty() {
            return;
        }
        in_flight.set_value(true);
        let since = cursor.get_value();
        spawn_local(async move {
            match api::fetch_capture_packets(&token_value, since).await {
                Ok(response) => {
                    cursor.set_value(response.next);
                    lost.update(|total| *total += response.lost);
                    let ended = response
                        .info
                        .as_ref()
                        .is_none_or(|info| info.state != CaptureState::Running);
                    let quiet = response.lines.is_empty();
                    if !quiet {
                        lines.update(|rows| {
                            rows.extend(response.lines);
                            if rows.len() > MAX_PAGE_LINES {
                                rows.drain(..rows.len() - MAX_PAGE_LINES);
                            }
                        });
                    }
                    info.set(response.info);
                    // Nothing more will come once it has ended and the last
                    // lines have been read.
                    if ended && quiet {
                        polling.set(false);
                    }
                }
                Err(message) => {
                    polling.set(false);
                    report(message);
                }
            }
            in_flight.set_value(false);
        });
    };

    // The Effect keeps the Interval alive while the page is shown.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            Some(Interval::new(POLL_MS, poll))
        }
    });

    // Keep the newest line in view while following.
    Effect::new(move |_| {
        lines.track();
        if follow.get_untracked() {
            Timeout::new(0, move || {
                if let Some(element) = output.get_untracked() {
                    element.set_scroll_top(element.scroll_height());
                }
            })
            .forget();
        }
    });

    let start = move |_| {
        error.set(None);
        let filter = match filter.get_untracked() {
            Ok(filter) => filter,
            Err(message) => {
                error.set(Some(message));
                return;
            }
        };
        let number = |text: String, name: &str| {
            text.trim()
                .parse::<u32>()
                .map_err(|_| format!("{name} must be a whole number"))
        };
        let request = (|| {
            Ok::<_, String>(CaptureRequest {
                interface: interface.get_untracked(),
                filter,
                snaplen: number(snaplen.get_untracked(), "Snapshot length")?,
                max_packets: number(packets.get_untracked(), "Packet limit")?,
                max_seconds: number(seconds.get_untracked(), "Time limit")?,
                detail: detail.get_untracked(),
                link_level: link_level.get_untracked(),
            })
        })();
        let request = match request {
            Ok(request) => request,
            Err(message) => {
                error.set(Some(message));
                return;
            }
        };
        if let Err(message) = request.validate() {
            error.set(Some(message));
            return;
        }
        let token_value = token.get_untracked();
        busy.set(true);
        spawn_local(async move {
            match api::start_capture(&token_value, &request).await {
                Ok(started) => {
                    lines.set(Vec::new());
                    lost.set(0);
                    cursor.set_value(0);
                    info.set(Some(started));
                    polling.set(true);
                }
                Err(message) => report(message),
            }
            busy.set(false);
        });
    };

    let stop = move |_| {
        let token_value = token.get_untracked();
        busy.set(true);
        spawn_local(async move {
            match api::stop_capture(&token_value).await {
                Ok(stopped) => {
                    info.set(Some(stopped));
                    polling.set(true);
                }
                Err(message) => report(message),
            }
            busy.set(false);
        });
    };

    let discard = move |_| {
        let token_value = token.get_untracked();
        spawn_local(async move {
            match api::discard_capture(&token_value).await {
                Ok(_) => {
                    info.set(None);
                    lines.set(Vec::new());
                    lost.set(0);
                    cursor.set_value(0);
                    polling.set(false);
                }
                Err(message) => report(message),
            }
        });
    };

    let download = move |_| {
        let Some(current) = info.get_untracked() else {
            return;
        };
        let token_value = token.get_untracked();
        spawn_local(async move {
            match api::download_capture(&token_value).await {
                Ok(bytes) => {
                    let filename = format!(
                        "keystone-{}-{}.pcap",
                        current.request.interface, current.started_at
                    );
                    if let Err(message) =
                        download_bytes(&filename, &bytes, "application/vnd.tcpdump.pcap")
                    {
                        error.set(Some(message));
                    }
                }
                Err(message) => report(message),
            }
        });
    };

    view! {
        <div class="space-y-4">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Packet capture"</h1>
                <p class="text-gray-400 text-sm">
                    "Capture traffic on an interface with tcpdump, watch it live, then download the pcap for Wireshark. One capture at a time; the file is kept in memory until you start another or discard it."
                </p>
            </div>

            {move || error.get().map(|message| view! {
                <div role="alert" class="bg-red-900/50 border border-red-500 text-red-200 px-4 py-3 rounded text-sm">
                    {message}
                </div>
            })}

            // Status of the current capture
            <Show when=move || info.with(|info| info.is_some())>
                <div class="bg-gray-800 rounded-lg p-4 space-y-3">
                    <div class="flex flex-wrap items-center justify-between gap-3">
                        <div class="space-y-1">
                            <p class="text-gray-100 text-sm">
                                {move || info.get().map(|info| status_text(&info)).unwrap_or_default()}
                            </p>
                            <p class="text-gray-500 text-xs font-mono break-all">
                                {move || info.get().map(|info| {
                                    if info.expression.is_empty() {
                                        "filter: (everything)".to_string()
                                    } else {
                                        format!("filter: {}", info.expression)
                                    }
                                }).unwrap_or_default()}
                            </p>
                            {move || info.get().and_then(|info| info.dropped_by_kernel).filter(|n| *n > 0).map(|n| view! {
                                <p class="text-amber-300 text-xs">
                                    {format!("The kernel dropped {n} packets because the capture could not keep up. Narrow the filter or shorten the snapshot length.")}
                                </p>
                            })}
                        </div>
                        <div class="flex gap-2">
                            <Show when=running>
                                <button class=PRIMARY_BUTTON_CLASS prop:disabled=move || busy.get() on:click=stop>
                                    "Stop"
                                </button>
                            </Show>
                            <Show when=move || !running() && info.with(|info| info.as_ref().is_some_and(|info| info.has_pcap))>
                                <button class=PRIMARY_BUTTON_CLASS on:click=download>"Download pcap"</button>
                            </Show>
                            <Show when=move || !running()>
                                <button class=BUTTON_CLASS on:click=discard>"Discard"</button>
                            </Show>
                        </div>
                    </div>
                </div>
            </Show>

            // The filter builder and limits. Hidden while a capture runs.
            <Show when=move || !running()>
                <div class="bg-gray-800 rounded-lg p-4 space-y-4">
                    <h2 class="text-lg font-medium text-gray-200">"New capture"</h2>

                    <label class="block space-y-1">
                        <span class="text-sm text-gray-300">"Interface"</span>
                        <select
                            class=format!("{INPUT_CLASS} w-full md:w-64")
                            prop:value=move || interface.get()
                            on:change=move |ev| interface.set(event_target_value(&ev))
                        >
                            {move || interfaces.get().into_iter().map(|name| {
                                let label = if name == "any" { "any (all interfaces)".to_string() } else { name.clone() };
                                view! { <option value=name>{label}</option> }
                            }).collect_view()}
                        </select>
                    </label>

                    // Ready-made filters
                    <div class="space-y-2">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="text-sm text-gray-300">"DHCP / ISP debugging (replaces the filter):"</span>
                            {scenarios().into_iter().map(|preset| {
                                let Preset { label, hint, groups: specs, detail: preset_detail, link_level: preset_link } = preset;
                                view! {
                                    <button
                                        class=CHIP_CLASS
                                        title=hint
                                        on:click=move |_| {
                                            error.set(None);
                                            groups.set(Vec::new());
                                            add_groups(specs.clone());
                                            if let Some(value) = preset_detail {
                                                detail.set(value);
                                            }
                                            if let Some(value) = preset_link {
                                                link_level.set(value);
                                            }
                                        }
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                        <p class="text-xs text-gray-500">
                            "Capture on the WAN interface. Verbose decoding shows DHCP options, so you can tell a fresh DISCOVER from a REQUEST that carries option 50. DHCPv4 message filters read option 53 at its usual position, right after the magic cookie."
                        </p>
                    </div>

                    <div class="space-y-2">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="text-sm text-gray-300">"Filter: packets must match all of"</span>
                            <button class=BUTTON_CLASS on:click=move |_| add_groups(vec![GroupSpec::one(protocol_spec("tcp"))])>
                                "+ Add condition"
                            </button>
                            <span class="text-xs text-gray-500">"Add:"</span>
                            {add_ons().into_iter().map(|preset| {
                                let Preset { label, hint, groups: specs, .. } = preset;
                                view! {
                                    <button
                                        class=CHIP_CLASS
                                        title=hint
                                        on:click=move |_| add_groups(specs.clone())
                                    >
                                        {label}
                                    </button>
                                }
                            }).collect_view()}
                        </div>

                        <For
                            each=move || groups.get()
                            key=|group| group.id
                            children=move |group| view! {
                                <GroupView group=group groups=groups ids=ids />
                            }
                        />
                        <Show when=move || groups.with(|groups| groups.is_empty())>
                            <p class="text-sm text-gray-500">"No conditions: every packet on the interface is captured."</p>
                        </Show>

                        <p class="text-xs font-mono break-all">
                            {move || match expression.get() {
                                Ok(text) if text.is_empty() => view! { <span class="text-gray-500">"filter: (everything)"</span> }.into_any(),
                                Ok(text) => view! { <span class="text-gray-400">{format!("filter: {text}")}</span> }.into_any(),
                                Err(message) => view! { <span class="text-red-300">{message}</span> }.into_any(),
                            }}
                        </p>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <label class="space-y-1">
                            <span class="text-sm text-gray-300">"Stop after (packets)"</span>
                            <input class=format!("{INPUT_CLASS} w-full") inputmode="numeric"
                                prop:value=move || packets.get()
                                on:input=move |ev| packets.set(event_target_value(&ev)) />
                        </label>
                        <label class="space-y-1">
                            <span class="text-sm text-gray-300">"Stop after (seconds)"</span>
                            <input class=format!("{INPUT_CLASS} w-full") inputmode="numeric"
                                prop:value=move || seconds.get()
                                on:input=move |ev| seconds.set(event_target_value(&ev)) />
                        </label>
                        <label class="space-y-1">
                            <span class="text-sm text-gray-300">"Bytes kept per packet"</span>
                            <input class=format!("{INPUT_CLASS} w-full") inputmode="numeric"
                                prop:value=move || snaplen.get()
                                on:input=move |ev| snaplen.set(event_target_value(&ev)) />
                        </label>
                    </div>

                    <div class="flex flex-wrap items-end gap-4">
                        <label class="space-y-1">
                            <span class="text-sm text-gray-300">"Live view detail"</span>
                            <select
                                class=format!("{INPUT_CLASS} block")
                                prop:value=move || detail_value(detail.get())
                                on:change=move |ev| detail.set(detail_from_value(&event_target_value(&ev)))
                            >
                                <option value="normal">"One line per packet"</option>
                                <option value="verbose">"Verbose (DHCP options, IP header)"</option>
                                <option value="very_verbose">"Very verbose"</option>
                            </select>
                        </label>
                        <label class="flex items-center gap-2 text-sm text-gray-300 cursor-pointer pb-2">
                            <input
                                type="checkbox"
                                prop:checked=move || link_level.get()
                                on:change=move |ev| link_level.set(event_target_checked(&ev))
                            />
                            "Show MAC addresses"
                        </label>
                    </div>
                    <p class="text-xs text-gray-500">
                        "Detail only changes the live view. The downloaded pcap always has the whole packet, up to the bytes kept."
                    </p>

                    <div class="flex flex-wrap items-center gap-3">
                        <button
                            class=PRIMARY_BUTTON_CLASS
                            prop:disabled=move || busy.get() || expression.with(|e| e.is_err())
                            on:click=start
                        >
                            {move || if info.with(|info| info.as_ref().is_some_and(|i| i.has_pcap)) {
                                "Start new capture (replaces the previous file)"
                            } else {
                                "Start capture"
                            }}
                        </button>
                        <span class="text-xs text-gray-500">
                            "Not promiscuous. Starting a capture is recorded in the daemon log."
                        </span>
                    </div>
                </div>
            </Show>

            // Live output
            <Show when=move || info.with(|info| info.is_some())>
                <div class="bg-gray-800 rounded-lg p-4 space-y-2">
                    <div class="flex flex-wrap items-center justify-between gap-2">
                        <h2 class="text-lg font-medium text-gray-200">"Packets"</h2>
                        <label class="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                            <input
                                type="checkbox"
                                prop:checked=move || follow.get()
                                on:change=move |ev| follow.set(event_target_checked(&ev))
                            />
                            "Follow newest"
                        </label>
                    </div>
                    <Show when=move || lost.get() != 0>
                        <p class="text-amber-300 text-xs">
                            {move || format!("{} lines were skipped because the page fell behind. The pcap file still has every packet.", lost.get())}
                        </p>
                    </Show>
                    <div
                        node_ref=output
                        class="bg-gray-900 rounded border border-gray-700 p-2 h-96 overflow-auto font-mono text-xs text-gray-200"
                        role="log"
                    >
                        <For
                            each=move || lines.get()
                            key=|line| line.seq
                            children=move |line| view! {
                                <div class="whitespace-pre">{line.text}</div>
                            }
                        />
                        <Show when=move || lines.with(|lines| lines.is_empty())>
                            <p class="text-gray-500">
                                {move || if running() { "Waiting for packets…" } else { "No packets were captured." }}
                            </p>
                        </Show>
                    </div>
                    <p class="text-xs text-gray-500">
                        {format!("Showing the newest {MAX_PAGE_LINES} lines.")}
                    </p>
                </div>
            </Show>
        </div>
    }
}

/// One condition of the filter: a row, or several alternative rows.
#[component]
fn GroupView(group: GroupRow, groups: RwSignal<Vec<GroupRow>>, ids: Ids) -> impl IntoView {
    let many = move || group.rows.with(|rows| rows.len() > 1);

    // Remove one alternative, or the whole group when it was the last. When
    // two alternatives become one, a group-level "none of" moves onto the row
    // that is left, which means the same thing.
    let remove_row = move |row_id: u32| {
        group
            .rows
            .update(|rows| rows.retain(|row| row.id != row_id));
        let left = group.rows.get_untracked();
        match left.as_slice() {
            [] => groups.update(|groups| groups.retain(|other| other.id != group.id)),
            [only] if group.negate.get_untracked() => {
                only.negate.update(|negated| *negated = !*negated);
                group.negate.set(false);
            }
            _ => {}
        }
    };

    let add_alternative = move |_| {
        let id = ids.next();
        group
            .rows
            .update(|rows| rows.push(ClauseRow::new(id, protocol_spec("tcp"))));
    };

    view! {
        <div class="bg-gray-700/40 rounded p-2 space-y-2">
            <Show when=many>
                <div class="flex flex-wrap items-center gap-3 text-xs text-gray-400">
                    <span>"Match any one of:"</span>
                    <label class="flex items-center gap-1 cursor-pointer">
                        <input
                            type="checkbox"
                            prop:checked=move || group.negate.get()
                            on:change=move |ev| group.negate.set(event_target_checked(&ev))
                        />
                        "none of these instead"
                    </label>
                </div>
            </Show>
            <For
                each=move || group.rows.get()
                key=|row| row.id
                children=move |row| view! {
                    <ClauseRowView row=row on_remove=Callback::new(move |()| remove_row(row.id)) />
                }
            />
            <button
                class="text-xs text-blue-300 hover:text-blue-200"
                on:click=add_alternative
            >
                "+ or another"
            </button>
        </div>
    }
}

/// One editable filter row.
#[component]
fn ClauseRowView(row: ClauseRow, on_remove: Callback<()>) -> impl IntoView {
    let has_direction = move || !matches!(row.kind.get(), RowKind::Protocol | RowKind::Dhcp);
    view! {
        <div class="flex flex-wrap items-center gap-2">
            <label class="flex items-center gap-1 text-sm text-gray-300 cursor-pointer">
                <input
                    type="checkbox"
                    prop:checked=move || row.negate.get()
                    on:change=move |ev| row.negate.set(event_target_checked(&ev))
                />
                "not"
            </label>
            <select
                class=INPUT_CLASS
                aria-label="Condition type"
                prop:value=move || row.kind.get().value()
                on:change=move |ev| {
                    let kind = RowKind::from_value(&event_target_value(&ev));
                    row.kind.set(kind);
                    row.value.set(kind.default_value().to_string());
                    row.last.set(String::new());
                }
            >
                {RowKind::ALL.into_iter().map(|kind| view! {
                    <option value=kind.value()>{kind.label()}</option>
                }).collect_view()}
            </select>
            <Show when=has_direction>
                <select
                    class=INPUT_CLASS
                    aria-label="Direction"
                    prop:value=move || direction_value(row.direction.get())
                    on:change=move |ev| row.direction.set(direction_from_value(&event_target_value(&ev)))
                >
                    <option value="any">"source or destination"</option>
                    <option value="src">"source"</option>
                    <option value="dst">"destination"</option>
                </select>
            </Show>
            {move || match row.kind.get() {
                RowKind::Protocol => view! {
                    <select
                        class=INPUT_CLASS
                        aria-label="Protocol"
                        prop:value=move || row.value.get()
                        on:change=move |ev| row.value.set(event_target_value(&ev))
                    >
                        {CaptureProtocol::ALL.into_iter().map(|protocol| view! {
                            <option value=protocol.as_str()>{protocol.as_str()}</option>
                        }).collect_view()}
                    </select>
                }.into_any(),
                RowKind::Dhcp => view! {
                    <select
                        class=INPUT_CLASS
                        aria-label="DHCP message type"
                        prop:value=move || row.value.get()
                        on:change=move |ev| row.value.set(event_target_value(&ev))
                    >
                        {DhcpMessageType::ALL.into_iter().map(|message| view! {
                            <option value=dhcp_value(message)>{message.label()}</option>
                        }).collect_view()}
                    </select>
                }.into_any(),
                RowKind::Port => view! {
                    <input
                        class=format!("{INPUT_CLASS} w-24")
                        aria-label="Port"
                        inputmode="numeric"
                        placeholder=RowKind::Port.placeholder()
                        prop:value=move || row.value.get()
                        on:input=move |ev| row.value.set(event_target_value(&ev))
                    />
                    <span class="text-gray-400 text-sm">"to"</span>
                    <input
                        class=format!("{INPUT_CLASS} w-24")
                        aria-label="Last port of the range (optional)"
                        inputmode="numeric"
                        placeholder="(optional)"
                        prop:value=move || row.last.get()
                        on:input=move |ev| row.last.set(event_target_value(&ev))
                    />
                }.into_any(),
                kind => view! {
                    <input
                        class=format!("{INPUT_CLASS} w-64 max-w-full")
                        aria-label=kind.label()
                        placeholder=kind.placeholder()
                        prop:value=move || row.value.get()
                        on:input=move |ev| row.value.set(event_target_value(&ev))
                    />
                }.into_any(),
            }}
            <button
                class="ml-auto px-2 py-1 text-gray-400 hover:text-red-300 text-sm"
                aria-label="Remove condition"
                on:click=move |_| on_remove.run(())
            >
                "Remove"
            </button>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: RowKind, value: &str) -> ClauseSpec {
        ClauseSpec::new(kind, value)
    }

    fn expression(groups: &[GroupSpec]) -> Result<String, String> {
        let groups = groups
            .iter()
            .enumerate()
            .map(|(index, group)| group_from_spec(group, index + 1))
            .collect::<Result<Vec<_>, _>>()?;
        CaptureFilter { groups }.to_expression()
    }

    #[test]
    fn rows_become_the_expected_filter() {
        let mut host = spec(RowKind::Host, "192.168.1.20");
        host.direction = CaptureDirection::Src;
        let mut range = spec(RowKind::Port, "1000");
        range.last = "2000".into();
        range.negate = true;
        assert_eq!(
            expression(&[
                GroupSpec::one(spec(RowKind::Protocol, "tcp")),
                GroupSpec::one(host),
                GroupSpec::one(range),
            ])
            .unwrap(),
            "tcp and src host 192.168.1.20 and not (portrange 1000-2000)"
        );
        assert_eq!(expression(&[]).unwrap(), "");
    }

    #[test]
    fn alternatives_become_an_or_group() {
        let groups = [
            GroupSpec::one(spec(RowKind::Host, "10.0.0.1")),
            GroupSpec::any_of(vec![protocol_spec("tcp"), protocol_spec("udp")]),
        ];
        assert_eq!(
            expression(&groups).unwrap(),
            "host 10.0.0.1 and (tcp or udp)"
        );
        let mut none = GroupSpec::any_of(vec![protocol_spec("arp"), protocol_spec("icmp")]);
        none.negate = true;
        assert_eq!(expression(&[none]).unwrap(), "not (arp or icmp)");
    }

    #[test]
    fn a_bad_row_is_named_with_its_place() {
        for bad in [
            spec(RowKind::Host, "not an address"),
            spec(RowKind::Net, "10.0.0.0"),
            spec(RowKind::Port, "0"),
            spec(RowKind::Port, "http"),
            spec(RowKind::Mac, "aa:bb"),
            spec(RowKind::Protocol, ""),
            spec(RowKind::Dhcp, ""),
            spec(RowKind::Dhcp, "hello"),
        ] {
            assert!(clause_from_spec(&bad).is_err(), "{bad:?}");
        }
        let mut backwards = spec(RowKind::Port, "2000");
        backwards.last = "1000".into();
        assert!(clause_from_spec(&backwards).is_err());

        let error = expression(&[
            GroupSpec::one(protocol_spec("tcp")),
            GroupSpec::any_of(vec![protocol_spec("udp"), spec(RowKind::Host, "x")]),
        ])
        .unwrap_err();
        assert!(error.starts_with("condition 2, alternative 2:"), "{error}");
        let single = expression(&[GroupSpec::one(spec(RowKind::Host, "x"))]).unwrap_err();
        assert!(single.starts_with("condition 1:"), "{single}");
    }

    #[test]
    fn every_dhcp_message_type_can_be_chosen_in_the_page() {
        for message in DhcpMessageType::ALL {
            let clause = clause_from_spec(&dhcp_spec(message)).unwrap();
            assert_eq!(
                clause.term,
                FilterTerm::DhcpMessage {
                    message_type: message
                }
            );
        }
    }

    #[test]
    fn every_add_on_is_a_valid_filter() {
        let presets = add_ons();
        assert!(presets.len() >= 5);
        for preset in presets {
            assert!(
                expression(&preset.groups).is_ok_and(|text| !text.is_empty()),
                "{}",
                preset.label
            );
            // Add-ons combine with what is there, so they never reset the
            // decode settings.
            assert_eq!(preset.detail, None, "{}", preset.label);
            assert_eq!(preset.link_level, None, "{}", preset.label);
        }
    }

    #[test]
    fn every_scenario_is_a_valid_filter_that_the_limits_allow() {
        let scenarios = scenarios();
        assert!(scenarios.len() >= 6);
        for preset in &scenarios {
            let text =
                expression(&preset.groups).unwrap_or_else(|e| panic!("{}: {e}", preset.label));
            assert!(!text.is_empty(), "{}", preset.label);
            assert!(preset.groups.len() <= MAX_GROUPS, "{}", preset.label);
            let terms: usize = preset.groups.iter().map(|g| g.any.len()).sum();
            assert!(terms <= MAX_CLAUSES, "{}", preset.label);
            assert!(!preset.hint.is_empty(), "{}", preset.label);
        }
    }

    #[test]
    fn the_isp_scenarios_ask_for_what_the_bug_needs() {
        let by_label = |label: &str| {
            scenarios()
                .into_iter()
                .find(|preset| preset.label == label)
                .unwrap_or_else(|| panic!("no scenario {label}"))
        };
        // The DHCP ones need decoded options to tell a DISCOVER from an
        // INIT-REBOOT REQUEST.
        for label in [
            "DHCPv4 exchange",
            "DISCOVER",
            "REQUEST",
            "RELEASE",
            "Server replies",
        ] {
            let preset = by_label(label);
            assert_eq!(preset.detail, Some(CaptureDetail::Verbose), "{label}");
            assert_eq!(preset.link_level, Some(true), "{label}");
        }
        assert!(
            expression(&by_label("DISCOVER").groups)
                .unwrap()
                .contains("udp[250] = 1")
        );
        assert!(
            expression(&by_label("RELEASE").groups)
                .unwrap()
                .contains("udp[250] = 7")
        );
        assert_eq!(
            expression(&by_label("Server replies").groups)
                .unwrap()
                .matches("udp[250] = ")
                .count(),
            3
        );
        assert_eq!(
            expression(&by_label("DHCPv4 + DHCPv6").groups).unwrap(),
            "(portrange 67-68 or portrange 546-547)"
        );
        assert_eq!(
            expression(&by_label("ARP + ping").groups).unwrap(),
            "(arp or icmp)"
        );
        assert_eq!(
            expression(&by_label("IPv4 without DHCP").groups).unwrap(),
            "ip and not (portrange 67-68)"
        );
    }

    #[test]
    fn new_rows_start_valid_where_a_default_exists() {
        for kind in RowKind::ALL {
            let row = spec(kind, kind.default_value());
            let expected = matches!(kind, RowKind::Protocol | RowKind::Dhcp);
            assert_eq!(clause_from_spec(&row).is_ok(), expected, "{kind:?}");
            assert_eq!(RowKind::from_value(kind.value()), kind);
        }
    }

    #[test]
    fn detail_choices_round_trip() {
        for detail in [
            CaptureDetail::Normal,
            CaptureDetail::Verbose,
            CaptureDetail::VeryVerbose,
        ] {
            assert_eq!(detail_from_value(detail_value(detail)), detail);
        }
    }

    #[test]
    fn sizes_are_readable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }
}
