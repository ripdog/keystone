//! Packet tester: "what happens to this packet?"
//!
//! The form describes one packet. The daemon walks it through the same rules
//! the router applies and returns the steps in order, with the decisive step
//! of each chain marked. Rule steps link to the page that holds the rule.

use crate::api;
use crate::components::form_utils::event_target_value;
use keystone_core::{
    FirewallZone, RuleProtocol, TestPacketRequest, TestPacketResponse, TraceOrigin, TraceStage,
    TraceStep, TraceVerdict,
};
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

/// Page that holds the rule a trace step refers to. Port forwards, their
/// accepts and their hairpin rules all live on the port forwards page.
pub(crate) fn rule_page(rule_kind: &str) -> &'static str {
    match rule_kind {
        "input" => "/firewall/input-rules",
        "forward" => "/firewall/forward-rules",
        _ => "/firewall/port-forwards",
    }
}

fn stage_label(stage: TraceStage) -> &'static str {
    match stage {
        TraceStage::Prerouting => "Prerouting (DNAT)",
        TraceStage::Routing => "Routing",
        TraceStage::Input => "Input chain",
        TraceStage::Forward => "Forward chain",
        TraceStage::Postrouting => "Postrouting (SNAT)",
    }
}

fn verdict_label(verdict: TraceVerdict) -> (&'static str, &'static str) {
    match verdict {
        TraceVerdict::Accept => ("ACCEPT", "bg-green-700 text-green-50"),
        TraceVerdict::Drop => ("DROP", "bg-red-800 text-red-50"),
        TraceVerdict::Reject => ("REJECT", "bg-red-800 text-red-50"),
    }
}

/// Border and text colour of a step. Only the decisive step of a chain is
/// emphasised. A rewrite (DNAT or masquerade) is blue. The filter decision
/// takes the verdict's colour. Steps that did not match are dimmed.
fn step_style(step: &TraceStep, verdict: TraceVerdict) -> &'static str {
    if !step.matched {
        return "border-gray-700 text-gray-500";
    }
    if !step.decisive {
        return "border-gray-600 text-gray-200";
    }
    match step.stage {
        TraceStage::Prerouting | TraceStage::Postrouting => {
            "border-blue-400 bg-blue-950/40 text-blue-100"
        }
        TraceStage::Input | TraceStage::Forward => match verdict {
            TraceVerdict::Accept => "border-green-400 bg-green-950/40 text-green-100",
            TraceVerdict::Drop | TraceVerdict::Reject => {
                "border-red-400 bg-red-950/40 text-red-100"
            }
        },
        TraceStage::Routing => "border-gray-600 text-gray-200",
    }
}

/// Port field: empty means none, otherwise a number from 1 to 65535.
fn parse_port(text: &str, field: &str) -> Result<Option<u16>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    match text.parse::<u16>() {
        Ok(port) if port >= 1 => Ok(Some(port)),
        _ => Err(format!("{field} must be a number from 1 to 65535")),
    }
}

/// Build the request from the form. `ingress` is `iface:<name>` or `zone:<name>`.
fn build_request(
    ingress: &str,
    source: &str,
    destination: &str,
    protocol: &str,
    ports: (&str, &str),

    icmp_type: &str,
    egress: &str,
) -> Result<TestPacketRequest, String> {
    let (ingress_interface, ingress_zone) = match ingress.split_once(':') {
        Some(("iface", name)) if !name.is_empty() => (Some(name.to_string()), None),
        Some(("zone", name)) if !name.is_empty() => (None, Some(name.to_string())),
        _ => return Err("Choose where the packet arrives".to_string()),
    };
    let protocol: RuleProtocol = protocol.parse()?;
    if protocol == RuleProtocol::TcpUdp {
        return Err("a packet has one protocol: choose tcp or udp".to_string());
    }
    let icmp_type = match icmp_type.trim() {
        "" => None,
        text => Some(
            text.parse::<u8>()
                .map_err(|_| "ICMP type must be a number from 0 to 255".to_string())?,
        ),
    };
    Ok(TestPacketRequest {
        ingress_interface,
        ingress_zone,
        source_ip: source.trim().to_string(),
        destination_ip: destination.trim().to_string(),
        protocol,
        source_port: parse_port(ports.0, "Source port")?,
        destination_port: parse_port(ports.1, "Destination port")?,
        icmp_type,
        egress_interface: match egress.trim() {
            "" => None,
            name => Some(name.to_string()),
        },
    })
}

/// Interfaces of the zones, as `iface:<name>` choices labelled with their zone.
fn ingress_choices(zones: &[FirewallZone]) -> Vec<(String, String)> {
    let mut choices = Vec::new();
    for zone in zones {
        if zone.interfaces.is_empty() {
            continue;
        }
        choices.push((format!("zone:{}", zone.name), format!("zone {}", zone.name)));
        for interface in &zone.interfaces {
            choices.push((
                format!("iface:{interface}"),
                format!("interface {interface} (zone {})", zone.name),
            ));
        }
    }
    choices
}

fn interface_names(zones: &[FirewallZone]) -> Vec<String> {
    let mut names: Vec<String> = zones
        .iter()
        .flat_map(|zone| zone.interfaces.iter().cloned())
        .collect();
    names.sort();
    names.dedup();
    names
}

#[component]
pub fn PacketTesterTab(token: Signal<String>, on_unauthorized: Callback<()>) -> impl IntoView {
    let zones = LocalResource::new(move || {
        let token = token.get();
        async move { api::fetch_firewall_zones(&token).await }
    });

    let ingress = RwSignal::new(String::new());
    let source = RwSignal::new(String::new());
    let destination = RwSignal::new(String::new());
    let protocol = RwSignal::new("tcp".to_string());
    let source_port = RwSignal::new(String::new());
    let destination_port = RwSignal::new(String::new());
    let icmp_type = RwSignal::new(String::new());
    let egress = RwSignal::new(String::new());
    let applied = RwSignal::new(false);
    let form_error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let result = RwSignal::new(None::<Result<TestPacketResponse, String>>);

    let submit = move |event: leptos::ev::SubmitEvent| {
        event.prevent_default();
        form_error.set(None);
        let request = match build_request(
            &ingress.get_untracked(),
            &source.get_untracked(),
            &destination.get_untracked(),
            &protocol.get_untracked(),
            (
                &source_port.get_untracked(),
                &destination_port.get_untracked(),
            ),
            &icmp_type.get_untracked(),
            &egress.get_untracked(),
        ) {
            Ok(request) => request,
            Err(message) => {
                form_error.set(Some(message));
                return;
            }
        };
        let Some(token_value) = Some(token.get_untracked()).filter(|t| !t.is_empty()) else {
            return;
        };
        let applied_baseline = applied.get_untracked();
        busy.set(true);
        spawn_local(async move {
            let outcome = api::run_packet_trace(&token_value, &request, applied_baseline).await;
            if let Err(message) = &outcome
                && message.contains("Unauthorized")
            {
                on_unauthorized.run(());
            }
            result.set(Some(outcome));
            busy.set(false);
        });
    };

    let input_class =
        "px-2 py-1.5 bg-gray-700 text-gray-200 rounded border border-gray-600 text-sm w-full";

    view! {
        <div class="space-y-6">
            <div>
                <h2 class="text-lg font-medium text-gray-200">"Packet Tester"</h2>
                <p class="text-gray-500 text-xs mt-1">
                    "Simulated from configuration. Established/related replies and kernel behaviour are not modelled beyond the notes shown with each result."
                </p>
            </div>

            <form class="grid grid-cols-1 md:grid-cols-2 gap-4" on:submit=submit>
                <label class="space-y-1 md:col-span-2">
                    <span class="text-sm text-gray-300">"Arrives on"</span>
                    <select
                        class=input_class
                        prop:value=move || ingress.get()
                        on:change=move |ev| ingress.set(event_target_value(&ev))
                    >
                        <option value="">"Choose an interface or zone"</option>
                        {move || {
                            zones
                                .get()
                                .map(|result| match result {
                                    Ok(list) => ingress_choices(&list)
                                        .into_iter()
                                        .map(|(value, label)| view! { <option value=value>{label}</option> })
                                        .collect_view()
                                        .into_any(),
                                    Err(_) => view! { <option value="">"Zones unavailable"</option> }.into_any(),
                                })
                        }}
                    </select>
                </label>

                <label class="space-y-1">
                    <span class="text-sm text-gray-300">"Source IP"</span>
                    <input class=input_class placeholder="192.168.1.20"
                        prop:value=move || source.get()
                        on:input=move |ev| source.set(event_target_value(&ev)) />
                </label>
                <label class="space-y-1">
                    <span class="text-sm text-gray-300">"Destination IP"</span>
                    <input class=input_class placeholder="203.0.113.5 (a router address) or a host"
                        prop:value=move || destination.get()
                        on:input=move |ev| destination.set(event_target_value(&ev)) />
                </label>

                <label class="space-y-1">
                    <span class="text-sm text-gray-300">"Protocol"</span>
                    <select class=input_class
                        prop:value=move || protocol.get()
                        on:change=move |ev| protocol.set(event_target_value(&ev))>
                        <option value="tcp">"TCP"</option>
                        <option value="udp">"UDP"</option>
                        <option value="icmp">"ICMP (IPv4)"</option>
                        <option value="icmpv6">"ICMPv6"</option>
                        <option value="any">"Any (no protocol)"</option>
                    </select>
                </label>
                <div class="grid grid-cols-2 gap-4">
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">"Source port"</span>
                        <input class=input_class placeholder="optional"
                            prop:value=move || source_port.get()
                            on:input=move |ev| source_port.set(event_target_value(&ev)) />
                    </label>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">"Destination port"</span>
                        <input class=input_class placeholder="22"
                            prop:value=move || destination_port.get()
                            on:input=move |ev| destination_port.set(event_target_value(&ev)) />
                    </label>
                </div>

                <label class="space-y-1">
                    <span class="text-sm text-gray-300">"ICMP type"</span>
                    <input class=input_class placeholder="8 (echo request) by default"
                        prop:value=move || icmp_type.get()
                        on:input=move |ev| icmp_type.set(event_target_value(&ev)) />
                </label>
                <label class="space-y-1">
                    <span class="text-sm text-gray-300">"Leaves via (forwarded traffic)"</span>
                    <select class=input_class
                        prop:value=move || egress.get()
                        on:change=move |ev| egress.set(event_target_value(&ev))>
                        <option value="">"From the live routing table"</option>
                        {move || {
                            zones
                                .get()
                                .map(|result| match result {
                                    Ok(list) => interface_names(&list)
                                        .into_iter()
                                        .map(|name| { let label = name.clone(); view! { <option value=name>{label}</option> } })
                                        .collect_view()
                                        .into_any(),
                                    Err(_) => ().into_any(),
                                })
                        }}
                    </select>
                </label>

                <label class="flex items-center gap-2 text-sm text-gray-300 md:col-span-2">
                    <input type="checkbox" class="rounded"
                        prop:checked=move || applied.get()
                        on:change=move |ev| applied.set(event_target_checked(&ev)) />
                    "Trace the last applied configuration instead of the saved one"
                </label>

                <div class="md:col-span-2 flex items-center gap-4">
                    <button type="submit"
                        class="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded text-sm"
                        disabled=move || busy.get()>
                        {move || if busy.get() { "Tracing..." } else { "Trace packet" }}
                    </button>
                    {move || form_error.get().map(|message| view! {
                        <span class="text-red-400 text-sm">{message}</span>
                    })}
                </div>
            </form>

            {move || result.get().map(|outcome| match outcome {
                Ok(response) => view! { <TraceResult response=response /> }.into_any(),
                Err(message) => view! {
                    <p class="text-red-400 text-sm">"Could not trace the packet: "{message}</p>
                }.into_any(),
            })}
        </div>
    }
}

fn event_target_checked(ev: &leptos::ev::Event) -> bool {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|input| input.checked())
        .unwrap_or(false)
}

#[component]
fn TraceResult(response: TestPacketResponse) -> impl IntoView {
    let (verdict_text, verdict_class) = verdict_label(response.verdict);
    let egress = response
        .egress
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let dnat = match &response.dnat {
        Some(dnat) => match dnat.port {
            Some(port) => format!("to {}:{port}", dnat.address),
            None => format!("to {} (port kept)", dnat.address),
        },
        None => "none".to_string(),
    };
    let baseline = if response.baseline == "applied" {
        match response.applied_snapshot_id {
            Some(id) => format!("applied configuration (snapshot {id})"),
            None => "applied configuration".to_string(),
        }
    } else {
        "saved configuration".to_string()
    };
    let path = match response.path {
        TraceStage::Input => "input chain (destined to the router)",
        _ => "forward chain (routed through the router)",
    };
    let ingress = response.ingress.join(", ");
    let verdict = response.verdict;
    let steps = response.steps.clone();
    let notes = response.notes.clone();

    view! {
        <section class="space-y-4">
            <div class="flex flex-wrap items-center gap-4">
                <span class=format!("px-3 py-1 rounded font-semibold tracking-wide {verdict_class}")>
                    {verdict_text}
                </span>
                <dl class="grid grid-cols-2 md:grid-cols-4 gap-x-6 gap-y-1 text-sm text-gray-300">
                    <dt class="text-gray-500">"Arrives on"</dt><dd>{ingress}</dd>
                    <dt class="text-gray-500">"Handled by"</dt><dd>{path}</dd>
                    <dt class="text-gray-500">"Leaves via"</dt><dd>{egress}</dd>
                    <dt class="text-gray-500">"Destination rewrite"</dt><dd>{dnat}</dd>
                    <dt class="text-gray-500">"Source rewrite"</dt>
                    <dd>{if response.masquerade { "masquerade" } else { "none" }}</dd>
                    <dt class="text-gray-500">"Configuration"</dt><dd>{baseline}</dd>
                </dl>
            </div>

            <div class="bg-gray-900/60 border border-amber-700/60 rounded p-3 text-xs text-amber-200 space-y-1">
                <p class="font-semibold">"Simulation notes"</p>
                <ul class="list-disc list-inside space-y-0.5">
                    {notes.into_iter().map(|note| view! { <li>{note}</li> }).collect_view()}
                </ul>
            </div>

            <ol class="space-y-2">
                {steps
                    .into_iter()
                    .map(|step| view! { <TraceStepRow step=step verdict=verdict /> })
                    .collect_view()}
            </ol>
        </section>
    }
}

#[component]
fn TraceStepRow(step: TraceStep, verdict: TraceVerdict) -> impl IntoView {
    let style = step_style(&step, verdict);
    let status = match (step.matched, step.decisive) {
        (true, true) => "decisive",
        (true, false) => "matched",
        (false, _) => "no match",
    };
    let stage = stage_label(step.stage);
    let link = match &step.origin {
        TraceOrigin::User { rule_kind, .. } => Some(rule_page(rule_kind)),
        _ => None,
    };
    let label = step.label.clone();
    let reason = step.reason.clone();
    view! {
        <li class=format!("border-l-4 rounded px-3 py-2 bg-gray-900/40 {style}")>
            <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span class="text-xs uppercase tracking-wide text-gray-500 w-36 shrink-0">{stage}</span>
                <span class="font-medium">
                    {match link {
                        Some(path) => view! { <A href=path>{label}</A> }.into_any(),
                        None => view! { <span>{label}</span> }.into_any(),
                    }}
                </span>
                <span class="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300">{status}</span>
            </div>
            <p class="text-sm text-gray-400 mt-0.5">{reason}</p>
        </li>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_rules_link_to_the_page_that_holds_them() {
        assert_eq!(rule_page("input"), "/firewall/input-rules");
        assert_eq!(rule_page("forward"), "/firewall/forward-rules");
        for kind in [
            "portfwd",
            "portfwd-accept",
            "portfwd-hairpin",
            "portfwd-hairpin-snat",
        ] {
            assert_eq!(rule_page(kind), "/firewall/port-forwards");
        }
    }

    #[test]
    fn a_request_needs_an_ingress_and_valid_ports() {
        let ok = build_request(
            "iface:eth1",
            "192.168.1.20",
            "192.168.1.1",
            "tcp",
            ("", "22"),
            "",
            "",
        );
        let request = ok.expect("valid form");
        assert_eq!(request.ingress_interface.as_deref(), Some("eth1"));
        assert_eq!(request.destination_port, Some(22));

        assert!(build_request("", "1.1.1.1", "2.2.2.2", "tcp", ("", "22"), "", "").is_err());
        assert!(
            build_request("iface:eth1", "1.1.1.1", "2.2.2.2", "tcp", ("", "0"), "", "").is_err()
        );
        assert!(
            build_request(
                "iface:eth1",
                "1.1.1.1",
                "2.2.2.2",
                "tcp",
                ("", "70000"),
                "",
                ""
            )
            .is_err()
        );
        assert!(
            build_request(
                "iface:eth1",
                "1.1.1.1",
                "2.2.2.2",
                "tcp+udp",
                ("", "1"),
                "",
                ""
            )
            .is_err()
        );
    }

    #[test]
    fn the_decisive_step_of_a_filter_chain_takes_the_verdict_colour() {
        let step = TraceStep {
            stage: TraceStage::Input,
            origin: TraceOrigin::Builtin,
            label: "x".into(),
            matched: true,
            decisive: true,
            reason: String::new(),
        };
        assert!(step_style(&step, TraceVerdict::Accept).contains("green"));
        assert!(step_style(&step, TraceVerdict::Drop).contains("red"));
        let skipped = TraceStep {
            matched: false,
            decisive: false,
            ..step
        };
        assert!(step_style(&skipped, TraceVerdict::Accept).contains("gray-500"));
    }
}
