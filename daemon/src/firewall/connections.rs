//! Connection tracking view: the kernel's table of tracked connections.
//!
//! `conntrack -L -f <family> -o xml` (conntrack-tools) lists each connection as
//! a `<flow>` element with three `<meta>` blocks: the original direction, the
//! reply direction, and the independent data (state, timeout, mark). The output
//! is streamed and split into flows as it arrives. Reading stops once the cap
//! is exceeded, which is then reported as truncated, so a large table does not
//! load into memory.

use anyhow::{Context, Result};
use keystone_core::{ConnectionEntry, ConnectionsResponse};
use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};
use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

/// Most connections returned in one response.
pub const MAX_CONNECTIONS: usize = 5000;
/// Longest time spent reading the table before the request fails.
const READ_TIMEOUT: Duration = Duration::from_secs(15);
/// A flow longer than this without its end tag is not a conntrack flow.
const MAX_PENDING_BYTES: usize = 256 * 1024;
const FLOW_END: &[u8] = b"</flow>";

/// Read the connection table (IPv4 and IPv6), up to [`MAX_CONNECTIONS`].
pub(crate) async fn read_connections() -> Result<ConnectionsResponse> {
    let mut stream = FlowStream::new(MAX_CONNECTIONS);
    tokio::time::timeout(READ_TIMEOUT, async {
        for family in ["ipv4", "ipv6"] {
            if !dump_family(family, &mut stream).await? {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("timed out reading the connection table")??;
    Ok(ConnectionsResponse {
        connections: stream.connections,
        truncated: stream.truncated,
        limit: MAX_CONNECTIONS,
    })
}

/// Stream one family of `conntrack -L` into `stream`. Returns `false` when the
/// stream stopped early because of the cap.
async fn dump_family(family: &str, stream: &mut FlowStream) -> Result<bool> {
    let mut child = Command::new("conntrack")
        .args(["-L", "-f", family, "-o", "xml"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("conntrack is not installed (package conntrack-tools)")
            } else {
                anyhow::Error::from(error).context("failed to run conntrack")
            }
        })?;
    let mut stdout = child.stdout.take().context("conntrack has no output")?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = stdout
            .read(&mut buffer)
            .await
            .context("reading conntrack output")?;
        if read == 0 {
            break;
        }
        if !stream.push(&buffer[..read]) {
            // Dropping the child kills it: the rest of the table is not needed.
            return Ok(false);
        }
    }
    let status = child.wait().await.context("waiting for conntrack")?;
    if !status.success() {
        let stderr = read_to_string(child.stderr.take()).await;
        anyhow::bail!("conntrack failed: {}", stderr.trim());
    }
    Ok(true)
}

async fn read_to_string<R: AsyncRead + Unpin>(pipe: Option<R>) -> String {
    let mut text = String::new();
    if let Some(mut pipe) = pipe {
        let _ = pipe.read_to_string(&mut text).await;
    }
    text
}

/// Splits the streamed XML into flows, parses each one, and stops at the cap.
pub(crate) struct FlowStream {
    pending: Vec<u8>,
    pub connections: Vec<ConnectionEntry>,
    limit: usize,
    pub truncated: bool,
}

impl FlowStream {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            pending: Vec::new(),
            connections: Vec::new(),
            limit,
            truncated: false,
        }
    }

    /// Feed the next bytes of output. Returns `false` once a connection past
    /// the limit has been seen; the caller then stops reading.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> bool {
        self.pending.extend_from_slice(bytes);
        while let Some(end) = find(&self.pending, FLOW_END) {
            let end = end + FLOW_END.len();
            let chunk: Vec<u8> = self.pending.drain(..end).collect();
            let Some(start) = find(&chunk, b"<flow") else {
                continue;
            };
            let xml = String::from_utf8_lossy(&chunk[start..]);
            let Some(connection) = parse_flow(&xml) else {
                continue;
            };
            if self.connections.len() == self.limit {
                self.truncated = true;
                return false;
            }
            self.connections.push(connection);
        }
        if self.pending.len() > MAX_PENDING_BYTES {
            self.pending.clear();
        }
        true
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Original,
    Reply,
    Independent,
}

/// One direction of a connection: what conntrack reports for its tuple.
#[derive(Default)]
struct Tuple {
    family: Option<String>,
    protocol: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    packets: Option<u64>,
    bytes: Option<u64>,
}

#[derive(Default)]
struct Independent {
    state: Option<String>,
    timeout: Option<u64>,
    mark: Option<u32>,
}

fn attribute(element: &BytesStart, name: &str) -> Option<String> {
    element
        .try_get_attribute(name)
        .ok()
        .flatten()?
        .normalized_value(XmlVersion::Implicit1_0)
        .ok()
        .map(|value| value.into_owned())
}

fn tuple_for<'a>(
    direction: Option<Direction>,
    original: &'a mut Tuple,
    reply: &'a mut Tuple,
) -> Option<&'a mut Tuple> {
    match direction? {
        Direction::Original => Some(original),
        Direction::Reply => Some(reply),
        Direction::Independent => None,
    }
}

/// Parse one `<flow>` element into a connection. `None` when the flow lacks
/// the fields a connection needs, or is not well formed.
pub(crate) fn parse_flow(xml: &str) -> Option<ConnectionEntry> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut original = Tuple::default();
    let mut reply = Tuple::default();
    let mut independent = Independent::default();
    let mut direction: Option<Direction> = None;
    let mut path: Vec<String> = Vec::new();

    loop {
        match reader.read_event().ok()? {
            Event::Start(element) => {
                let name = element.name().as_ref().to_owned();
                apply_element(&name, &element, &mut direction, &mut original, &mut reply);
                path.push(name);
            }
            Event::Empty(element) => {
                let name = element.name().as_ref().to_owned();
                apply_element(&name, &element, &mut direction, &mut original, &mut reply);
            }
            Event::End(element) => {
                path.pop();
                if element.name().as_ref() == "meta" {
                    direction = None;
                }
            }
            Event::Text(text) => {
                let value = text.xml10_content().trim().to_string();
                if value.is_empty() {
                    continue;
                }
                let leaf = path.last().map(String::as_str).unwrap_or_default();
                let parent = path
                    .len()
                    .checked_sub(2)
                    .and_then(|index| path.get(index))
                    .map(String::as_str)
                    .unwrap_or_default();
                if parent == "meta" && direction == Some(Direction::Independent) {
                    match leaf {
                        "state" => independent.state = Some(value),
                        "timeout" => independent.timeout = value.parse().ok(),
                        "mark" => independent.mark = value.parse().ok(),
                        _ => {}
                    }
                } else if let Some(tuple) = tuple_for(direction, &mut original, &mut reply) {
                    match (parent, leaf) {
                        ("layer3", "src") => tuple.source = Some(value),
                        ("layer3", "dst") => tuple.destination = Some(value),
                        ("layer4", "sport") => tuple.source_port = value.parse().ok(),
                        ("layer4", "dport") => tuple.destination_port = value.parse().ok(),
                        _ => {}
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    connection_from(original, reply, independent)
}

/// Record what one start (or empty) element says about the current direction.
fn apply_element(
    name: &str,
    element: &BytesStart,
    direction: &mut Option<Direction>,
    original: &mut Tuple,
    reply: &mut Tuple,
) {
    match name {
        "meta" => {
            *direction = match attribute(element, "direction").as_deref() {
                Some("original") => Some(Direction::Original),
                Some("reply") => Some(Direction::Reply),
                Some("independent") => Some(Direction::Independent),
                _ => None,
            };
        }
        "layer3" => {
            if let Some(tuple) = tuple_for(*direction, original, reply) {
                tuple.family = attribute(element, "protoname");
            }
        }
        "layer4" => {
            if let Some(tuple) = tuple_for(*direction, original, reply) {
                tuple.protocol = attribute(element, "protoname");
            }
        }
        "counters" => {
            if let Some(tuple) = tuple_for(*direction, original, reply) {
                tuple.packets = attribute(element, "packets").and_then(|v| v.parse().ok());
                tuple.bytes = attribute(element, "bytes").and_then(|v| v.parse().ok());
            }
        }
        _ => {}
    }
}

fn connection_from(
    original: Tuple,
    reply: Tuple,
    independent: Independent,
) -> Option<ConnectionEntry> {
    let protocol = original.protocol?;
    let source = original.source?;
    let destination = original.destination?;
    let family = original
        .family
        .clone()
        .unwrap_or_else(|| match source.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => "ipv6".to_string(),
            _ => "ipv4".to_string(),
        });

    // A reply missing from the output is taken as the mirror of the original.
    let has_reply = reply.source.is_some();
    let reply_source = reply.source.clone().unwrap_or_else(|| destination.clone());
    let reply_destination = reply.destination.clone().unwrap_or_else(|| source.clone());
    let reply_source_port = if has_reply {
        reply.source_port
    } else {
        original.destination_port
    };
    let reply_destination_port = if has_reply {
        reply.destination_port
    } else {
        original.source_port
    };
    let nat = reply_source != destination
        || reply_destination != source
        || reply_source_port != original.destination_port
        || reply_destination_port != original.source_port;

    Some(ConnectionEntry {
        family,
        protocol,
        state: independent.state,
        original_source: source,
        original_destination: destination,
        original_source_port: original.source_port,
        original_destination_port: original.destination_port,
        reply_source,
        reply_destination,
        reply_source_port,
        reply_destination_port,
        nat,
        mark: independent.mark.unwrap_or(0),
        timeout: independent.timeout,
        packets: sum(original.packets, reply.packets),
        bytes: sum(original.bytes, reply.bytes),
    })
}

/// Sum of both directions. `None` when neither reports a value.
fn sum(first: Option<u64>, second: Option<u64>) -> Option<u64> {
    match (first, second) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like `conntrack -L -f ipv4 -o xml` on conntrack-tools 1.4.x, with
    /// connection accounting on for the first flow only. Written from the
    /// documented output format, since conntrack is not installed on the
    /// development host.
    const FIXTURE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<conntrack>
<flow>
  <meta direction="original">
    <layer3 protonum="2" protoname="ipv4">
      <src>192.168.1.20</src>
      <dst>1.1.1.1</dst>
    </layer3>
    <layer4 protonum="6" protoname="tcp">
      <sport>51234</sport>
      <dport>443</dport>
    </layer4>
    <counters packets="12" bytes="1840"/>
  </meta>
  <meta direction="reply">
    <layer3 protonum="2" protoname="ipv4">
      <src>1.1.1.1</src>
      <dst>203.0.113.5</dst>
    </layer3>
    <layer4 protonum="6" protoname="tcp">
      <sport>443</sport>
      <dport>51234</dport>
    </layer4>
    <counters packets="10" bytes="9120"/>
  </meta>
  <meta direction="independent">
    <state>ESTABLISHED</state>
    <timeout>431999</timeout>
    <mark>0</mark>
  </meta>
</flow>
<flow>
  <meta direction="original">
    <layer3 protonum="2" protoname="ipv4">
      <src>198.51.100.9</src>
      <dst>203.0.113.5</dst>
    </layer3>
    <layer4 protonum="17" protoname="udp">
      <sport>40100</sport>
      <dport>27010</dport>
    </layer4>
  </meta>
  <meta direction="reply">
    <layer3 protonum="2" protoname="ipv4">
      <src>192.168.1.50</src>
      <dst>198.51.100.9</dst>
    </layer3>
    <layer4 protonum="17" protoname="udp">
      <sport>27010</sport>
      <dport>40100</dport>
    </layer4>
  </meta>
  <meta direction="independent">
    <timeout>29</timeout>
    <mark>0</mark>
  </meta>
</flow>
<flow>
  <meta direction="original">
    <layer3 protonum="2" protoname="ipv4">
      <src>192.168.1.20</src>
      <dst>192.168.1.1</dst>
    </layer3>
    <layer4 protonum="1" protoname="icmp">
      <type>8</type>
      <code>0</code>
      <id>4242</id>
    </layer4>
  </meta>
  <meta direction="reply">
    <layer3 protonum="2" protoname="ipv4">
      <src>192.168.1.1</src>
      <dst>192.168.1.20</dst>
    </layer3>
    <layer4 protonum="1" protoname="icmp">
      <type>0</type>
      <code>0</code>
      <id>4242</id>
    </layer4>
  </meta>
  <meta direction="independent">
    <timeout>29</timeout>
    <mark>7</mark>
  </meta>
</flow>
</conntrack>
"#;

    fn parse_fixture() -> Vec<ConnectionEntry> {
        let mut stream = FlowStream::new(usize::MAX);
        assert!(stream.push(FIXTURE.as_bytes()));
        stream.connections
    }

    #[test]
    fn a_tcp_flow_reads_both_tuples_state_and_counters() {
        let connections = parse_fixture();
        let tcp = connections
            .iter()
            .find(|c| c.protocol == "tcp")
            .expect("tcp flow");
        assert_eq!(tcp.family, "ipv4");
        assert_eq!(tcp.state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(tcp.original_source, "192.168.1.20");
        assert_eq!(tcp.original_destination, "1.1.1.1");
        assert_eq!(tcp.original_source_port, Some(51234));
        assert_eq!(tcp.original_destination_port, Some(443));
        assert_eq!(tcp.reply_source, "1.1.1.1");
        assert_eq!(tcp.reply_destination, "203.0.113.5");
        assert_eq!(tcp.reply_source_port, Some(443));
        assert_eq!(tcp.reply_destination_port, Some(51234));
        assert_eq!(tcp.timeout, Some(431999));
        assert_eq!(tcp.packets, Some(22));
        assert_eq!(tcp.bytes, Some(10960));
        // Masquerade rewrote the source, so replies return to the WAN address.
        assert!(tcp.nat, "replies to 203.0.113.5, not to the LAN client");
    }

    #[test]
    fn a_reply_from_a_different_address_marks_the_flow_as_nat() {
        let connections = parse_fixture();
        let udp = connections
            .iter()
            .find(|c| c.protocol == "udp")
            .expect("udp flow");
        assert!(udp.nat, "the reply comes from the internal server");
        assert_eq!(udp.state, None, "udp has no state");
        assert_eq!(udp.packets, None, "accounting is off for this flow");
        assert_eq!(udp.bytes, None);
        assert_eq!(udp.mark, 0);
    }

    #[test]
    fn icmp_flows_have_no_ports_and_keep_their_mark() {
        let connections = parse_fixture();
        let icmp = connections
            .iter()
            .find(|c| c.protocol == "icmp")
            .expect("icmp flow");
        assert_eq!(icmp.original_source_port, None);
        assert_eq!(icmp.reply_destination_port, None);
        assert_eq!(icmp.mark, 7);
        assert!(!icmp.nat);
    }

    #[test]
    fn a_flow_missing_its_addresses_is_skipped() {
        let xml = r#"<flow><meta direction="original"><layer4 protoname="tcp"><sport>1</sport></layer4></meta></flow>"#;
        assert_eq!(parse_flow(xml), None);
        assert_eq!(parse_flow("<flow><meta direction="), None);
    }

    /// Output arrives in arbitrary pieces. Splitting it at every byte offset
    /// must give the same connections as one whole read.
    #[test]
    fn flows_are_recovered_from_output_split_at_any_byte() {
        let whole = parse_fixture();
        let bytes = FIXTURE.as_bytes();
        for split in (0..bytes.len()).step_by(37) {
            let mut stream = FlowStream::new(usize::MAX);
            stream.push(&bytes[..split]);
            stream.push(&bytes[split..]);
            assert_eq!(stream.connections, whole, "split at {split}");
        }
    }

    #[test]
    fn reading_stops_at_the_cap_and_reports_truncation() {
        let mut stream = FlowStream::new(1);
        let keep_going = stream.push(FIXTURE.as_bytes());
        assert!(!keep_going);
        assert!(stream.truncated);
        assert_eq!(stream.connections.len(), 1);
    }

    #[test]
    fn a_table_within_the_cap_is_not_truncated() {
        let mut stream = FlowStream::new(MAX_CONNECTIONS);
        assert!(stream.push(FIXTURE.as_bytes()));
        assert!(!stream.truncated);
        assert_eq!(stream.connections.len(), parse_fixture().len());
    }
}
