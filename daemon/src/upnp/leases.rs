//! Reading miniupnpd's lease file.
//!
//! miniupnpd writes one line per mapping:
//!
//! ```text
//! PROTO:EXTPORT:INTADDR:INTPORT:TIMESTAMP:DESCRIPTION
//! ```
//!
//! `TIMESTAMP` is the Unix time the lease ends, or `0` for no lease. The
//! description is supplied by the client, so it is treated as untrusted text.
//! It may contain colons, which is why only the first five separators split
//! fields.

use std::net::Ipv4Addr;

use keystone_core::upnp::{UpnpMapping, UpnpProtocol};

/// Longest description kept. Longer text is cut, not rejected.
const DESCRIPTION_MAX_CHARS: usize = 256;

/// Parse the whole file. Malformed lines are skipped and counted, so one bad
/// line never hides the other mappings.
pub fn parse_lease_file(text: &str) -> (Vec<UpnpMapping>, Vec<String>) {
    let mut mappings = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_lease_line(line) {
            Ok(mapping) => mappings.push(mapping),
            Err(_) => skipped += 1,
        }
    }
    let mut warnings = Vec::new();
    if skipped > 0 {
        warnings.push(format!(
            "skipped {skipped} malformed line(s) in the miniupnpd lease file"
        ));
    }
    (mappings, warnings)
}

/// Parse one lease line. The error text is for tests and logs only; it never
/// reaches the API, because the line itself is untrusted.
pub fn parse_lease_line(line: &str) -> Result<UpnpMapping, &'static str> {
    let fields: Vec<&str> = line.splitn(6, ':').collect();
    let [
        proto,
        external,
        internal,
        internal_port,
        expires,
        description,
    ] = fields.as_slice()
    else {
        return Err("wrong number of fields");
    };

    let protocol = match *proto {
        "TCP" => UpnpProtocol::Tcp,
        "UDP" => UpnpProtocol::Udp,
        _ => return Err("unsupported protocol"),
    };
    let external_port: u16 = external.parse().map_err(|_| "bad external port")?;
    let internal_address: Ipv4Addr = internal.parse().map_err(|_| "bad internal address")?;
    let internal_port: u16 = internal_port.parse().map_err(|_| "bad internal port")?;
    let expires: u32 = expires.parse().map_err(|_| "bad lease time")?;
    if external_port == 0 || internal_port == 0 {
        return Err("port zero");
    }

    Ok(UpnpMapping {
        protocol,
        external_port,
        internal_address: internal_address.to_string(),
        internal_port,
        expires_at: (expires != 0).then_some(i64::from(expires)),
        description: clean_description(description),
    })
}

/// Drop control characters and cap the length, so the text is safe to show.
fn clean_description(description: &str) -> String {
    description
        .chars()
        .filter(|c| !c.is_control())
        .take(DESCRIPTION_MAX_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_file_is_parsed_in_order() {
        let text = "TCP:8080:192.168.1.50:80:1767225600:Web server\n\
                    UDP:5353:192.168.1.7:5353:0:Permanent\n";
        let (mappings, warnings) = parse_lease_file(text);
        assert!(warnings.is_empty());
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].protocol, UpnpProtocol::Tcp);
        assert_eq!(mappings[0].external_port, 8080);
        assert_eq!(mappings[0].internal_address, "192.168.1.50");
        assert_eq!(mappings[0].internal_port, 80);
        assert_eq!(mappings[0].expires_at, Some(1_767_225_600));
        assert_eq!(mappings[0].description, "Web server");
        assert_eq!(mappings[1].protocol, UpnpProtocol::Udp);
        assert_eq!(mappings[1].expires_at, None);
    }

    #[test]
    fn colons_in_a_description_stay_in_the_description() {
        let mapping = parse_lease_line("TCP:443:10.0.0.9:8443:0:app: v1:beta: x").unwrap();
        assert_eq!(mapping.description, "app: v1:beta: x");
    }

    #[test]
    fn control_characters_are_removed_from_descriptions() {
        let mapping = parse_lease_line("TCP:1:10.0.0.9:2:0:bad\u{1b}[31mname\r").unwrap();
        assert_eq!(mapping.description, "bad[31mname");
    }

    #[test]
    fn long_descriptions_are_cut() {
        let long = "d".repeat(400);
        let mapping = parse_lease_line(&format!("UDP:9:10.0.0.9:9:0:{long}")).unwrap();
        assert_eq!(mapping.description.chars().count(), DESCRIPTION_MAX_CHARS);
    }

    #[test]
    fn malformed_lines_are_skipped_and_counted() {
        let text = "\
TCP:8080:192.168.1.50:80:0:ok
not a lease line
TCP:notaport:192.168.1.50:80:0:bad port
TCP:8080:999.1.1.1:80:0:bad address
SCTP:8080:192.168.1.50:80:0:bad protocol
TCP:8080:192.168.1.50:80:soon:bad time
TCP:0:192.168.1.50:80:0:port zero
UDP:53:192.168.1.50:53:0:fine

";
        let (mappings, warnings) = parse_lease_file(text);
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[1].description, "fine");
        assert_eq!(
            warnings,
            vec!["skipped 6 malformed line(s) in the miniupnpd lease file"]
        );
    }

    #[test]
    fn an_empty_file_has_no_mappings_and_no_warnings() {
        assert_eq!(parse_lease_file(""), (Vec::new(), Vec::new()));
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let (mappings, warnings) = parse_lease_file("TCP:22:10.0.0.2:22:0:ssh\r\n");
        assert!(warnings.is_empty());
        assert_eq!(mappings[0].description, "ssh");
    }
}
