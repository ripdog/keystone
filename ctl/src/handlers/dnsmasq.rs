use anyhow::Result;
use keystone_core::*;

use crate::client::DaemonClient;
use crate::commands::{
    AddressOverrideCommands, CnameRecordCommands, DhcpOptionCommands, DhcpRangeCommands,
    DnsmasqCommands, DnsmasqConfigCommands, HostRecordCommands, StaticLeaseCommands,
};
use crate::io::{output, output_slice};
use crate::pretty;
use crate::token::get_token;

pub async fn handle_dnsmasq_command(
    client: &DaemonClient,
    cli_json: bool,
    subcmd: DnsmasqCommands,
) -> Result<()> {
    match subcmd {
        DnsmasqCommands::State { token } => {
            let authed = client.authed(get_token(token)?);
            let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
            output(cli_json, &response, pretty::dnsmasq_state);
        }

        DnsmasqCommands::Config(config_cmd) => match config_cmd {
            DnsmasqConfigCommands::Get { token } => {
                let authed = client.authed(get_token(token)?);
                let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
                output(cli_json, &response.config, pretty::dnsmasq_config);
            }

            DnsmasqConfigCommands::Set {
                token,
                enabled,
                cache_size,
                local_domain,
                upstream_mode,
                dnssec,
                log_queries,
                log_dhcp,
            } => {
                let authed = client.authed(get_token(token)?);

                let current: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;

                let upstream = match upstream_mode.as_deref() {
                    Some("system") => Some(DnsmasqUpstreamMode::System),
                    Some("custom") => Some(DnsmasqUpstreamMode::Custom),
                    Some("localadguard") => Some(DnsmasqUpstreamMode::LocalAdGuard),
                    Some(other) => {
                        anyhow::bail!(
                            "Invalid upstream mode '{}'. Valid options: system, custom, localadguard",
                            other
                        );
                    }
                    None => None,
                };

                let config = DnsmasqConfig {
                    enabled: enabled.unwrap_or(current.config.enabled),
                    dns_port: current.config.dns_port,
                    cache_size: cache_size.unwrap_or(current.config.cache_size),
                    local_domain: local_domain.or(current.config.local_domain),
                    upstream_mode: upstream.unwrap_or(current.config.upstream_mode),
                    upstream_servers: current.config.upstream_servers,
                    dnssec_enabled: dnssec.unwrap_or(current.config.dnssec_enabled),
                    domain_needed: current.config.domain_needed,
                    bogus_priv: current.config.bogus_priv,
                    expand_hosts: current.config.expand_hosts,
                    listen_interfaces: current.config.listen_interfaces,
                    except_interfaces: current.config.except_interfaces,
                    no_dhcp_interfaces: current.config.no_dhcp_interfaces,
                    bind_dynamic: current.config.bind_dynamic,
                    log_queries: log_queries.unwrap_or(current.config.log_queries),
                    log_dhcp: log_dhcp.unwrap_or(current.config.log_dhcp),
                };

                let request = SaveDnsmasqConfigRequest { config };
                let response: SaveDnsmasqConfigResponse =
                    authed.post("/dnsmasq/config", &request).await?;
                output(cli_json, &response, pretty::save_dnsmasq_config);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        DnsmasqCommands::Ranges(ranges_cmd) => match ranges_cmd {
            DhcpRangeCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
                output_slice(cli_json, &response.dhcp_ranges, pretty::dhcp_ranges);
            }

            DhcpRangeCommands::Add {
                token,
                name,
                interface,
                start,
                end,
                netmask,
                lease_time,
                enabled,
            } => {
                let authed = client.authed(get_token(token)?);
                let range = DnsmasqDhcpRange {
                    id: None,
                    name,
                    interface,
                    start_address: start,
                    end_address: end,
                    netmask,
                    lease_time,
                    enabled,
                    ipv6_mode: None,
                    ipv6_prefix: None,
                };
                let request = SaveDhcpRangeRequest { range };
                let response: SaveDhcpRangeResponse =
                    authed.post("/dnsmasq/ranges", &request).await?;
                output(cli_json, &response, pretty::save_dhcp_range);
                if !response.success {
                    std::process::exit(1);
                }
            }

            DhcpRangeCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let request = DeleteDhcpRangeRequest { id };
                let response: serde_json::Value =
                    authed.delete("/dnsmasq/ranges", &request).await?;

                let success = response
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if cli_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&response).unwrap_or_default()
                    );
                } else {
                    pretty::delete_success(success, message);
                }

                if !success {
                    std::process::exit(1);
                }
            }
        },

        DnsmasqCommands::Leases(leases_cmd) => match leases_cmd {
            StaticLeaseCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
                output_slice(cli_json, &response.static_leases, pretty::static_leases);
            }

            StaticLeaseCommands::Add {
                token,
                mac,
                ip,
                hostname,
                enabled,
            } => {
                let authed = client.authed(get_token(token)?);
                let lease = DnsmasqStaticLease {
                    id: None,
                    mac_address: mac,
                    ip_address: ip,
                    hostname,
                    enabled,
                    lease_time: None,
                    client_id: None,
                    set_tags: Vec::new(),
                };
                let request = SaveStaticLeaseRequest { lease };
                let response: SaveStaticLeaseResponse =
                    authed.post("/dnsmasq/static-leases", &request).await?;
                output(cli_json, &response, pretty::save_static_lease);
                if !response.success {
                    std::process::exit(1);
                }
            }

            StaticLeaseCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let request = DeleteStaticLeaseRequest { id };
                let response: serde_json::Value =
                    authed.delete("/dnsmasq/static-leases", &request).await?;

                let success = response
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if cli_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&response).unwrap_or_default()
                    );
                } else {
                    pretty::delete_success(success, message);
                }

                if !success {
                    std::process::exit(1);
                }
            }
        },

        DnsmasqCommands::Options(options_cmd) => match options_cmd {
            DhcpOptionCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
                output_slice(cli_json, &response.dhcp_options, pretty::dhcp_options);
            }

            DhcpOptionCommands::Add {
                token,
                option,
                value,
                description,
                ipv6,
                force,
                enabled,
            } => {
                let token = get_token(token)?;
                let opt = DnsmasqDhcpOption {
                    id: None,
                    option,
                    value,
                    description,
                    match_tags: Vec::new(),
                    enabled,
                    ipv6,
                    force,
                };
                let request = SaveDhcpOptionRequest { option: opt };
                let response: SaveDhcpOptionResponse = client
                    .post("/dnsmasq/dhcp-options", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_dhcp_option);
                if !response.success {
                    std::process::exit(1);
                }
            }

            DhcpOptionCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteDhcpOptionRequest { id };
                let response: serde_json::Value = client
                    .delete("/dnsmasq/dhcp-options", &request, Some(&token))
                    .await?;

                let success = response
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if cli_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&response).unwrap_or_default()
                    );
                } else {
                    pretty::delete_success(success, message);
                }

                if !success {
                    std::process::exit(1);
                }
            }
        },

        DnsmasqCommands::Hosts(hosts_cmd) => match hosts_cmd {
            HostRecordCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
                output_slice(cli_json, &response.host_records, pretty::host_records);
            }

            HostRecordCommands::Add {
                token,
                hostnames,
                ipv4,
                ipv6,
                enabled,
            } => {
                let token = get_token(token)?;

                let hostnames_vec: Vec<String> = hostnames
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                if hostnames_vec.is_empty() {
                    anyhow::bail!("At least one hostname is required");
                }

                if ipv4.is_none() && ipv6.is_none() {
                    anyhow::bail!("At least one of --ipv4 or --ipv6 is required");
                }

                let record = DnsmasqHostRecord {
                    id: None,
                    hostnames: hostnames_vec,
                    ipv4_address: ipv4,
                    ipv6_address: ipv6,
                    ttl: None,
                    enabled,
                };

                let request = SaveHostRecordRequest { record };
                let response: SaveHostRecordResponse = client
                    .post("/dnsmasq/host-records", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_host_record);
                if !response.success {
                    std::process::exit(1);
                }
            }

            HostRecordCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteHostRecordRequest { id };
                let response: serde_json::Value = client
                    .delete("/dnsmasq/host-records", &request, Some(&token))
                    .await?;

                let success = response
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if cli_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&response).unwrap_or_default()
                    );
                } else {
                    pretty::delete_success(success, message);
                }

                if !success {
                    std::process::exit(1);
                }
            }
        },

        DnsmasqCommands::Cnames(cnames_cmd) => match cnames_cmd {
            CnameRecordCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
                output_slice(cli_json, &response.cname_records, pretty::cname_records);
            }

            CnameRecordCommands::Add {
                token,
                alias,
                target,
                enabled,
            } => {
                let token = get_token(token)?;
                let record = DnsmasqCnameRecord {
                    id: None,
                    alias,
                    target,
                    ttl: None,
                    enabled,
                };

                let request = SaveCnameRecordRequest { record };
                let response: SaveCnameRecordResponse = client
                    .post("/dnsmasq/cname-records", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_cname_record);
                if !response.success {
                    std::process::exit(1);
                }
            }

            CnameRecordCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteCnameRecordRequest { id };
                let response: serde_json::Value = client
                    .delete("/dnsmasq/cname-records", &request, Some(&token))
                    .await?;

                let success = response
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if cli_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&response).unwrap_or_default()
                    );
                } else {
                    pretty::delete_success(success, message);
                }

                if !success {
                    std::process::exit(1);
                }
            }
        },

        DnsmasqCommands::Overrides(overrides_cmd) => match overrides_cmd {
            AddressOverrideCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: DnsmasqStateResponse = authed.get("/dnsmasq/state").await?;
                output_slice(
                    cli_json,
                    &response.address_overrides,
                    pretty::address_overrides,
                );
            }

            AddressOverrideCommands::Add {
                token,
                domain,
                action,
                redirect_to,
                enabled,
            } => {
                let token = get_token(token)?;

                let action_enum = match action.to_lowercase().as_str() {
                    "block" => DnsmasqAddressAction::Block,
                    "redirect" => DnsmasqAddressAction::Redirect,
                    "null" => DnsmasqAddressAction::Null,
                    other => {
                        anyhow::bail!(
                            "Invalid action '{}'. Valid options: block, redirect, null",
                            other
                        );
                    }
                };

                if matches!(action_enum, DnsmasqAddressAction::Redirect) && redirect_to.is_none() {
                    anyhow::bail!("--redirect-to is required when action is 'redirect'");
                }

                let ovr = DnsmasqAddressOverride {
                    id: None,
                    domain,
                    action: action_enum,
                    redirect_address: redirect_to,
                    enabled,
                };
                let request = SaveAddressOverrideRequest {
                    override_entry: ovr,
                };
                let response: SaveAddressOverrideResponse = client
                    .post("/dnsmasq/address-overrides", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_address_override);
                if !response.success {
                    std::process::exit(1);
                }
            }

            AddressOverrideCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteAddressOverrideRequest { id };
                let response: serde_json::Value = client
                    .delete("/dnsmasq/address-overrides", &request, Some(&token))
                    .await?;

                let success = response
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let message = response
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if cli_json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&response).unwrap_or_default()
                    );
                } else {
                    pretty::delete_success(success, message);
                }

                if !success {
                    std::process::exit(1);
                }
            }
        },

        DnsmasqCommands::ActiveLeases { token } => {
            let authed = client.authed(get_token(token)?);
            let response: DhcpLeasesResponse = authed.get("/dnsmasq/leases").await?;
            output(cli_json, &response, pretty::active_leases);
        }

        DnsmasqCommands::Preview { token } => {
            let authed = client.authed(get_token(token)?);
            let response: DnsmasqPreviewResponse = authed.get("/dnsmasq/preview").await?;
            output(cli_json, &response, pretty::dnsmasq_preview);
        }

        DnsmasqCommands::Apply { token } => {
            let authed = client.authed(get_token(token)?);
            let request = DnsmasqApplyRequest {};
            let response: DnsmasqApplyResponse = authed.post("/dnsmasq/apply", &request).await?;
            output(cli_json, &response, pretty::dnsmasq_apply);
            if !response.success {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
