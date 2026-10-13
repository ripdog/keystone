use anyhow::Result;
use keystone_core::api::{
    ConfirmFirewall, SaveFirewallGlobalSettings, SaveFirewallZone, SaveForwardRule, SaveInputRule,
    SavePortForward, SaveZoneForward,
};
use keystone_core::*;

use crate::client::DaemonClient;
use crate::commands::{
    FirewallCommands, ForwardRulesCommands, InputRulesCommands, PortForwardsCommands,
    SettingsCommands, ZoneForwardsCommands, ZonesCommands,
};
use crate::io::output;
use crate::pretty;
use crate::token::get_token;

pub async fn handle_firewall_command(
    client: &DaemonClient,
    cli_json: bool,
    subcmd: FirewallCommands,
) -> Result<()> {
    match subcmd {
        FirewallCommands::Zones(zones_cmd) => match zones_cmd {
            ZonesCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: FirewallZonesResponse = authed.get("/firewall/zones").await?;
                output(cli_json, &response, pretty::firewall_zones);
            }

            ZonesCommands::Add {
                token,
                id,
                name,
                description,
                interfaces,
                input_policy,
                wan,
                masquerade_ipv4,
            } => {
                let authed = client.authed(get_token(token)?);
                let interfaces_vec: Vec<String> = interfaces
                    .map(|s| s.split(',').map(|i| i.trim().to_string()).collect())
                    .unwrap_or_default();

                let input_policy: FirewallPolicy = input_policy
                    .parse()
                    .map_err(|e: String| anyhow::anyhow!(e))?;

                let zone = FirewallZone {
                    id,
                    name,
                    description,
                    interfaces: interfaces_vec,
                    is_wan: wan,
                    masquerade_ipv4,
                    default_input_policy: input_policy,
                    // Unused by the firewall generator; kept for storage compatibility.
                    default_forward_policy: FirewallPolicy::Drop,
                };

                let request = SaveFirewallZoneRequest { zone };
                let response: SaveFirewallZoneResponse =
                    authed.call::<SaveFirewallZone>(&request).await?;
                output(cli_json, &response, pretty::save_zone);
                if !response.success {
                    std::process::exit(1);
                }
            }

            ZonesCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let response: DeleteFirewallZoneResponse =
                    authed.delete(&format!("/firewall/zones/{}", id)).await?;
                output(cli_json, &response, pretty::delete_zone);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::ZoneForwards(zf_cmd) => match zf_cmd {
            ZoneForwardsCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: ZoneForwardsResponse = authed.get("/firewall/zone-forwards").await?;
                output(cli_json, &response, pretty::zone_forwards);
            }

            ZoneForwardsCommands::Add {
                token,
                source,
                dest,
                policy,
                enabled,
            } => {
                let authed = client.authed(get_token(token)?);
                let policy: FirewallAction =
                    policy.parse().map_err(|e: String| anyhow::anyhow!(e))?;

                let forward = ZoneForwardPolicy {
                    id: None,
                    source_zone: source,
                    dest_zone: dest,
                    policy,
                    enabled,
                };

                let request = SaveZoneForwardRequest { forward };
                let response: SaveZoneForwardResponse =
                    authed.call::<SaveZoneForward>(&request).await?;
                output(cli_json, &response, pretty::save_zone_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }

            ZoneForwardsCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let response: DeleteZoneForwardResponse = authed
                    .delete(&format!("/firewall/zone-forwards/{}", id))
                    .await?;
                output(cli_json, &response, pretty::delete_zone_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::PortForwards(pf_cmd) => match pf_cmd {
            PortForwardsCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: PortForwardsResponse = authed.get("/firewall/port-forwards").await?;
                output(cli_json, &response, pretty::port_forwards);
            }

            PortForwardsCommands::Add {
                token,
                name,
                description,
                protocol,
                source_zone,
                external_port,
                external_port_end,
                source_ip,
                dest_ip,
                dest_port,
                enabled,
            } => {
                let authed = client.authed(get_token(token)?);
                let protocol: RuleProtocol =
                    protocol.parse().map_err(|e: String| anyhow::anyhow!(e))?;

                let port_forward = PortForward {
                    id: None,
                    name,
                    description,
                    enabled,
                    protocol,
                    source_zone,
                    external_port_start: external_port,
                    external_port_end,
                    source_ip,
                    source_group: None,
                    dest_ip,
                    dest_port,
                };

                let request = SavePortForwardRequest { port_forward };
                let response: SavePortForwardResponse =
                    authed.call::<SavePortForward>(&request).await?;
                output(cli_json, &response, pretty::save_port_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }

            PortForwardsCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let response: DeletePortForwardResponse = authed
                    .delete(&format!("/firewall/port-forwards/{}", id))
                    .await?;
                output(cli_json, &response, pretty::delete_port_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::InputRules(ir_cmd) => match ir_cmd {
            InputRulesCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: InputRulesResponse = authed.get("/firewall/input-rules").await?;
                output(cli_json, &response, pretty::input_rules);
            }

            InputRulesCommands::Add {
                token,
                name,
                description,
                zone,
                protocol,
                port,
                port_end,
                source_ip,
                action,
                log,
                log_prefix,
                rate_limit,
                position,
                enabled,
            } => {
                let authed = client.authed(get_token(token)?);
                let protocol: Option<RuleProtocol> = protocol
                    .map(|p| p.parse())
                    .transpose()
                    .map_err(|e: String| anyhow::anyhow!(e))?;
                let action: FirewallAction =
                    action.parse().map_err(|e: String| anyhow::anyhow!(e))?;

                let rule = InputRule {
                    id: None,
                    name,
                    description,
                    enabled,
                    position,
                    zone,
                    protocol,
                    port_start: port,
                    port_end,
                    source_ip,
                    source_group: None,
                    dest_port_group: None,
                    action,
                    log_enabled: log,
                    log_prefix,
                    rate_limit,
                };

                let request = SaveInputRuleRequest { rule };
                let response: SaveInputRuleResponse =
                    authed.call::<SaveInputRule>(&request).await?;
                output(cli_json, &response, pretty::save_input_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }

            InputRulesCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let response: DeleteInputRuleResponse = authed
                    .delete(&format!("/firewall/input-rules/{}", id))
                    .await?;
                output(cli_json, &response, pretty::delete_input_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::ForwardRules(fr_cmd) => match fr_cmd {
            ForwardRulesCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: ForwardRulesResponse = authed.get("/firewall/forward-rules").await?;
                output(cli_json, &response, pretty::forward_rules);
            }

            ForwardRulesCommands::Add {
                token,
                name,
                description,
                source_zone,
                dest_zone,
                protocol,
                dest_port,
                dest_port_end,
                source_ip,
                dest_ip,
                action,
                log,
                log_prefix,
                rate_limit,
                position,
                enabled,
            } => {
                let authed = client.authed(get_token(token)?);
                let protocol: Option<RuleProtocol> = protocol
                    .map(|p| p.parse())
                    .transpose()
                    .map_err(|e: String| anyhow::anyhow!(e))?;
                let action: FirewallAction =
                    action.parse().map_err(|e: String| anyhow::anyhow!(e))?;

                let rule = ForwardRule {
                    id: None,
                    name,
                    description,
                    enabled,
                    position,
                    source_zone,
                    dest_zone,
                    protocol,
                    dest_port_start: dest_port,
                    dest_port_end,
                    source_ip,
                    dest_ip,
                    source_group: None,
                    dest_group: None,
                    dest_port_group: None,
                    action,
                    log_enabled: log,
                    log_prefix,
                    rate_limit,
                };

                let request = SaveForwardRuleRequest { rule };
                let response: SaveForwardRuleResponse =
                    authed.call::<SaveForwardRule>(&request).await?;
                output(cli_json, &response, pretty::save_forward_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }

            ForwardRulesCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let response: DeleteForwardRuleResponse = authed
                    .delete(&format!("/firewall/forward-rules/{}", id))
                    .await?;
                output(cli_json, &response, pretty::delete_forward_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::Settings(settings_cmd) => match settings_cmd {
            SettingsCommands::Get { token } => {
                let authed = client.authed(get_token(token)?);
                let response: FirewallGlobalSettingsResponse =
                    authed.get("/firewall/settings").await?;
                output(cli_json, &response, pretty::firewall_settings);
            }

            SettingsCommands::Set {
                token,
                ping_wan,
                ping_lan,
                hairpin_nat,
            } => {
                let authed = client.authed(get_token(token)?);

                let current: FirewallGlobalSettingsResponse =
                    authed.get("/firewall/settings").await?;

                let settings = FirewallGlobalSettings {
                    ping_wan_enabled: ping_wan.unwrap_or(current.settings.ping_wan_enabled),
                    ping_lan_enabled: ping_lan.unwrap_or(current.settings.ping_lan_enabled),
                    hairpin_nat_enabled: hairpin_nat
                        .unwrap_or(current.settings.hairpin_nat_enabled),
                };

                let request = SaveFirewallGlobalSettingsRequest { settings };
                let response: SaveFirewallGlobalSettingsResponse =
                    authed.call::<SaveFirewallGlobalSettings>(&request).await?;
                output(cli_json, &response, pretty::save_firewall_settings);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::Preview { token } => {
            let authed = client.authed(get_token(token)?);
            let response: FirewallPreviewResponse = authed.get("/firewall/preview").await?;
            output(cli_json, &response, pretty::firewall_preview);
        }

        FirewallCommands::Apply { token } => {
            let authed = client.authed(get_token(token)?);
            let request = FirewallApplyRequest {};
            let response: FirewallApplyResponse = authed.post("/firewall/apply", &request).await?;
            output(cli_json, &response, pretty::firewall_apply);
            if !response.success {
                std::process::exit(1);
            }
        }

        FirewallCommands::Confirm { token, session_id } => {
            let authed = client.authed(get_token(token)?);
            let request = FirewallConfirmRequest { session_id };
            let response: FirewallConfirmResponse =
                authed.call::<ConfirmFirewall>(&request).await?;
            output(cli_json, &response, pretty::firewall_confirm);
            if !response.success {
                std::process::exit(1);
            }
        }

        FirewallCommands::Rollback { token } => {
            let authed = client.authed(get_token(token)?);
            let response: FirewallRollbackResponse = authed.post("/firewall/rollback", &()).await?;
            output(cli_json, &response, pretty::firewall_rollback);
            if !response.success {
                std::process::exit(1);
            }
        }

        FirewallCommands::Status { token } => {
            let authed = client.authed(get_token(token)?);
            let response: FirewallStatusResponse = authed.get("/firewall/status").await?;
            output(cli_json, &response, pretty::firewall_status);
        }
    }

    Ok(())
}
