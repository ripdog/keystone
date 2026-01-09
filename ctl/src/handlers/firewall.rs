use anyhow::Result;
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
                let token = get_token(token)?;
                let response: FirewallZonesResponse =
                    client.get("/firewall/zones", Some(&token)).await?;
                output(cli_json, &response, pretty::firewall_zones);
            }

            ZonesCommands::Add {
                token,
                name,
                description,
                interfaces,
                input_policy,
                forward_policy,
            } => {
                let token = get_token(token)?;
                let interfaces_vec: Vec<String> = interfaces
                    .map(|s| s.split(',').map(|i| i.trim().to_string()).collect())
                    .unwrap_or_default();

                let input_policy: FirewallPolicy = input_policy
                    .parse()
                    .map_err(|e: String| anyhow::anyhow!(e))?;
                let forward_policy: FirewallPolicy = forward_policy
                    .parse()
                    .map_err(|e: String| anyhow::anyhow!(e))?;

                let zone = FirewallZone {
                    id: None,
                    name,
                    description,
                    interfaces: interfaces_vec,
                    default_input_policy: input_policy,
                    default_forward_policy: forward_policy,
                };

                let request = SaveFirewallZoneRequest { zone };
                let response: SaveFirewallZoneResponse = client
                    .post("/firewall/zones", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_zone);
                if !response.success {
                    std::process::exit(1);
                }
            }

            ZonesCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteFirewallZoneRequest { id };
                let response: DeleteFirewallZoneResponse = client
                    .delete("/firewall/zones", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::delete_zone);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::ZoneForwards(zf_cmd) => match zf_cmd {
            ZoneForwardsCommands::List { token } => {
                let token = get_token(token)?;
                let response: ZoneForwardsResponse =
                    client.get("/firewall/zone-forwards", Some(&token)).await?;
                output(cli_json, &response, pretty::zone_forwards);
            }

            ZoneForwardsCommands::Add {
                token,
                source,
                dest,
                policy,
                enabled,
            } => {
                let token = get_token(token)?;
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
                let response: SaveZoneForwardResponse = client
                    .post("/firewall/zone-forwards", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_zone_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }

            ZoneForwardsCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteZoneForwardRequest { id };
                let response: DeleteZoneForwardResponse = client
                    .delete("/firewall/zone-forwards", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::delete_zone_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::PortForwards(pf_cmd) => match pf_cmd {
            PortForwardsCommands::List { token } => {
                let token = get_token(token)?;
                let response: PortForwardsResponse =
                    client.get("/firewall/port-forwards", Some(&token)).await?;
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
                let token = get_token(token)?;
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
                    dest_ip,
                    dest_port,
                };

                let request = SavePortForwardRequest { port_forward };
                let response: SavePortForwardResponse = client
                    .post("/firewall/port-forwards", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_port_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }

            PortForwardsCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeletePortForwardRequest { id };
                let response: DeletePortForwardResponse = client
                    .delete("/firewall/port-forwards", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::delete_port_forward);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::InputRules(ir_cmd) => match ir_cmd {
            InputRulesCommands::List { token } => {
                let token = get_token(token)?;
                let response: InputRulesResponse =
                    client.get("/firewall/input-rules", Some(&token)).await?;
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
                let token = get_token(token)?;
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
                    action,
                    log_enabled: log,
                    log_prefix,
                    rate_limit,
                };

                let request = SaveInputRuleRequest { rule };
                let response: SaveInputRuleResponse = client
                    .post("/firewall/input-rules", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_input_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }

            InputRulesCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteInputRuleRequest { id };
                let response: DeleteInputRuleResponse = client
                    .delete("/firewall/input-rules", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::delete_input_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::ForwardRules(fr_cmd) => match fr_cmd {
            ForwardRulesCommands::List { token } => {
                let token = get_token(token)?;
                let response: ForwardRulesResponse =
                    client.get("/firewall/forward-rules", Some(&token)).await?;
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
                let token = get_token(token)?;
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
                    action,
                    log_enabled: log,
                    log_prefix,
                    rate_limit,
                };

                let request = SaveForwardRuleRequest { rule };
                let response: SaveForwardRuleResponse = client
                    .post("/firewall/forward-rules", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_forward_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }

            ForwardRulesCommands::Delete { token, id } => {
                let token = get_token(token)?;
                let request = DeleteForwardRuleRequest { id };
                let response: DeleteForwardRuleResponse = client
                    .delete("/firewall/forward-rules", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::delete_forward_rule);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::Settings(settings_cmd) => match settings_cmd {
            SettingsCommands::Get { token } => {
                let token = get_token(token)?;
                let response: FirewallGlobalSettingsResponse =
                    client.get("/firewall/settings", Some(&token)).await?;
                output(cli_json, &response, pretty::firewall_settings);
            }

            SettingsCommands::Set {
                token,
                ping_wan,
                ping_lan,
                hairpin_nat,
            } => {
                let token = get_token(token)?;

                let current: FirewallGlobalSettingsResponse =
                    client.get("/firewall/settings", Some(&token)).await?;

                let settings = FirewallGlobalSettings {
                    ping_wan_enabled: ping_wan.unwrap_or(current.settings.ping_wan_enabled),
                    ping_lan_enabled: ping_lan.unwrap_or(current.settings.ping_lan_enabled),
                    hairpin_nat_enabled: hairpin_nat
                        .unwrap_or(current.settings.hairpin_nat_enabled),
                };

                let request = SaveFirewallGlobalSettingsRequest { settings };
                let response: SaveFirewallGlobalSettingsResponse = client
                    .post("/firewall/settings", &request, Some(&token))
                    .await?;
                output(cli_json, &response, pretty::save_firewall_settings);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        FirewallCommands::Preview { token } => {
            let token = get_token(token)?;
            let response: FirewallPreviewResponse =
                client.get("/firewall/preview", Some(&token)).await?;
            output(cli_json, &response, pretty::firewall_preview);
        }

        FirewallCommands::Apply { token } => {
            let token = get_token(token)?;
            let request = FirewallApplyRequest {};
            let response: FirewallApplyResponse = client
                .post("/firewall/apply", &request, Some(&token))
                .await?;
            output(cli_json, &response, pretty::firewall_apply);
            if !response.success {
                std::process::exit(1);
            }
        }

        FirewallCommands::Confirm { token, session_id } => {
            let token = get_token(token)?;
            let request = FirewallConfirmRequest { session_id };
            let response: FirewallConfirmResponse = client
                .post("/firewall/confirm", &request, Some(&token))
                .await?;
            output(cli_json, &response, pretty::firewall_confirm);
            if !response.success {
                std::process::exit(1);
            }
        }

        FirewallCommands::Rollback { token } => {
            let token = get_token(token)?;
            let response: FirewallRollbackResponse =
                client.post("/firewall/rollback", &(), Some(&token)).await?;
            output(cli_json, &response, pretty::firewall_rollback);
            if !response.success {
                std::process::exit(1);
            }
        }

        FirewallCommands::Status { token } => {
            let token = get_token(token)?;
            let response: FirewallStatusResponse =
                client.get("/firewall/status", Some(&token)).await?;
            output(cli_json, &response, pretty::firewall_status);
        }
    }

    Ok(())
}
