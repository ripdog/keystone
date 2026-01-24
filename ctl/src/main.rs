//! keystonectl - Command-line interface for Keystone
//!
//! Communicates with the keystone-daemon over Unix socket at /run/keystone/keystone.sock

// CLI argument enums naturally have variant size differences - this is expected
#![allow(clippy::large_enum_variant)]

use anyhow::{Context, Result};
use clap::Parser;
use keystone_core::{
    ApplyConfigRequest, ApplyConfigResponse, CompleteSetupResponse, DashboardResponse,
    DeleteUserRequest, DeleteUserResponse, LoginRequest, LoginResponse, ManagedInterfacesResponse,
    SaveManagedInterfacesRequest, SaveManagedInterfacesResponse, SaveUserRequest, SaveUserResponse,
    SystemState, UsersResponse,
};

mod client;
mod commands;
mod handlers;
mod io;
mod pretty;
mod token;
mod wizard;

use crate::client::DaemonClient;
use crate::commands::*;
use crate::handlers::dnsmasq::handle_dnsmasq_command;
use crate::handlers::firewall::handle_firewall_command;
use crate::io::{output, read_json_input};
use crate::token::get_token;

use std::path::Path;

pub const SOCKET_PATH: &str = "/run/keystone/keystone.sock";

pub fn state(state: &SystemState) {
    println!("=== System State ===\n");

    println!("Interfaces ({}):", state.interfaces.len());
    for iface in &state.interfaces {
        let status = if iface.enabled { "UP" } else { "DOWN" };
        let addr = iface.address.as_deref().unwrap_or("no address");
        let dhcp = if iface.dhcp_enabled { "DHCP" } else { "static" };
        println!(
            "  {} [{}] {} ({}, {})",
            iface.name, iface.role, addr, dhcp, status
        );
    }

    // TODO: Add firewall zone display once FirewallConfig is integrated
    println!("\nFirewall: Zone-based firewall (run 'keystonectl firewall' for details)");
}

pub fn dashboard(dashboard: &DashboardResponse) {
    state(&dashboard.state);

    println!("\nInterface Counters:");
    for counter in &dashboard.interface_counters {
        println!(
            "  {}: RX {} bytes ({} pkts), TX {} bytes ({} pkts)",
            counter.name,
            format_bytes(counter.rx_bytes),
            counter.rx_packets,
            format_bytes(counter.tx_bytes),
            counter.tx_packets
        );
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2}G", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.2}M", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2}K", bytes as f64 / 1_000.0)
    } else {
        format!("{}", bytes)
    }
}

pub fn apply(response: &ApplyConfigResponse) {
    if response.success {
        println!("✓ Configuration applied: {}", response.message);
    } else {
        println!("✗ Failed to apply configuration: {}", response.message);
        for err in &response.errors {
            println!("  - {}", err);
        }
    }
}

pub fn users(response: &UsersResponse) {
    println!("=== Users ===\n");
    println!("{:<6} {:<20} {:<30}", "ID", "Username", "Email");
    println!("{}", "-".repeat(60));
    for user in &response.users {
        let email = user.email.as_deref().unwrap_or("-");
        println!("{:<6} {:<20} {:<30}", user.id, user.username, email);
    }
}

pub fn save_user(response: &SaveUserResponse) {
    if response.success {
        println!("✓ {}", response.message);
        if let Some(id) = response.user_id {
            println!("  User ID: {}", id);
        }
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn delete_user(response: &DeleteUserResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

pub fn managed_interfaces(response: &ManagedInterfacesResponse) {
    println!("=== Managed Interfaces ===\n");
    println!(
        "{:<15} {:<6} {:<20} {:<8}",
        "Name", "Role", "Static IP", "Enabled"
    );
    println!("{}", "-".repeat(55));
    for iface in &response.interfaces {
        let ip = iface.static_ip.as_deref().unwrap_or("DHCP");
        let enabled = if iface.enabled { "yes" } else { "no" };
        println!(
            "{:<15} {:<6} {:<20} {:<8}",
            iface.name, iface.role, ip, enabled
        );
    }
}

pub fn save_interfaces(response: &SaveManagedInterfacesResponse) {
    if response.success {
        println!("✓ {}", response.message);
    } else {
        println!("✗ {}", response.message);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check socket exists before trying to connect
    if !Path::new(&cli.socket).exists() {
        eprintln!(
            "Error: Daemon socket not found at {}\n\
             Is keystone-daemon running?",
            cli.socket
        );
        std::process::exit(1);
    }

    let client = DaemonClient::new(cli.socket);

    match cli.command {
        None => {
            // No command specified - default to dashboard
            // If the daemon rejects dashboard because setup isn't complete,
            // fall back to prompting the user to run the setup wizard.
            let authed = client.authed(get_token(None)?);
            match authed.get::<DashboardResponse>("/dashboard").await {
                Ok(response) => output(cli.json, &response, pretty::dashboard),
                Err(e) => {
                    eprintln!("{e}");
                    eprintln!(
                        "If this system is not set up yet, configure it and then run: keystonectl complete-setup-now"
                    );
                    eprintln!("For interactive setup, run: keystonectl setup");
                    std::process::exit(1);
                }
            }
        }

        Some(Commands::Health) => {
            let response: serde_json::Value = client.get("/health", None).await?;
            output(cli.json, &response, pretty::health);
        }

        Some(Commands::Login { username, password }) => {
            let password = match password {
                Some(p) => p,
                None => {
                    // Prompt for password securely
                    rpassword::prompt_password(format!("Password for {}: ", username))
                        .context("Failed to read password")?
                }
            };
            let request = LoginRequest { username, password };
            let response: LoginResponse = client.post("/login", &request, None).await?;
            output(cli.json, &response, pretty::login);
            if !response.success {
                std::process::exit(1);
            }
        }

        Some(Commands::State { token }) => {
            let authed = client.authed(get_token(token)?);
            let response: SystemState = authed.get("/state").await?;
            output(cli.json, &response, pretty::state);
        }

        Some(Commands::Dashboard { token }) => {
            let authed = client.authed(get_token(token)?);
            let response: DashboardResponse = authed.get("/dashboard").await?;
            output(cli.json, &response, pretty::dashboard);
        }

        Some(Commands::Apply { token, file }) => {
            let authed = client.authed(get_token(token)?);
            let json_input = read_json_input(file.as_deref())?;
            let state: SystemState =
                serde_json::from_str(&json_input).context("Invalid JSON input")?;
            let request = ApplyConfigRequest { state };
            let response: ApplyConfigResponse = authed.post("/apply", &request).await?;
            output(cli.json, &response, pretty::apply);
            if !response.success {
                std::process::exit(1);
            }
        }

        Some(Commands::Users(subcmd)) => match subcmd {
            UsersCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: UsersResponse = authed.get("/users").await?;
                output(cli.json, &response, pretty::users);
            }

            UsersCommands::Create {
                token,
                username,
                email,
                password,
            } => {
                let authed = client.authed(get_token(token)?);
                let password = match password {
                    Some(p) => p,
                    None => {
                        // Prompt for password securely
                        let pass1 =
                            rpassword::prompt_password(format!("Password for {}: ", username))
                                .context("Failed to read password")?;
                        let pass2 = rpassword::prompt_password("Confirm password: ")
                            .context("Failed to read password confirmation")?;
                        if pass1 != pass2 {
                            eprintln!("Error: Passwords do not match");
                            std::process::exit(1);
                        }
                        pass1
                    }
                };
                let request = SaveUserRequest {
                    id: None,
                    username,
                    email,
                    password: Some(password),
                };
                let response: SaveUserResponse = authed.post("/users", &request).await?;
                output(cli.json, &response, pretty::save_user);
                if !response.success {
                    std::process::exit(1);
                }
            }

            UsersCommands::Update {
                token,
                id,
                username,
                email,
                password,
            } => {
                let authed = client.authed(get_token(token)?);
                let request = SaveUserRequest {
                    id: Some(id),
                    username,
                    email,
                    password,
                };
                let response: SaveUserResponse = authed.post("/users", &request).await?;
                output(cli.json, &response, pretty::save_user);
                if !response.success {
                    std::process::exit(1);
                }
            }

            UsersCommands::Delete { token, id } => {
                let authed = client.authed(get_token(token)?);
                let request = DeleteUserRequest { id };
                let response: DeleteUserResponse =
                    authed.delete_with_body("/users", &request).await?;
                output(cli.json, &response, pretty::delete_user);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        Some(Commands::Interfaces(subcmd)) => match subcmd {
            InterfacesCommands::List { token } => {
                let authed = client.authed(get_token(token)?);
                let response: ManagedInterfacesResponse = authed.get("/managed-interfaces").await?;
                output(cli.json, &response, pretty::managed_interfaces);
            }

            InterfacesCommands::Save { token, file } => {
                let authed = client.authed(get_token(token)?);
                let json_input = read_json_input(file.as_deref())?;
                let request: SaveManagedInterfacesRequest =
                    serde_json::from_str(&json_input).context("Invalid JSON input")?;
                let response: SaveManagedInterfacesResponse =
                    authed.post("/managed-interfaces", &request).await?;
                output(cli.json, &response, pretty::save_interfaces);
                if !response.success {
                    std::process::exit(1);
                }
            }
        },

        Some(Commands::Firewall(subcmd)) => {
            handle_firewall_command(&client, cli.json, subcmd).await?
        }

        Some(Commands::Setup) => {
            wizard::run_wizard(&client).await?;
        }

        Some(Commands::CompleteSetupNow { token }) => {
            let authed = client.authed(get_token(token)?);
            let response: CompleteSetupResponse = authed.post("/complete-setup", &()).await?;
            output(cli.json, &response, |r| println!("{}", r.message));
            if !response.success {
                std::process::exit(1);
            }
        }

        Some(Commands::Dnsmasq(subcmd)) => {
            handle_dnsmasq_command(&client, cli.json, subcmd).await?
        }
    }

    Ok(())
}
