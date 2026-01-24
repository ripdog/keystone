//! CLI Setup Wizard
//!
//! Interactive TUI wizard for initial Keystone configuration.
//! Uses inquire for beautiful terminal prompts.

use anyhow::Result;
use console::{Term, style};
use inquire::{Confirm, MultiSelect, Password, PasswordDisplayMode, Select, Text};
use keystone_core::{
    InterfaceRole, LoginRequest, LoginResponse, SaveUserRequest, SaveUserResponse, SystemState,
    SystemStatusResponse, WizardAdvanceRequest, WizardAdvanceResponse, WizardInterfaceAssignment,
    WizardSaveInterfacesRequest, WizardSaveInterfacesResponse, WizardSkipRequest,
    WizardSkipResponse, WizardState, WizardStateResponse, WizardStep,
};

use crate::client::DaemonClient;
use crate::token::save_token;

/// Run the interactive setup wizard
pub async fn run_wizard(client: &DaemonClient) -> Result<()> {
    let term = Term::stdout();
    term.clear_screen()?;

    println!();
    println!(
        "{}",
        style("╔══════════════════════════════════════════════════════════════╗")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("║                                                              ║")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("║               Welcome to Keystone Setup                      ║")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("║                                                              ║")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("╚══════════════════════════════════════════════════════════════╝")
            .cyan()
            .bold()
    );
    println!();
    println!(
        "{}",
        style("Keystone is a router and firewall manager for Arch Linux.").dim()
    );
    println!(
        "{}",
        style("This wizard will help you configure your system.").dim()
    );
    println!();

    // Step 0: Login
    let token = login_step(client).await?;

    // Get wizard state
    let state = get_wizard_state(client, &token).await?;

    if state.is_complete {
        println!();
        println!("{}", style("Setup is already complete!").green().bold());
        println!("Run 'keystonectl dashboard' to see system status.");
        return Ok(());
    }

    // Offer to skip
    println!();
    let skip = Confirm::new("Skip wizard and configure manually?")
        .with_default(false)
        .with_help_message("Only recommended for advanced users")
        .prompt()?;

    if skip {
        skip_wizard(client, &token).await?;
        println!();
        println!("{}", style("Wizard skipped.").yellow());
        println!("You can configure settings using keystonectl commands.");
        return Ok(());
    }

    // Run through each step based on current state
    let mut current_step = state.current_step;

    // Step 1: Change password (if not already done)
    if current_step == WizardStep::NotStarted {
        println!();
        println!(
            "{}",
            style("━━━ Step 1: Change Default Password ━━━")
                .cyan()
                .bold()
        );
        println!();
        change_password_step(client, &token).await?;
        current_step = advance_wizard(client, &token, WizardStep::NotStarted).await?;
    }

    // Step 2: System checks
    if current_step == WizardStep::PasswordChanged {
        println!();
        println!(
            "{}",
            style("━━━ Step 2: System Requirements ━━━").cyan().bold()
        );
        println!();
        system_checks_step(client, &token).await?;
        current_step = advance_wizard(client, &token, WizardStep::PasswordChanged).await?;
    }

    // Refresh wizard state after advancing.
    if current_step == WizardStep::SystemChecksCompleted {
        current_step = get_wizard_state(client, &token).await?.current_step;
    }

    // Step 3: Interface assignment
    if current_step == WizardStep::SystemChecksCompleted {
        println!();
        println!(
            "{}",
            style("━━━ Step 3: Configure Network Interfaces ━━━")
                .cyan()
                .bold()
        );
        println!();
        interface_assignment_step(client, &token).await?;
        current_step = advance_wizard(client, &token, WizardStep::SystemChecksCompleted).await?;
    }

    // Step 4: Complete
    if current_step == WizardStep::InterfacesAssigned {
        advance_wizard(client, &token, WizardStep::InterfacesAssigned).await?;
    }

    // Show completion message
    println!();
    println!(
        "{}",
        style("╔══════════════════════════════════════════════════════════════╗")
            .green()
            .bold()
    );
    println!(
        "{}",
        style("║                                                              ║")
            .green()
            .bold()
    );
    println!(
        "{}",
        style("║                   Setup Complete!                            ║")
            .green()
            .bold()
    );
    println!(
        "{}",
        style("║                                                              ║")
            .green()
            .bold()
    );
    println!(
        "{}",
        style("╚══════════════════════════════════════════════════════════════╝")
            .green()
            .bold()
    );
    println!();
    println!("What's been configured:");
    println!("  {} Admin password changed", style("✓").green());
    println!("  {} System requirements verified", style("✓").green());
    println!("  {} WAN and LAN interfaces configured", style("✓").green());
    println!("  {} Firewall zones created (wan, lan)", style("✓").green());
    println!("  {} LAN to WAN forwarding enabled", style("✓").green());
    println!();
    println!("Next steps:");
    println!(
        "  • Run '{}' to see system status",
        style("keystonectl dashboard").cyan()
    );
    println!(
        "  • Run '{}' to apply firewall rules",
        style("keystonectl firewall apply").cyan()
    );
    println!(
        "  • Access the web UI at {}",
        style("http://localhost:8080").cyan()
    );
    println!();

    Ok(())
}

/// Login step - authenticate with the daemon
async fn login_step(client: &DaemonClient) -> Result<String> {
    println!("{}", style("Please login to continue.").dim());
    println!("{}", style("Default credentials: admin / admin").dim());
    println!();

    loop {
        let username = Text::new("Username:").with_default("admin").prompt()?;

        let password = Password::new("Password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()?;

        let request = LoginRequest {
            username: username.clone(),
            password,
        };

        match client.post::<LoginResponse>("/login", &request, None).await {
            Ok(response) => {
                if response.success
                    && let Some(token) = response.token
                {
                    // Save token for future commands
                    save_token(&token)?;
                    println!();
                    println!(
                        "{} Logged in as {}",
                        style("✓").green(),
                        style(&username).cyan()
                    );
                    return Ok(token);
                }
                println!("{} {}", style("✗").red(), style(&response.message).red());
                println!();
            }
            Err(e) => {
                println!("{} Login failed: {}", style("✗").red(), e);
                println!();
            }
        }
    }
}

/// Get current wizard state from daemon
async fn get_wizard_state(client: &DaemonClient, token: &str) -> Result<WizardState> {
    // Daemon routes are mounted under /api when accessed via the web UI proxy.
    // keystonectl talks directly to the daemon, so it uses the raw paths.
    let response: WizardStateResponse = client.get("/wizard", Some(token)).await?;
    Ok(response.state)
}

/// Skip the wizard
async fn skip_wizard(client: &DaemonClient, token: &str) -> Result<()> {
    let request = WizardSkipRequest { confirm_skip: true };
    let _response: WizardSkipResponse = client.post("/wizard/skip", &request, Some(token)).await?;
    Ok(())
}

/// Advance wizard to next step
async fn advance_wizard(
    client: &DaemonClient,
    token: &str,
    completing_step: WizardStep,
) -> Result<WizardStep> {
    let request = WizardAdvanceRequest { completing_step };
    let response: WizardAdvanceResponse = client
        .post("/wizard/advance", &request, Some(token))
        .await?;

    if !response.success {
        anyhow::bail!("Failed to advance wizard: {}", response.message);
    }

    Ok(response.new_step)
}

/// Step 1: Change the default password
async fn change_password_step(client: &DaemonClient, token: &str) -> Result<()> {
    println!(
        "{}",
        style("For security, you must change the default admin password.").dim()
    );
    println!();

    loop {
        let new_password = Password::new("New password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_help_message("At least 8 characters")
            .without_confirmation()
            .prompt()?;

        if new_password.len() < 8 {
            println!(
                "{} Password must be at least 8 characters",
                style("✗").red()
            );
            continue;
        }

        let confirm_password = Password::new("Confirm password:")
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()?;

        if new_password != confirm_password {
            println!("{} Passwords do not match", style("✗").red());
            continue;
        }

        // Save the new password
        let request = SaveUserRequest {
            id: Some(1), // Admin user is always ID 1
            username: "admin".to_string(),
            email: None,
            password: Some(new_password),
        };

        let response: SaveUserResponse = client.post("/users", &request, Some(token)).await?;

        if response.success {
            println!();
            println!("{} Password updated successfully", style("✓").green());
            return Ok(());
        } else {
            println!(
                "{} Failed to update password: {}",
                style("✗").red(),
                response.message
            );
        }
    }
}

/// Step 2: System requirements check
async fn system_checks_step(client: &DaemonClient, token: &str) -> Result<()> {
    println!("{}", style("Checking system requirements...").dim());
    println!();

    loop {
        let response: SystemStatusResponse = client.get("/system-status", Some(token)).await?;

        // Display checks
        for check in &response.checks {
            let icon = match check.severity {
                keystone_core::CheckSeverity::Pass => style("✓").green(),
                keystone_core::CheckSeverity::Warning => style("⚠").yellow(),
                keystone_core::CheckSeverity::Error => style("✗").red(),
            };
            println!("  {} {}: {}", icon, check.name, check.message);

            if let Some(ref advice) = check.fix_advice {
                println!("    {}", style(format!("Fix: {}", advice)).dim());
            }
        }

        println!();

        if response.all_checks_pass {
            println!("{} All system checks passed!", style("✓").green().bold());
            return Ok(());
        }

        println!(
            "{} {} errors, {} warnings",
            style("!").yellow(),
            response.error_count,
            response.warning_count
        );
        println!();

        let retry = Confirm::new("Retry checks?")
            .with_default(true)
            .with_help_message("Fix the issues above and retry")
            .prompt()?;

        if !retry {
            anyhow::bail!(
                "System checks did not pass. Please fix the issues and run the wizard again."
            );
        }

        println!();
        println!("{}", style("Re-checking...").dim());
        println!();
    }
}

/// Step 3: Interface assignment
async fn interface_assignment_step(client: &DaemonClient, token: &str) -> Result<()> {
    println!(
        "{}",
        style("Assign roles to your network interfaces.").dim()
    );
    println!(
        "{}",
        style("WAN = Internet connection, LAN = Local network").dim()
    );
    println!();

    // Get available interfaces
    // During initial setup `/dashboard` is blocked until setup is complete.
    // Use `/state` instead to list interfaces without traffic counters.
    let state: SystemState = client.get("/state", Some(token)).await?;
    let interfaces = state.interfaces;

    if interfaces.is_empty() {
        anyhow::bail!("No network interfaces found!");
    }

    // Display interfaces
    println!("Available interfaces:");
    for iface in &interfaces {
        let addr = iface.address.as_deref().unwrap_or("No IP");
        println!("  • {} ({})", style(&iface.name).cyan(), addr);
    }
    println!();

    // Select WAN interface(s)
    let interface_names: Vec<&str> = interfaces.iter().map(|i| i.name.as_str()).collect();

    let wan_selection = Select::new(
        "Select WAN interface (Internet connection):",
        interface_names.clone(),
    )
    .with_help_message("Use arrow keys to navigate, Enter to select")
    .prompt()?;

    println!();

    // WAN IP configuration
    let wan_use_dhcp = Confirm::new("Use DHCP for WAN interface?")
        .with_default(true)
        .with_help_message("Most home connections use DHCP")
        .prompt()?;

    let wan_static_ip = if !wan_use_dhcp {
        let ip = Text::new("Enter static IP (CIDR format, e.g., 192.168.1.2/24):").prompt()?;
        Some(ip)
    } else {
        None
    };

    println!();

    // Select LAN interface(s)
    let remaining: Vec<&str> = interface_names
        .iter()
        .filter(|&&n| n != wan_selection)
        .copied()
        .collect();

    if remaining.is_empty() {
        anyhow::bail!("Need at least 2 interfaces (one for WAN, one for LAN)");
    }

    let lan_selections = if remaining.len() == 1 {
        // Only one option, auto-select it
        println!(
            "Using {} as LAN interface (only remaining option)",
            style(remaining[0]).cyan()
        );
        remaining
    } else {
        MultiSelect::new("Select LAN interface(s) (local network):", remaining)
            .with_help_message("Space to select, Enter to confirm")
            .prompt()?
    };

    if lan_selections.is_empty() {
        anyhow::bail!("At least one LAN interface is required");
    }

    println!();

    // LAN IP configuration
    let default_lan_ip = "192.168.1.1/24".to_string();
    let lan_ip = Text::new("Enter LAN IP address (CIDR format):")
        .with_default(&default_lan_ip)
        .with_help_message("This will be the router's IP on the local network")
        .prompt()?;

    // Build assignments
    let mut assignments = vec![WizardInterfaceAssignment {
        name: wan_selection.to_string(),
        role: InterfaceRole::WAN,
        use_dhcp: wan_use_dhcp,
        static_ip: wan_static_ip,
    }];

    for lan_iface in lan_selections {
        assignments.push(WizardInterfaceAssignment {
            name: lan_iface.to_string(),
            role: InterfaceRole::LAN,
            use_dhcp: false,
            static_ip: Some(lan_ip.clone()),
        });
    }

    // Save assignments
    println!();
    println!("{}", style("Saving interface configuration...").dim());

    let request = WizardSaveInterfacesRequest { assignments };
    let response: WizardSaveInterfacesResponse = client
        .post("/wizard/interfaces", &request, Some(token))
        .await?;

    if !response.success {
        anyhow::bail!("Failed to save interfaces: {}", response.message);
    }

    println!("{} {}", style("✓").green(), response.message);

    Ok(())
}
