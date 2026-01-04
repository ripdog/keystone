//! Database module for Keystone configuration storage
//!
//! Uses SQLite via sqlx for persistent configuration storage.
//!
//! This module is organized into submodules for different entity types:
//! - `users` - User accounts and JWT key management
//! - `interfaces` - Network interface configurations
//! - `vlans` - VLAN configurations
//! - `bridges` - Bridge configurations
//! - `firewall` - Firewall zones, rules, and settings
//! - `settings` - Global application settings

pub mod bridges;
pub mod firewall;
pub mod interfaces;
pub mod settings;
pub mod users;
pub mod vlans;

use anyhow::{Context, Result};
use keystone_core::{
    BridgeConfig, FirewallConfig, FirewallGlobalSettings, FirewallZone, ForwardRule,
    GlobalSettings, InputRule, InterfaceConfig, ManagedInterface, PortForward, User, UserInfo,
    VlanConfig, ZoneForwardPolicy,
};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tracing::info;

const DB_PATH: &str = "/var/lib/keystone/keystone.db";

/// Database connection pool wrapper
#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Initialize the database, creating tables if needed
    pub async fn new() -> Result<Self> {
        // Ensure directory exists
        let db_dir = std::path::Path::new(DB_PATH).parent().unwrap();
        std::fs::create_dir_all(db_dir).context("Failed to create database directory")?;

        let db_url = format!("sqlite:{}?mode=rwc", DB_PATH);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .context("Failed to connect to database")?;

        info!("Connected to database at {}", DB_PATH);

        let db = Self { pool };
        db.run_migrations().await?;

        Ok(db)
    }

    /// Get a reference to the database pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run database migrations
    async fn run_migrations(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run database migrations")?;

        info!("Database migrations complete");
        Ok(())
    }

    // ========================================================================
    // User Operations (delegated to users module)
    // ========================================================================

    fn users(&self) -> users::UsersDb<'_> {
        users::UsersDb::new(&self.pool)
    }

    /// Get all users (without password hashes)
    pub async fn get_users(&self) -> Result<Vec<UserInfo>> {
        self.users().get_users().await
    }

    /// Get a user by username (with password hash)
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.users().get_user_by_username(username).await
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
    ) -> Result<i64> {
        self.users()
            .create_user(username, email, password_hash)
            .await
    }

    /// Update user information
    pub async fn update_user(
        &self,
        id: i64,
        username: &str,
        email: Option<&str>,
        password_hash: Option<&str>,
    ) -> Result<()> {
        self.users()
            .update_user(id, username, email, password_hash)
            .await
    }

    /// Delete a user
    pub async fn delete_user(&self, id: i64) -> Result<()> {
        self.users().delete_user(id).await
    }

    /// Get or create JWT signing key
    pub async fn get_or_create_jwt_key(&self) -> Result<Vec<u8>> {
        self.users().get_or_create_jwt_key().await
    }

    // ========================================================================
    // Interface Operations (delegated to interfaces module)
    // ========================================================================

    fn interfaces(&self) -> interfaces::InterfacesDb<'_> {
        interfaces::InterfacesDb::new(&self.pool)
    }

    /// Get all managed interfaces
    pub async fn get_managed_interfaces(&self) -> Result<Vec<ManagedInterface>> {
        self.interfaces().get_managed_interfaces().await
    }

    /// Save managed interfaces (replaces all existing)
    pub async fn save_managed_interfaces(&self, interfaces: &[ManagedInterface]) -> Result<()> {
        self.interfaces().save_managed_interfaces(interfaces).await
    }

    /// Get all interface configurations
    pub async fn get_interface_configs(&self) -> Result<Vec<InterfaceConfig>> {
        self.interfaces().get_interface_configs().await
    }

    /// Get a single interface configuration by name
    pub async fn get_interface_config(&self, name: &str) -> Result<Option<InterfaceConfig>> {
        self.interfaces().get_interface_config(name).await
    }

    /// Save an interface configuration (insert or update)
    pub async fn save_interface_config(&self, config: &InterfaceConfig) -> Result<i64> {
        self.interfaces().save_interface_config(config).await
    }

    /// Delete an interface configuration
    pub async fn delete_interface_config(&self, name: &str) -> Result<()> {
        self.interfaces().delete_interface_config(name).await
    }

    // ========================================================================
    // VLAN Operations (delegated to vlans module)
    // ========================================================================

    fn vlans(&self) -> vlans::VlansDb<'_> {
        vlans::VlansDb::new(&self.pool)
    }

    /// Get all VLAN configurations
    pub async fn get_all_vlans(&self) -> Result<Vec<VlanConfig>> {
        self.vlans().get_all_vlans().await
    }

    /// Get a single VLAN by ID
    pub async fn get_vlan(&self, id: i64) -> Result<Option<VlanConfig>> {
        self.vlans().get_vlan(id).await
    }

    /// Save (insert or update) a VLAN configuration
    pub async fn save_vlan(&self, config: &VlanConfig) -> Result<i64> {
        self.vlans().save_vlan(config).await
    }

    /// Delete a VLAN by ID
    pub async fn delete_vlan(&self, id: i64) -> Result<bool> {
        self.vlans().delete_vlan(id).await
    }

    // ========================================================================
    // Bridge Operations (delegated to bridges module)
    // ========================================================================

    fn bridges(&self) -> bridges::BridgesDb<'_> {
        bridges::BridgesDb::new(&self.pool)
    }

    /// Get all bridge configurations
    pub async fn get_all_bridges(&self) -> Result<Vec<BridgeConfig>> {
        self.bridges().get_all_bridges().await
    }

    /// Get a single bridge by ID
    pub async fn get_bridge(&self, id: i64) -> Result<Option<BridgeConfig>> {
        self.bridges().get_bridge(id).await
    }

    /// Save (insert or update) a bridge configuration
    pub async fn save_bridge(&self, config: &BridgeConfig) -> Result<i64> {
        self.bridges().save_bridge(config).await
    }

    /// Delete a bridge configuration
    pub async fn delete_bridge(&self, id: i64) -> Result<bool> {
        self.bridges().delete_bridge(id).await
    }

    // ========================================================================
    // Firewall Operations (delegated to firewall module)
    // ========================================================================

    fn firewall(&self) -> firewall::FirewallDb<'_> {
        firewall::FirewallDb::new(&self.pool)
    }

    /// Get all firewall zones
    pub async fn get_firewall_zones(&self) -> Result<Vec<FirewallZone>> {
        self.firewall().get_firewall_zones().await
    }

    /// Get a single firewall zone by ID
    pub async fn get_firewall_zone(&self, id: i64) -> Result<Option<FirewallZone>> {
        self.firewall().get_firewall_zone(id).await
    }

    /// Save (insert or update) a firewall zone
    pub async fn save_firewall_zone(&self, zone: &FirewallZone) -> Result<i64> {
        self.firewall().save_firewall_zone(zone).await
    }

    /// Delete a firewall zone by ID
    pub async fn delete_firewall_zone(&self, id: i64) -> Result<bool> {
        self.firewall().delete_firewall_zone(id).await
    }

    /// Get all zone forward policies
    pub async fn get_zone_forwards(&self) -> Result<Vec<ZoneForwardPolicy>> {
        self.firewall().get_zone_forwards().await
    }

    /// Save (insert or update) a zone forward policy
    pub async fn save_zone_forward(&self, forward: &ZoneForwardPolicy) -> Result<i64> {
        self.firewall().save_zone_forward(forward).await
    }

    /// Delete a zone forward policy by ID
    pub async fn delete_zone_forward(&self, id: i64) -> Result<bool> {
        self.firewall().delete_zone_forward(id).await
    }

    /// Get all port forwards
    pub async fn get_port_forwards(&self) -> Result<Vec<PortForward>> {
        self.firewall().get_port_forwards().await
    }

    /// Save (insert or update) a port forward
    pub async fn save_port_forward(&self, pf: &PortForward) -> Result<i64> {
        self.firewall().save_port_forward(pf).await
    }

    /// Delete a port forward by ID
    pub async fn delete_port_forward(&self, id: i64) -> Result<bool> {
        self.firewall().delete_port_forward(id).await
    }

    /// Get all input rules
    pub async fn get_input_rules(&self) -> Result<Vec<InputRule>> {
        self.firewall().get_input_rules().await
    }

    /// Get a single input rule by ID
    pub async fn get_input_rule(&self, id: i64) -> Result<Option<InputRule>> {
        self.firewall().get_input_rule(id).await
    }

    /// Save (insert or update) an input rule
    pub async fn save_input_rule(&self, rule: &InputRule) -> Result<i64> {
        self.firewall().save_input_rule(rule).await
    }

    /// Delete an input rule by ID
    pub async fn delete_input_rule(&self, id: i64) -> Result<bool> {
        self.firewall().delete_input_rule(id).await
    }

    /// Get all forward rules
    pub async fn get_forward_rules(&self) -> Result<Vec<ForwardRule>> {
        self.firewall().get_forward_rules().await
    }

    /// Get a single forward rule by ID
    pub async fn get_forward_rule(&self, id: i64) -> Result<Option<ForwardRule>> {
        self.firewall().get_forward_rule(id).await
    }

    /// Save (insert or update) a forward rule
    pub async fn save_forward_rule(&self, rule: &ForwardRule) -> Result<i64> {
        self.firewall().save_forward_rule(rule).await
    }

    /// Delete a forward rule by ID
    pub async fn delete_forward_rule(&self, id: i64) -> Result<bool> {
        self.firewall().delete_forward_rule(id).await
    }

    /// Get complete firewall configuration
    pub async fn get_firewall_config(&self) -> Result<FirewallConfig> {
        self.firewall().get_firewall_config().await
    }

    /// Get global firewall settings
    pub async fn get_firewall_global_settings(&self) -> Result<FirewallGlobalSettings> {
        self.firewall().get_firewall_global_settings().await
    }

    /// Save global firewall settings
    pub async fn save_firewall_global_settings(
        &self,
        settings: &FirewallGlobalSettings,
    ) -> Result<()> {
        self.firewall()
            .save_firewall_global_settings(settings)
            .await
    }

    /// Save rollback state for safe apply
    pub async fn save_rollback_state(
        &self,
        config: &FirewallConfig,
        rollback_at: i64,
    ) -> Result<()> {
        self.firewall()
            .save_rollback_state(config, rollback_at)
            .await
    }

    /// Get pending rollback state
    pub async fn get_rollback_state(&self) -> Result<Option<(FirewallConfig, i64)>> {
        self.firewall().get_rollback_state().await
    }

    /// Clear rollback state (called on confirm)
    pub async fn clear_rollback_state(&self) -> Result<()> {
        self.firewall().clear_rollback_state().await
    }

    // ========================================================================
    // Global Settings Operations (delegated to settings module)
    // ========================================================================

    fn settings(&self) -> settings::SettingsDb<'_> {
        settings::SettingsDb::new(&self.pool)
    }

    /// Get global application settings
    pub async fn get_global_settings(&self) -> Result<GlobalSettings> {
        self.settings().get_global_settings().await
    }

    /// Save global application settings
    pub async fn save_global_settings(&self, settings: &GlobalSettings) -> Result<()> {
        self.settings().save_global_settings(settings).await
    }

    /// Mark setup as complete
    pub async fn mark_setup_complete(&self) -> Result<()> {
        self.settings().mark_setup_complete().await
    }
}
