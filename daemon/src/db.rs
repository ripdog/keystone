//! Database module for Keystone configuration storage
//!
//! Uses SQLite via sqlx for persistent configuration storage.

use anyhow::{Context, Result};
use keystone_core::{
    ActivationPolicy, AddressScope, DhcpMode, Dhcpv4ClientConfig, Dhcpv6ClientConfig,
    InterfaceConfig, InterfaceRole, IpForwardMode, IpMasqueradeMode, LinkLocalMode,
    ManagedInterface, RouteType, StaticAddress, StaticRoute, User, UserInfo,
};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
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
        std::fs::create_dir_all(db_dir)
            .context("Failed to create database directory")?;

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

    /// Run database migrations
    async fn run_migrations(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run database migrations")?;

        info!("Database migrations complete");
        Ok(())
    }

    /// Get all managed interfaces
    pub async fn get_managed_interfaces(&self) -> Result<Vec<ManagedInterface>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, bool)>(
            "SELECT name, role, static_ip, enabled FROM managed_interfaces ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch managed interfaces")?;

        let interfaces = rows
            .into_iter()
            .filter_map(|(name, role, static_ip, enabled)| {
                let role: InterfaceRole = role.parse().ok()?;
                Some(ManagedInterface {
                    name,
                    role,
                    static_ip,
                    enabled,
                })
            })
            .collect();

        Ok(interfaces)
    }

    /// Save managed interfaces (replaces all existing)
    pub async fn save_managed_interfaces(&self, interfaces: &[ManagedInterface]) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Clear existing
        sqlx::query("DELETE FROM managed_interfaces")
            .execute(&mut *tx)
            .await
            .context("Failed to clear managed interfaces")?;

        // Insert new
        for iface in interfaces {
            sqlx::query(
                "INSERT INTO managed_interfaces (name, role, static_ip, enabled) VALUES (?, ?, ?, ?)",
            )
            .bind(&iface.name)
            .bind(iface.role.to_string())
            .bind(&iface.static_ip)
            .bind(iface.enabled)
            .execute(&mut *tx)
            .await
            .context("Failed to insert managed interface")?;
        }

        tx.commit().await.context("Failed to commit transaction")?;

        info!("Saved {} managed interfaces", interfaces.len());
        Ok(())
    }

    /// Get or create JWT signing key
    pub async fn get_or_create_jwt_key(&self) -> Result<Vec<u8>> {
        // Try to get existing key
        if let Some(row) = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT key_bytes FROM jwt_key WHERE id = 1"
        )
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch JWT key")? {
            info!("Loaded existing JWT key from database");
            return Ok(row.0);
        }

        // Generate new key
        use rand::random;
        let key_bytes: [u8; 32] = random();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO jwt_key (id, key_bytes, created_at) VALUES (1, ?, ?)"
        )
        .bind(&key_bytes[..])
        .bind(now)
        .execute(&self.pool)
        .await
        .context("Failed to create JWT key")?;

        info!("Generated new JWT key and stored in database");
        Ok(key_bytes.to_vec())
    }

    /// Get all users (without password hashes)
    pub async fn get_users(&self) -> Result<Vec<UserInfo>> {
        let rows = sqlx::query_as::<_, (i64, String, Option<String>, i64)>(
            "SELECT id, username, email, created_at FROM users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch users")?;

        let users = rows
            .into_iter()
            .map(|(id, username, email, created_at)| UserInfo {
                id,
                username,
                email,
                created_at,
            })
            .collect();

        Ok(users)
    }

    /// Get a user by username (with password hash)
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let row = sqlx::query_as::<_, (i64, String, Option<String>, String, i64)>(
            "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch user")?;

        Ok(row.map(|(id, username, email, password_hash, created_at)| User {
            id,
            username,
            email,
            password_hash,
            created_at,
        }))
    }

    /// Create a new user
    pub async fn create_user(&self, username: &str, email: Option<&str>, password_hash: &str) -> Result<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = sqlx::query(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("Failed to create user")?;

        Ok(result.last_insert_rowid())
    }

    /// Update user information
    pub async fn update_user(&self, id: i64, username: &str, email: Option<&str>, password_hash: Option<&str>) -> Result<()> {
        if let Some(hash) = password_hash {
            sqlx::query(
                "UPDATE users SET username = ?, email = ?, password_hash = ? WHERE id = ?",
            )
            .bind(username)
            .bind(email)
            .bind(hash)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update user")?;
        } else {
            sqlx::query(
                "UPDATE users SET username = ?, email = ? WHERE id = ?",
            )
            .bind(username)
            .bind(email)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update user")?;
        }

        info!("Updated user {} (id: {})", username, id);
        Ok(())
    }

    /// Delete a user
    pub async fn delete_user(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete user")?;

        info!("Deleted user id: {}", id);
        Ok(())
    }

    // ========================================================================
    // Interface Configuration Methods
    // ========================================================================

    /// Get all interface configurations
    pub async fn get_interface_configs(&self) -> Result<Vec<InterfaceConfig>> {
        let rows = sqlx::query_as::<_, (i64, String, String, bool, Option<String>, String, Option<String>, bool, String, String)>(
            r#"SELECT id, interface_name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade
               FROM interface_config ORDER BY interface_name"#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch interface configs")?;

        let mut configs = Vec::new();
        for (id, name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade) in rows {
            let addresses = self.get_interface_addresses(id).await?;
            let routes = self.get_interface_routes(id).await?;
            let dns_servers = self.get_interface_dns(id).await?;
            let search_domains = self.get_interface_domains(id).await?;
            let dhcpv4_client = self.get_dhcpv4_client_config(id).await?;
            let dhcpv6_client = self.get_dhcpv6_client_config(id).await?;

            configs.push(InterfaceConfig {
                id: Some(id),
                name,
                role: role.parse().unwrap_or(InterfaceRole::LAN),
                enabled,
                description,
                dhcp_mode: dhcp_mode.parse().unwrap_or(DhcpMode::No),
                addresses,
                routes,
                dns_servers,
                search_domains,
                gateway,
                link_local: LinkLocalMode::default(),
                required_for_online: true,
                activation_policy: ActivationPolicy::default(),
                dhcpv4_client,
                dhcpv6_client,
                dhcp_server: None, // TODO: Load from database
                ipv6_accept_ra,
                ip_forward: ip_forward.parse().unwrap_or(IpForwardMode::No),
                ip_masquerade: ip_masquerade.parse().unwrap_or(IpMasqueradeMode::No),
            });
        }

        Ok(configs)
    }

    /// Get a single interface configuration by name
    pub async fn get_interface_config(&self, name: &str) -> Result<Option<InterfaceConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, bool, Option<String>, String, Option<String>, bool, String, String)>(
            r#"SELECT id, interface_name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade
               FROM interface_config WHERE interface_name = ?"#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch interface config")?;

        match row {
            Some((id, name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade)) => {
                let addresses = self.get_interface_addresses(id).await?;
                let routes = self.get_interface_routes(id).await?;
                let dns_servers = self.get_interface_dns(id).await?;
                let search_domains = self.get_interface_domains(id).await?;
                let dhcpv4_client = self.get_dhcpv4_client_config(id).await?;
                let dhcpv6_client = self.get_dhcpv6_client_config(id).await?;

                Ok(Some(InterfaceConfig {
                    id: Some(id),
                    name,
                    role: role.parse().unwrap_or(InterfaceRole::LAN),
                    enabled,
                    description,
                    dhcp_mode: dhcp_mode.parse().unwrap_or(DhcpMode::No),
                    addresses,
                    routes,
                    dns_servers,
                    search_domains,
                    gateway,
                    link_local: LinkLocalMode::default(),
                    required_for_online: true,
                    activation_policy: ActivationPolicy::default(),
                    dhcpv4_client,
                    dhcpv6_client,
                    dhcp_server: None, // TODO: Load from database
                    ipv6_accept_ra,
                    ip_forward: ip_forward.parse().unwrap_or(IpForwardMode::No),
                    ip_masquerade: ip_masquerade.parse().unwrap_or(IpMasqueradeMode::No),
                }))
            }
            None => Ok(None),
        }
    }

    /// Save an interface configuration (insert or update)
    pub async fn save_interface_config(&self, config: &InterfaceConfig) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let config_id: i64 = if let Some(id) = config.id {
            // Update existing
            sqlx::query(
                r#"UPDATE interface_config SET
                   role = ?, enabled = ?, description = ?, dhcp_mode = ?, gateway = ?,
                   ipv6_accept_ra = ?, ip_forward = ?, ip_masquerade = ?, updated_at = ?
                   WHERE id = ?"#,
            )
            .bind(config.role.to_string())
            .bind(config.enabled)
            .bind(&config.description)
            .bind(config.dhcp_mode.to_string())
            .bind(&config.gateway)
            .bind(config.ipv6_accept_ra)
            .bind(config.ip_forward.to_string())
            .bind(config.ip_masquerade.to_string())
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to update interface config")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO interface_config 
                   (interface_name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            )
            .bind(&config.name)
            .bind(config.role.to_string())
            .bind(config.enabled)
            .bind(&config.description)
            .bind(config.dhcp_mode.to_string())
            .bind(&config.gateway)
            .bind(config.ipv6_accept_ra)
            .bind(config.ip_forward.to_string())
            .bind(config.ip_masquerade.to_string())
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("Failed to insert interface config")?;
            result.last_insert_rowid()
        };

        // Clear and re-insert addresses
        sqlx::query("DELETE FROM interface_addresses WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut *tx)
            .await?;
        for addr in &config.addresses {
            sqlx::query("INSERT INTO interface_addresses (interface_config_id, address, label) VALUES (?, ?, ?)")
                .bind(config_id)
                .bind(&addr.address)
                .bind(&addr.label)
                .execute(&mut *tx)
                .await?;
        }

        // Clear and re-insert routes
        sqlx::query("DELETE FROM interface_routes WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut *tx)
            .await?;
        for route in &config.routes {
            sqlx::query("INSERT INTO interface_routes (interface_config_id, destination, gateway, metric) VALUES (?, ?, ?, ?)")
                .bind(config_id)
                .bind(&route.destination)
                .bind(&route.gateway)
                .bind(route.metric.map(|m| m as i64))
                .execute(&mut *tx)
                .await?;
        }

        // Clear and re-insert DNS servers
        sqlx::query("DELETE FROM interface_dns WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut *tx)
            .await?;
        for (priority, dns) in config.dns_servers.iter().enumerate() {
            sqlx::query("INSERT INTO interface_dns (interface_config_id, server, priority) VALUES (?, ?, ?)")
                .bind(config_id)
                .bind(dns)
                .bind(priority as i64)
                .execute(&mut *tx)
                .await?;
        }

        // Clear and re-insert search domains
        sqlx::query("DELETE FROM interface_domains WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut *tx)
            .await?;
        for domain in &config.search_domains {
            sqlx::query("INSERT INTO interface_domains (interface_config_id, domain, is_routing_domain) VALUES (?, ?, 0)")
                .bind(config_id)
                .bind(domain)
                .execute(&mut *tx)
                .await?;
        }

        // Save DHCPv4 client config
        sqlx::query("DELETE FROM dhcpv4_client_config WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut *tx)
            .await?;
        if let Some(dhcp_config) = &config.dhcpv4_client {
            sqlx::query(
                r#"INSERT INTO dhcpv4_client_config 
                   (interface_config_id, send_hostname, hostname, use_dns, use_ntp, use_routes, use_gateway, use_mtu, use_domains, route_metric)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
            )
            .bind(config_id)
            .bind(dhcp_config.send_hostname)
            .bind(&dhcp_config.hostname)
            .bind(dhcp_config.use_dns)
            .bind(dhcp_config.use_ntp)
            .bind(dhcp_config.use_routes)
            .bind(dhcp_config.use_gateway)
            .bind(dhcp_config.use_mtu)
            .bind(&dhcp_config.use_domains)
            .bind(dhcp_config.route_metric.map(|m| m as i64))
            .execute(&mut *tx)
            .await?;
        }

        // Save DHCPv6 client config
        sqlx::query("DELETE FROM dhcpv6_client_config WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut *tx)
            .await?;
        if let Some(dhcp_config) = &config.dhcpv6_client {
            sqlx::query(
                r#"INSERT INTO dhcpv6_client_config 
                   (interface_config_id, use_dns, use_ntp, use_domains, prefix_delegation_hint, rapid_commit, without_ra)
                   VALUES (?, ?, ?, ?, ?, ?, ?)"#
            )
            .bind(config_id)
            .bind(dhcp_config.use_dns)
            .bind(dhcp_config.use_ntp)
            .bind(&dhcp_config.use_domains)
            .bind(&dhcp_config.prefix_delegation_hint)
            .bind(dhcp_config.rapid_commit)
            .bind(&dhcp_config.without_ra)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await.context("Failed to commit transaction")?;
        info!("Saved interface config for {}", config.name);
        Ok(config_id)
    }

    /// Delete an interface configuration
    pub async fn delete_interface_config(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM interface_config WHERE interface_name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .context("Failed to delete interface config")?;

        info!("Deleted interface config: {}", name);
        Ok(())
    }

    // Helper methods for fetching related data

    async fn get_interface_addresses(&self, config_id: i64) -> Result<Vec<StaticAddress>> {
        let rows = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT address, label FROM interface_addresses WHERE interface_config_id = ? ORDER BY id",
        )
        .bind(config_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch interface addresses")?;

        Ok(rows
            .into_iter()
            .map(|(address, label)| StaticAddress {
                address,
                label,
                scope: AddressScope::default(),
            })
            .collect())
    }

    async fn get_interface_routes(&self, config_id: i64) -> Result<Vec<StaticRoute>> {
        let rows = sqlx::query_as::<_, (Option<String>, String, Option<i64>)>(
            "SELECT destination, gateway, metric FROM interface_routes WHERE interface_config_id = ? ORDER BY id",
        )
        .bind(config_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch interface routes")?;

        Ok(rows
            .into_iter()
            .map(|(destination, gateway, metric)| StaticRoute {
                destination,
                gateway,
                metric: metric.map(|m| m as u32),
                table: None,
                route_type: RouteType::default(),
            })
            .collect())
    }

    async fn get_interface_dns(&self, config_id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT server FROM interface_dns WHERE interface_config_id = ? ORDER BY priority",
        )
        .bind(config_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch interface DNS servers")?;

        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    async fn get_interface_domains(&self, config_id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT domain FROM interface_domains WHERE interface_config_id = ? ORDER BY id",
        )
        .bind(config_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch interface domains")?;

        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    async fn get_dhcpv4_client_config(&self, config_id: i64) -> Result<Option<Dhcpv4ClientConfig>> {
        let row = sqlx::query_as::<_, (bool, Option<String>, bool, bool, bool, bool, bool, String, Option<i64>)>(
            r#"SELECT send_hostname, hostname, use_dns, use_ntp, use_routes, use_gateway, use_mtu, use_domains, route_metric
               FROM dhcpv4_client_config WHERE interface_config_id = ?"#
        )
        .bind(config_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch DHCPv4 client config")?;

        Ok(row.map(|(send_hostname, hostname, use_dns, use_ntp, use_routes, use_gateway, use_mtu, use_domains, route_metric)| {
            Dhcpv4ClientConfig {
                send_hostname,
                hostname,
                use_dns,
                use_ntp,
                use_routes,
                use_gateway,
                use_mtu,
                use_domains,
                route_metric: route_metric.map(|m| m as u32),
            }
        }))
    }

    async fn get_dhcpv6_client_config(&self, config_id: i64) -> Result<Option<Dhcpv6ClientConfig>> {
        let row = sqlx::query_as::<_, (bool, bool, String, Option<String>, bool, String)>(
            r#"SELECT use_dns, use_ntp, use_domains, prefix_delegation_hint, rapid_commit, without_ra
               FROM dhcpv6_client_config WHERE interface_config_id = ?"#
        )
        .bind(config_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch DHCPv6 client config")?;

        Ok(row.map(|(use_dns, use_ntp, use_domains, prefix_delegation_hint, rapid_commit, without_ra)| {
            Dhcpv6ClientConfig {
                use_dns,
                use_ntp,
                use_domains,
                prefix_delegation_hint,
                rapid_commit,
                without_ra,
            }
        }))
    }
}
