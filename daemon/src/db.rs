//! Database module for Keystone configuration storage
//!
//! Uses SQLite via sqlx for persistent configuration storage.

use anyhow::{Context, Result};
use keystone_core::{
    ActivationPolicy, AddressScope, BridgeConfig, DhcpMode, DhcpServerConfig, DhcpStaticLease,
    Dhcpv4ClientConfig, Dhcpv6ClientConfig, InterfaceConfig, InterfaceRole, IpForwardMode,
    IpMasqueradeMode, Ipv6AcceptRaConfig, Ipv6RaConfig, Ipv6RaPrefix, LinkLocalMode,
    ManagedInterface, RouteType, StaticAddress, StaticRoute, User, UserInfo, VlanConfig,
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
        let rows = sqlx::query_as::<_, (i64, String, String, bool, Option<String>, String, Option<String>, bool, String, String, String, bool, String, Option<i64>)>(
            r#"SELECT id, interface_name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade, link_local, required_for_online, activation_policy, mtu
               FROM interface_config ORDER BY interface_name"#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch interface configs")?;

        let mut configs = Vec::new();
        for (id, name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade, link_local, required_for_online, activation_policy, mtu) in rows {
            let addresses = self.get_interface_addresses(id).await?;
            let routes = self.get_interface_routes(id).await?;
            let dns_servers = self.get_interface_dns(id).await?;
            let search_domains = self.get_interface_domains(id).await?;
            let dhcpv4_client = self.get_dhcpv4_client_config(id).await?;
            let dhcpv6_client = self.get_dhcpv6_client_config(id).await?;
            let dhcp_server = self.get_dhcp_server_config(id).await?;
            let ipv6_ra = self.get_ipv6_ra_config(id).await?;
            let ipv6_accept_ra_config = self.get_ipv6_accept_ra_config(id).await?;
            let vlans = self.get_vlan_names_for_interface(&name).await?;

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
                link_local: link_local.parse().unwrap_or(LinkLocalMode::default()),
                required_for_online,
                activation_policy: activation_policy.parse().unwrap_or(ActivationPolicy::default()),
                dhcpv4_client,
                dhcpv6_client,
                dhcp_server,
                ipv6_accept_ra,
                ipv6_accept_ra_config,
                ipv6_ra,
                ip_forward: ip_forward.parse().unwrap_or(IpForwardMode::No),
                ip_masquerade: ip_masquerade.parse().unwrap_or(IpMasqueradeMode::No),
                mtu: mtu.map(|v| v as u32),
                vlans,
            });
        }

        Ok(configs)
    }

    /// Get a single interface configuration by name
    pub async fn get_interface_config(&self, name: &str) -> Result<Option<InterfaceConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, bool, Option<String>, String, Option<String>, bool, String, String, String, bool, String, Option<i64>)>(
            r#"SELECT id, interface_name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade, link_local, required_for_online, activation_policy, mtu
               FROM interface_config WHERE interface_name = ?"#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch interface config")?;

        match row {
            Some((id, name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade, link_local, required_for_online, activation_policy, mtu)) => {
                let addresses = self.get_interface_addresses(id).await?;
                let routes = self.get_interface_routes(id).await?;
                let dns_servers = self.get_interface_dns(id).await?;
                let search_domains = self.get_interface_domains(id).await?;
                let dhcpv4_client = self.get_dhcpv4_client_config(id).await?;
                let dhcpv6_client = self.get_dhcpv6_client_config(id).await?;
                let dhcp_server = self.get_dhcp_server_config(id).await?;
                let ipv6_ra = self.get_ipv6_ra_config(id).await?;
                let ipv6_accept_ra_config = self.get_ipv6_accept_ra_config(id).await?;
                let vlans = self.get_vlan_names_for_interface(&name).await?;

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
                    link_local: link_local.parse().unwrap_or(LinkLocalMode::default()),
                    required_for_online,
                    activation_policy: activation_policy.parse().unwrap_or(ActivationPolicy::default()),
                    dhcpv4_client,
                    dhcpv6_client,
                    dhcp_server,
                    ipv6_accept_ra,
                    ipv6_accept_ra_config,
                    ipv6_ra,
                    ip_forward: ip_forward.parse().unwrap_or(IpForwardMode::No),
                    ip_masquerade: ip_masquerade.parse().unwrap_or(IpMasqueradeMode::No),
                    mtu: mtu.map(|v| v as u32),
                    vlans,
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
                   ipv6_accept_ra = ?, ip_forward = ?, ip_masquerade = ?,
                   link_local = ?, required_for_online = ?, activation_policy = ?, mtu = ?, updated_at = ?
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
            .bind(config.link_local.to_string())
            .bind(config.required_for_online)
            .bind(config.activation_policy.to_string())
            .bind(config.mtu.map(|v| v as i64))
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
                   (interface_name, role, enabled, description, dhcp_mode, gateway, ipv6_accept_ra, ip_forward, ip_masquerade, link_local, required_for_online, activation_policy, mtu, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
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
            .bind(config.link_local.to_string())
            .bind(config.required_for_online)
            .bind(config.activation_policy.to_string())
            .bind(config.mtu.map(|v| v as i64))
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

        // Save DHCP server config
        self.save_dhcp_server_config_tx(&mut tx, config_id, &config.dhcp_server).await?;

        // Save IPv6 RA config
        self.save_ipv6_ra_config_tx(&mut tx, config_id, &config.ipv6_ra).await?;

        // Save IPv6 Accept RA config
        self.save_ipv6_accept_ra_config_tx(&mut tx, config_id, &config.ipv6_accept_ra_config).await?;

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

    async fn get_dhcp_server_config(&self, config_id: i64) -> Result<Option<DhcpServerConfig>> {
        let row = sqlx::query_as::<_, (bool, Option<i64>, Option<i64>, Option<i64>, Option<i64>, bool, bool, bool, Option<String>)>(
            r#"SELECT enabled, pool_offset, pool_size, default_lease_time_secs, max_lease_time_secs, emit_dns, emit_ntp, emit_router, router_address
               FROM dhcp_server_config WHERE interface_config_id = ?"#
        )
        .bind(config_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch DHCP server config")?;

        match row {
            Some((enabled, pool_offset, pool_size, default_lease_time_secs, max_lease_time_secs, emit_dns, emit_ntp, emit_router, router_address)) => {
                // Get DNS servers for DHCP server
                let dns_servers = sqlx::query_as::<_, (String,)>(
                    "SELECT server FROM dhcp_server_dns WHERE dhcp_server_id = ? ORDER BY priority"
                )
                .bind(config_id)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch DHCP server DNS")?
                .into_iter()
                .map(|(s,)| s)
                .collect();

                // Get NTP servers for DHCP server
                let ntp_servers = sqlx::query_as::<_, (String,)>(
                    "SELECT server FROM dhcp_server_ntp WHERE dhcp_server_id = ? ORDER BY priority"
                )
                .bind(config_id)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch DHCP server NTP")?
                .into_iter()
                .map(|(s,)| s)
                .collect();

                // Get static leases
                let static_leases = sqlx::query_as::<_, (String, String, Option<String>)>(
                    "SELECT mac_address, ip_address, hostname FROM dhcp_static_leases WHERE dhcp_server_id = ? ORDER BY id"
                )
                .bind(config_id)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch DHCP static leases")?
                .into_iter()
                .map(|(mac_address, ip_address, hostname)| DhcpStaticLease {
                    mac_address,
                    ip_address,
                    hostname,
                })
                .collect();

                Ok(Some(DhcpServerConfig {
                    enabled,
                    pool_offset: pool_offset.map(|v| v as u32),
                    pool_size: pool_size.map(|v| v as u32),
                    default_lease_time_secs: default_lease_time_secs.map(|v| v as u32),
                    max_lease_time_secs: max_lease_time_secs.map(|v| v as u32),
                    emit_dns,
                    dns_servers,
                    emit_ntp,
                    ntp_servers,
                    emit_router,
                    router_address,
                    static_leases,
                }))
            }
            None => Ok(None),
        }
    }

    async fn save_dhcp_server_config_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        config_id: i64,
        dhcp_server: &Option<DhcpServerConfig>,
    ) -> Result<()> {
        // Clear existing DHCP server config and related tables
        sqlx::query("DELETE FROM dhcp_static_leases WHERE dhcp_server_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM dhcp_server_ntp WHERE dhcp_server_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM dhcp_server_dns WHERE dhcp_server_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM dhcp_server_config WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;

        if let Some(dhcp) = dhcp_server {
            // Insert main config
            sqlx::query(
                r#"INSERT INTO dhcp_server_config 
                   (interface_config_id, enabled, pool_offset, pool_size, default_lease_time_secs, max_lease_time_secs, emit_dns, emit_ntp, emit_router, router_address)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
            )
            .bind(config_id)
            .bind(dhcp.enabled)
            .bind(dhcp.pool_offset.map(|v| v as i64))
            .bind(dhcp.pool_size.map(|v| v as i64))
            .bind(dhcp.default_lease_time_secs.map(|v| v as i64))
            .bind(dhcp.max_lease_time_secs.map(|v| v as i64))
            .bind(dhcp.emit_dns)
            .bind(dhcp.emit_ntp)
            .bind(dhcp.emit_router)
            .bind(&dhcp.router_address)
            .execute(&mut **tx)
            .await?;

            // Insert DNS servers
            for (priority, dns) in dhcp.dns_servers.iter().enumerate() {
                sqlx::query("INSERT INTO dhcp_server_dns (dhcp_server_id, server, priority) VALUES (?, ?, ?)")
                    .bind(config_id)
                    .bind(dns)
                    .bind(priority as i64)
                    .execute(&mut **tx)
                    .await?;
            }

            // Insert NTP servers
            for (priority, ntp) in dhcp.ntp_servers.iter().enumerate() {
                sqlx::query("INSERT INTO dhcp_server_ntp (dhcp_server_id, server, priority) VALUES (?, ?, ?)")
                    .bind(config_id)
                    .bind(ntp)
                    .bind(priority as i64)
                    .execute(&mut **tx)
                    .await?;
            }

            // Insert static leases
            for lease in &dhcp.static_leases {
                sqlx::query("INSERT INTO dhcp_static_leases (dhcp_server_id, mac_address, ip_address, hostname) VALUES (?, ?, ?, ?)")
                    .bind(config_id)
                    .bind(&lease.mac_address)
                    .bind(&lease.ip_address)
                    .bind(&lease.hostname)
                    .execute(&mut **tx)
                    .await?;
            }
        }

        Ok(())
    }

    // ============================================================================
    // IPv6 Router Advertisement Configuration
    // ============================================================================

    async fn get_ipv6_ra_config(&self, config_id: i64) -> Result<Option<Ipv6RaConfig>> {
        let row = sqlx::query_as::<_, (bool, Option<i64>, Option<String>, bool, bool, bool)>(
            r#"SELECT enabled, router_lifetime_secs, router_preference, managed, other_information, emit_dns
               FROM ipv6_ra_config WHERE interface_config_id = ?"#
        )
        .bind(config_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((enabled, router_lifetime_secs, router_preference, managed, other_information, emit_dns)) => {
                // Get DNS servers for RA
                let dns_servers = sqlx::query_as::<_, (String,)>(
                    "SELECT server FROM ipv6_ra_dns WHERE ipv6_ra_config_id = ? ORDER BY priority"
                )
                .bind(config_id)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|(s,)| s)
                .collect();

                // Get search domains
                let search_domains = sqlx::query_as::<_, (String,)>(
                    "SELECT domain FROM ipv6_ra_search_domains WHERE ipv6_ra_config_id = ? ORDER BY priority"
                )
                .bind(config_id)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|(d,)| d)
                .collect();

                // Get prefixes
                let prefix_rows = sqlx::query_as::<_, (String, Option<i64>, Option<i64>, bool, bool)>(
                    "SELECT prefix, preferred_lifetime_secs, valid_lifetime_secs, on_link, autonomous FROM ipv6_ra_prefixes WHERE ipv6_ra_config_id = ? ORDER BY id"
                )
                .bind(config_id)
                .fetch_all(&self.pool)
                .await?;

                let prefixes = prefix_rows.into_iter().map(|(prefix, preferred, valid, on_link, autonomous)| {
                    Ipv6RaPrefix {
                        prefix,
                        preferred_lifetime_secs: preferred.map(|v| v as u32),
                        valid_lifetime_secs: valid.map(|v| v as u32),
                        on_link,
                        autonomous,
                    }
                }).collect();

                Ok(Some(Ipv6RaConfig {
                    enabled,
                    router_lifetime_secs: router_lifetime_secs.map(|v| v as u32),
                    router_preference,
                    managed,
                    other_information,
                    emit_dns,
                    dns_servers,
                    search_domains,
                    prefixes,
                }))
            }
            None => Ok(None),
        }
    }

    async fn save_ipv6_ra_config_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        config_id: i64,
        ipv6_ra: &Option<Ipv6RaConfig>,
    ) -> Result<()> {
        // Clear existing IPv6 RA config and related tables
        sqlx::query("DELETE FROM ipv6_ra_prefixes WHERE ipv6_ra_config_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM ipv6_ra_search_domains WHERE ipv6_ra_config_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM ipv6_ra_dns WHERE ipv6_ra_config_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM ipv6_ra_config WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;

        if let Some(ra) = ipv6_ra {
            // Insert main config
            sqlx::query(
                r#"INSERT INTO ipv6_ra_config 
                   (interface_config_id, enabled, router_lifetime_secs, router_preference, managed, other_information, emit_dns)
                   VALUES (?, ?, ?, ?, ?, ?, ?)"#
            )
            .bind(config_id)
            .bind(ra.enabled)
            .bind(ra.router_lifetime_secs.map(|v| v as i64))
            .bind(&ra.router_preference)
            .bind(ra.managed)
            .bind(ra.other_information)
            .bind(ra.emit_dns)
            .execute(&mut **tx)
            .await?;

            // Insert DNS servers
            for (priority, dns) in ra.dns_servers.iter().enumerate() {
                sqlx::query("INSERT INTO ipv6_ra_dns (ipv6_ra_config_id, server, priority) VALUES (?, ?, ?)")
                    .bind(config_id)
                    .bind(dns)
                    .bind(priority as i64)
                    .execute(&mut **tx)
                    .await?;
            }

            // Insert search domains
            for (priority, domain) in ra.search_domains.iter().enumerate() {
                sqlx::query("INSERT INTO ipv6_ra_search_domains (ipv6_ra_config_id, domain, priority) VALUES (?, ?, ?)")
                    .bind(config_id)
                    .bind(domain)
                    .bind(priority as i64)
                    .execute(&mut **tx)
                    .await?;
            }

            // Insert prefixes
            for prefix in &ra.prefixes {
                sqlx::query(
                    r#"INSERT INTO ipv6_ra_prefixes 
                       (ipv6_ra_config_id, prefix, preferred_lifetime_secs, valid_lifetime_secs, on_link, autonomous)
                       VALUES (?, ?, ?, ?, ?, ?)"#
                )
                .bind(config_id)
                .bind(&prefix.prefix)
                .bind(prefix.preferred_lifetime_secs.map(|v| v as i64))
                .bind(prefix.valid_lifetime_secs.map(|v| v as i64))
                .bind(prefix.on_link)
                .bind(prefix.autonomous)
                .execute(&mut **tx)
                .await?;
            }
        }

        Ok(())
    }

    // ============================================================================
    // IPv6 Accept RA Configuration
    // ============================================================================

    async fn get_ipv6_accept_ra_config(&self, config_id: i64) -> Result<Option<Ipv6AcceptRaConfig>> {
        let row = sqlx::query_as::<_, (bool, bool, bool, bool)>(
            r#"SELECT use_dns, use_gateway, use_route_prefix, use_autonomous_prefix
               FROM ipv6_accept_ra_config WHERE interface_config_id = ?"#
        )
        .bind(config_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((use_dns, use_gateway, use_route_prefix, use_autonomous_prefix)) => {
                Ok(Some(Ipv6AcceptRaConfig {
                    use_dns,
                    use_gateway,
                    use_route_prefix,
                    use_autonomous_prefix,
                }))
            }
            None => Ok(None),
        }
    }

    async fn save_ipv6_accept_ra_config_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        config_id: i64,
        ipv6_accept_ra_config: &Option<Ipv6AcceptRaConfig>,
    ) -> Result<()> {
        // Clear existing config
        sqlx::query("DELETE FROM ipv6_accept_ra_config WHERE interface_config_id = ?")
            .bind(config_id)
            .execute(&mut **tx)
            .await?;

        if let Some(cfg) = ipv6_accept_ra_config {
            sqlx::query(
                r#"INSERT INTO ipv6_accept_ra_config 
                   (interface_config_id, use_dns, use_gateway, use_route_prefix, use_autonomous_prefix)
                   VALUES (?, ?, ?, ?, ?)"#
            )
            .bind(config_id)
            .bind(cfg.use_dns)
            .bind(cfg.use_gateway)
            .bind(cfg.use_route_prefix)
            .bind(cfg.use_autonomous_prefix)
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }

    // ============================================================================
    // VLAN Configuration
    // ============================================================================

    /// Get all VLAN configurations
    pub async fn get_all_vlans(&self) -> Result<Vec<VlanConfig>> {
        let rows = sqlx::query_as::<_, (i64, String, String, i64, String, Option<String>, Option<i64>)>(
            r#"SELECT id, name, parent_interface, vlan_id, protocol, description, interface_config_id
               FROM vlan_config ORDER BY parent_interface, vlan_id"#
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch VLANs")?;

        let vlans = rows
            .into_iter()
            .map(|(id, name, parent_interface, vlan_id, protocol, description, interface_config_id)| {
                VlanConfig {
                    id: Some(id),
                    name,
                    parent_interface,
                    vlan_id: vlan_id as u16,
                    protocol: protocol.parse().unwrap_or_default(),
                    description,
                    interface_config_id,
                }
            })
            .collect();

        Ok(vlans)
    }

    /// Get VLANs for a specific parent interface
    pub async fn get_vlans_for_interface(&self, parent_interface: &str) -> Result<Vec<VlanConfig>> {
        let rows = sqlx::query_as::<_, (i64, String, String, i64, String, Option<String>, Option<i64>)>(
            r#"SELECT id, name, parent_interface, vlan_id, protocol, description, interface_config_id
               FROM vlan_config WHERE parent_interface = ? ORDER BY vlan_id"#
        )
        .bind(parent_interface)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch VLANs for interface")?;

        let vlans = rows
            .into_iter()
            .map(|(id, name, parent_interface, vlan_id, protocol, description, interface_config_id)| {
                VlanConfig {
                    id: Some(id),
                    name,
                    parent_interface,
                    vlan_id: vlan_id as u16,
                    protocol: protocol.parse().unwrap_or_default(),
                    description,
                    interface_config_id,
                }
            })
            .collect();

        Ok(vlans)
    }

    /// Get a single VLAN by ID
    pub async fn get_vlan(&self, id: i64) -> Result<Option<VlanConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, i64, String, Option<String>, Option<i64>)>(
            r#"SELECT id, name, parent_interface, vlan_id, protocol, description, interface_config_id
               FROM vlan_config WHERE id = ?"#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch VLAN")?;

        Ok(row.map(|(id, name, parent_interface, vlan_id, protocol, description, interface_config_id)| {
            VlanConfig {
                id: Some(id),
                name,
                parent_interface,
                vlan_id: vlan_id as u16,
                protocol: protocol.parse().unwrap_or_default(),
                description,
                interface_config_id,
            }
        }))
    }

    /// Get a VLAN by name
    pub async fn get_vlan_by_name(&self, name: &str) -> Result<Option<VlanConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, i64, String, Option<String>, Option<i64>)>(
            r#"SELECT id, name, parent_interface, vlan_id, protocol, description, interface_config_id
               FROM vlan_config WHERE name = ?"#
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch VLAN by name")?;

        Ok(row.map(|(id, name, parent_interface, vlan_id, protocol, description, interface_config_id)| {
            VlanConfig {
                id: Some(id),
                name,
                parent_interface,
                vlan_id: vlan_id as u16,
                protocol: protocol.parse().unwrap_or_default(),
                description,
                interface_config_id,
            }
        }))
    }

    /// Save (insert or update) a VLAN configuration
    pub async fn save_vlan(&self, config: &VlanConfig) -> Result<i64> {
        // Validate VLAN ID
        if config.vlan_id < 1 || config.vlan_id > 4094 {
            anyhow::bail!("VLAN ID must be between 1 and 4094");
        }

        if config.name.is_empty() {
            anyhow::bail!("VLAN name is required");
        }

        if config.parent_interface.is_empty() {
            anyhow::bail!("Parent interface is required");
        }

        let mut tx = self.pool.begin().await?;

        let id = if let Some(id) = config.id {
            // Update existing
            sqlx::query(
                r#"UPDATE vlan_config SET 
                   name = ?, parent_interface = ?, vlan_id = ?, protocol = ?, 
                   description = ?, interface_config_id = ?, updated_at = strftime('%s', 'now')
                   WHERE id = ?"#
            )
            .bind(&config.name)
            .bind(&config.parent_interface)
            .bind(config.vlan_id as i64)
            .bind(config.protocol.to_string())
            .bind(&config.description)
            .bind(config.interface_config_id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to update VLAN")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO vlan_config (name, parent_interface, vlan_id, protocol, description, interface_config_id)
                   VALUES (?, ?, ?, ?, ?, ?)"#
            )
            .bind(&config.name)
            .bind(&config.parent_interface)
            .bind(config.vlan_id as i64)
            .bind(config.protocol.to_string())
            .bind(&config.description)
            .bind(config.interface_config_id)
            .execute(&mut *tx)
            .await
            .context("Failed to insert VLAN")?;
            result.last_insert_rowid()
        };

        tx.commit().await?;
        Ok(id)
    }

    /// Delete a VLAN by ID
    pub async fn delete_vlan(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM vlan_config WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete VLAN")?;

        Ok(result.rows_affected() > 0)
    }

    /// Get VLAN names attached to an interface (for populating vlans field in InterfaceConfig)
    pub async fn get_vlan_names_for_interface(&self, parent_interface: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT name FROM vlan_config WHERE parent_interface = ? ORDER BY vlan_id"
        )
        .bind(parent_interface)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch VLAN names")?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    // ========================================================================
    // Bridge Configuration
    // ========================================================================

    /// Get all bridge configurations
    pub async fn get_all_bridges(&self) -> Result<Vec<BridgeConfig>> {
        let rows = sqlx::query_as::<_, (i64, String, String, i64, i64, Option<String>, Option<i64>)>(
            "SELECT id, name, members, stp, stp_forward_delay, description, interface_config_id 
             FROM bridge_config 
             ORDER BY name"
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch bridges")?;

        let bridges = rows
            .into_iter()
            .map(|(id, name, members_json, stp, stp_forward_delay, description, interface_config_id)| {
                let members: Vec<String> = serde_json::from_str(&members_json).unwrap_or_default();
                BridgeConfig {
                    id: Some(id),
                    name,
                    members,
                    stp: stp != 0,
                    stp_forward_delay: stp_forward_delay as u32,
                    description,
                    interface_config_id,
                }
            })
            .collect();

        Ok(bridges)
    }

    /// Get a single bridge by ID
    pub async fn get_bridge(&self, id: i64) -> Result<Option<BridgeConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, i64, i64, Option<String>, Option<i64>)>(
            "SELECT id, name, members, stp, stp_forward_delay, description, interface_config_id 
             FROM bridge_config 
             WHERE id = ?"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch bridge")?;

        Ok(row.map(|(id, name, members_json, stp, stp_forward_delay, description, interface_config_id)| {
            let members: Vec<String> = serde_json::from_str(&members_json).unwrap_or_default();
            BridgeConfig {
                id: Some(id),
                name,
                members,
                stp: stp != 0,
                stp_forward_delay: stp_forward_delay as u32,
                description,
                interface_config_id,
            }
        }))
    }

    /// Get a bridge by name
    pub async fn get_bridge_by_name(&self, name: &str) -> Result<Option<BridgeConfig>> {
        let row = sqlx::query_as::<_, (i64, String, String, i64, i64, Option<String>, Option<i64>)>(
            "SELECT id, name, members, stp, stp_forward_delay, description, interface_config_id 
             FROM bridge_config 
             WHERE name = ?"
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch bridge by name")?;

        Ok(row.map(|(id, name, members_json, stp, stp_forward_delay, description, interface_config_id)| {
            let members: Vec<String> = serde_json::from_str(&members_json).unwrap_or_default();
            BridgeConfig {
                id: Some(id),
                name,
                members,
                stp: stp != 0,
                stp_forward_delay: stp_forward_delay as u32,
                description,
                interface_config_id,
            }
        }))
    }

    /// Save (insert or update) a bridge configuration
    pub async fn save_bridge(&self, config: &BridgeConfig) -> Result<i64> {
        let members_json = serde_json::to_string(&config.members)
            .context("Failed to serialize bridge members")?;
        
        let stp_int = if config.stp { 1 } else { 0 };

        if let Some(id) = config.id {
            // Update existing bridge
            sqlx::query(
                "UPDATE bridge_config 
                 SET name = ?, members = ?, stp = ?, stp_forward_delay = ?, 
                     description = ?, interface_config_id = ?, 
                     updated_at = strftime('%s', 'now')
                 WHERE id = ?"
            )
            .bind(&config.name)
            .bind(&members_json)
            .bind(stp_int)
            .bind(config.stp_forward_delay as i64)
            .bind(&config.description)
            .bind(config.interface_config_id)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update bridge")?;

            Ok(id)
        } else {
            // Insert new bridge
            let result = sqlx::query(
                "INSERT INTO bridge_config 
                 (name, members, stp, stp_forward_delay, description, interface_config_id) 
                 VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind(&config.name)
            .bind(&members_json)
            .bind(stp_int)
            .bind(config.stp_forward_delay as i64)
            .bind(&config.description)
            .bind(config.interface_config_id)
            .execute(&self.pool)
            .await
            .context("Failed to insert bridge")?;

            Ok(result.last_insert_rowid())
        }
    }

    /// Delete a bridge configuration
    pub async fn delete_bridge(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM bridge_config WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete bridge")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Firewall Zone CRUD Operations
    // ========================================================================

    /// Get all firewall zones
    pub async fn get_firewall_zones(&self) -> Result<Vec<keystone_core::FirewallZone>> {
        use keystone_core::{FirewallPolicy, FirewallZone};

        // First get all zones
        let zone_rows = sqlx::query_as::<_, (i64, String, Option<String>, String, String)>(
            r#"SELECT id, name, description, default_input_policy, default_forward_policy
               FROM firewall_zones ORDER BY name"#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch firewall zones")?;

        let mut zones = Vec::with_capacity(zone_rows.len());
        for (id, name, description, input_policy, forward_policy) in zone_rows {
            // Get interfaces for this zone
            let interface_rows = sqlx::query_as::<_, (String,)>(
                "SELECT interface_name FROM firewall_zone_interfaces WHERE zone_id = ?",
            )
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .context("Failed to fetch zone interfaces")?;

            let interfaces: Vec<String> = interface_rows.into_iter().map(|(name,)| name).collect();

            zones.push(FirewallZone {
                id: Some(id),
                name,
                description,
                interfaces,
                default_input_policy: input_policy.parse().unwrap_or(FirewallPolicy::Drop),
                default_forward_policy: forward_policy.parse().unwrap_or(FirewallPolicy::Drop),
            });
        }

        Ok(zones)
    }

    /// Get a single firewall zone by ID
    pub async fn get_firewall_zone(&self, id: i64) -> Result<Option<keystone_core::FirewallZone>> {
        use keystone_core::{FirewallPolicy, FirewallZone};

        let row = sqlx::query_as::<_, (i64, String, Option<String>, String, String)>(
            r#"SELECT id, name, description, default_input_policy, default_forward_policy
               FROM firewall_zones WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch firewall zone")?;

        match row {
            Some((id, name, description, input_policy, forward_policy)) => {
                let interface_rows = sqlx::query_as::<_, (String,)>(
                    "SELECT interface_name FROM firewall_zone_interfaces WHERE zone_id = ?",
                )
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch zone interfaces")?;

                let interfaces: Vec<String> =
                    interface_rows.into_iter().map(|(name,)| name).collect();

                Ok(Some(FirewallZone {
                    id: Some(id),
                    name,
                    description,
                    interfaces,
                    default_input_policy: input_policy.parse().unwrap_or(FirewallPolicy::Drop),
                    default_forward_policy: forward_policy.parse().unwrap_or(FirewallPolicy::Drop),
                }))
            }
            None => Ok(None),
        }
    }

    /// Get a firewall zone by name
    pub async fn get_firewall_zone_by_name(
        &self,
        name: &str,
    ) -> Result<Option<keystone_core::FirewallZone>> {
        use keystone_core::{FirewallPolicy, FirewallZone};

        let row = sqlx::query_as::<_, (i64, String, Option<String>, String, String)>(
            r#"SELECT id, name, description, default_input_policy, default_forward_policy
               FROM firewall_zones WHERE name = ?"#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch firewall zone by name")?;

        match row {
            Some((id, name, description, input_policy, forward_policy)) => {
                let interface_rows = sqlx::query_as::<_, (String,)>(
                    "SELECT interface_name FROM firewall_zone_interfaces WHERE zone_id = ?",
                )
                .bind(id)
                .fetch_all(&self.pool)
                .await
                .context("Failed to fetch zone interfaces")?;

                let interfaces: Vec<String> =
                    interface_rows.into_iter().map(|(name,)| name).collect();

                Ok(Some(FirewallZone {
                    id: Some(id),
                    name,
                    description,
                    interfaces,
                    default_input_policy: input_policy.parse().unwrap_or(FirewallPolicy::Drop),
                    default_forward_policy: forward_policy.parse().unwrap_or(FirewallPolicy::Drop),
                }))
            }
            None => Ok(None),
        }
    }

    /// Save (insert or update) a firewall zone
    pub async fn save_firewall_zone(&self, zone: &keystone_core::FirewallZone) -> Result<i64> {
        if zone.name.is_empty() {
            anyhow::bail!("Zone name is required");
        }

        let mut tx = self.pool.begin().await?;

        let id = if let Some(id) = zone.id {
            // Update existing zone
            sqlx::query(
                r#"UPDATE firewall_zones SET 
                   name = ?, description = ?, default_input_policy = ?, 
                   default_forward_policy = ?, updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&zone.name)
            .bind(&zone.description)
            .bind(zone.default_input_policy.to_string())
            .bind(zone.default_forward_policy.to_string())
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("Failed to update firewall zone")?;

            // Clear existing interfaces
            sqlx::query("DELETE FROM firewall_zone_interfaces WHERE zone_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .context("Failed to clear zone interfaces")?;

            id
        } else {
            // Insert new zone
            let result = sqlx::query(
                r#"INSERT INTO firewall_zones 
                   (name, description, default_input_policy, default_forward_policy, created_at, updated_at)
                   VALUES (?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&zone.name)
            .bind(&zone.description)
            .bind(zone.default_input_policy.to_string())
            .bind(zone.default_forward_policy.to_string())
            .execute(&mut *tx)
            .await
            .context("Failed to insert firewall zone")?;

            result.last_insert_rowid()
        };

        // Insert interfaces
        for iface_name in &zone.interfaces {
            sqlx::query(
                "INSERT INTO firewall_zone_interfaces (zone_id, interface_name) VALUES (?, ?)",
            )
            .bind(id)
            .bind(iface_name)
            .execute(&mut *tx)
            .await
            .context("Failed to insert zone interface")?;
        }

        tx.commit().await?;
        info!("Saved firewall zone '{}' with id {}", zone.name, id);
        Ok(id)
    }

    /// Delete a firewall zone by ID
    /// Returns error if zone is in use by forwarding policies or rules
    pub async fn delete_firewall_zone(&self, id: i64) -> Result<bool> {
        // Check if zone is used in zone forwards
        let forward_count = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM firewall_zone_forwards WHERE source_zone_id = ? OR dest_zone_id = ?",
        )
        .bind(id)
        .bind(id)
        .fetch_one(&self.pool)
        .await?
        .0;

        if forward_count > 0 {
            anyhow::bail!(
                "Cannot delete zone: it is used in {} zone forwarding policies",
                forward_count
            );
        }

        let result = sqlx::query("DELETE FROM firewall_zones WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete firewall zone")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Zone Forward Policy CRUD Operations
    // ========================================================================

    /// Get all zone forward policies
    pub async fn get_zone_forwards(&self) -> Result<Vec<keystone_core::ZoneForwardPolicy>> {
        use keystone_core::{FirewallAction, ZoneForwardPolicy};

        let rows = sqlx::query_as::<_, (i64, i64, i64, String, bool)>(
            r#"SELECT zf.id, zf.source_zone_id, zf.dest_zone_id, zf.policy, zf.enabled
               FROM firewall_zone_forwards zf
               ORDER BY zf.id"#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch zone forwards")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: std::collections::HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let forwards = rows
            .into_iter()
            .filter_map(|(id, source_id, dest_id, policy, enabled)| {
                Some(ZoneForwardPolicy {
                    id: Some(id),
                    source_zone: zone_names.get(&source_id)?.clone(),
                    dest_zone: zone_names.get(&dest_id)?.clone(),
                    policy: policy.parse().unwrap_or(FirewallAction::Drop),
                    enabled,
                })
            })
            .collect();

        Ok(forwards)
    }

    /// Save (insert or update) a zone forward policy
    pub async fn save_zone_forward(
        &self,
        forward: &keystone_core::ZoneForwardPolicy,
    ) -> Result<i64> {
        // Look up zone IDs by name
        let source_zone = self
            .get_firewall_zone_by_name(&forward.source_zone)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Source zone '{}' not found", forward.source_zone))?;
        let dest_zone = self
            .get_firewall_zone_by_name(&forward.dest_zone)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Destination zone '{}' not found", forward.dest_zone))?;

        let source_id = source_zone.id.unwrap();
        let dest_id = dest_zone.id.unwrap();

        let id = if let Some(id) = forward.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_zone_forwards SET 
                   source_zone_id = ?, dest_zone_id = ?, policy = ?, enabled = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(source_id)
            .bind(dest_id)
            .bind(forward.policy.to_string())
            .bind(forward.enabled)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update zone forward")?;
            id
        } else {
            // Insert new - use INSERT OR REPLACE to handle unique constraint
            let result = sqlx::query(
                r#"INSERT INTO firewall_zone_forwards 
                   (source_zone_id, dest_zone_id, policy, enabled, created_at, updated_at)
                   VALUES (?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))
                   ON CONFLICT(source_zone_id, dest_zone_id) DO UPDATE SET
                   policy = excluded.policy, enabled = excluded.enabled,
                   updated_at = strftime('%s', 'now')"#,
            )
            .bind(source_id)
            .bind(dest_id)
            .bind(forward.policy.to_string())
            .bind(forward.enabled)
            .execute(&self.pool)
            .await
            .context("Failed to insert zone forward")?;
            result.last_insert_rowid()
        };

        info!(
            "Saved zone forward {} -> {} ({})",
            forward.source_zone, forward.dest_zone, forward.policy
        );
        Ok(id)
    }

    /// Delete a zone forward policy by ID
    pub async fn delete_zone_forward(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_zone_forwards WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete zone forward")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Port Forward CRUD Operations
    // ========================================================================

    /// Get all port forwards
    pub async fn get_port_forwards(&self) -> Result<Vec<keystone_core::PortForward>> {
        use keystone_core::{PortForward, RuleProtocol};

        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                String,
                Option<i64>,
                i64,
                Option<i64>,
                Option<String>,
                String,
                Option<i64>,
            ),
        >(
            r#"SELECT pf.id, pf.name, pf.description, pf.enabled, pf.protocol,
                      pf.source_zone_id, pf.external_port_start, pf.external_port_end,
                      pf.source_ip, pf.dest_ip, pf.dest_port
               FROM firewall_port_forwards pf
               ORDER BY pf.name"#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch port forwards")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: std::collections::HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let forwards = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    description,
                    enabled,
                    protocol,
                    source_zone_id,
                    ext_port_start,
                    ext_port_end,
                    source_ip,
                    dest_ip,
                    dest_port,
                )| {
                    PortForward {
                        id: Some(id),
                        name,
                        description,
                        enabled,
                        protocol: protocol.parse().unwrap_or(RuleProtocol::Tcp),
                        source_zone: source_zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        external_port_start: ext_port_start as u16,
                        external_port_end: ext_port_end.map(|p| p as u16),
                        source_ip,
                        dest_ip,
                        dest_port: dest_port.map(|p| p as u16),
                    }
                },
            )
            .collect();

        Ok(forwards)
    }

    /// Save (insert or update) a port forward
    pub async fn save_port_forward(&self, pf: &keystone_core::PortForward) -> Result<i64> {
        if pf.name.is_empty() {
            anyhow::bail!("Port forward name is required");
        }
        if pf.dest_ip.is_empty() {
            anyhow::bail!("Destination IP is required");
        }
        if pf.external_port_start == 0 {
            anyhow::bail!("External port is required");
        }

        // Look up source zone ID if specified
        let source_zone_id = if let Some(ref zone_name) = pf.source_zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let id = if let Some(id) = pf.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_port_forwards SET 
                   name = ?, description = ?, enabled = ?, protocol = ?,
                   source_zone_id = ?, external_port_start = ?, external_port_end = ?,
                   source_ip = ?, dest_ip = ?, dest_port = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&pf.name)
            .bind(&pf.description)
            .bind(pf.enabled)
            .bind(pf.protocol.to_string())
            .bind(source_zone_id)
            .bind(pf.external_port_start as i64)
            .bind(pf.external_port_end.map(|p| p as i64))
            .bind(&pf.source_ip)
            .bind(&pf.dest_ip)
            .bind(pf.dest_port.map(|p| p as i64))
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update port forward")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO firewall_port_forwards 
                   (name, description, enabled, protocol, source_zone_id, 
                    external_port_start, external_port_end, source_ip, dest_ip, dest_port,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&pf.name)
            .bind(&pf.description)
            .bind(pf.enabled)
            .bind(pf.protocol.to_string())
            .bind(source_zone_id)
            .bind(pf.external_port_start as i64)
            .bind(pf.external_port_end.map(|p| p as i64))
            .bind(&pf.source_ip)
            .bind(&pf.dest_ip)
            .bind(pf.dest_port.map(|p| p as i64))
            .execute(&self.pool)
            .await
            .context("Failed to insert port forward")?;
            result.last_insert_rowid()
        };

        info!("Saved port forward '{}' with id {}", pf.name, id);
        Ok(id)
    }

    /// Delete a port forward by ID
    pub async fn delete_port_forward(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_port_forwards WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete port forward")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Input Rule CRUD Operations
    // ========================================================================

    /// Get all input rules
    pub async fn get_input_rules(&self) -> Result<Vec<keystone_core::InputRule>> {
        use keystone_core::{FirewallAction, InputRule, RuleProtocol};

        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, zone_id, protocol,
                      port_start, port_end, source_ip, action, log_enabled, log_prefix, rate_limit
               FROM firewall_input_rules
               ORDER BY position, id"#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch input rules")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: std::collections::HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let rules = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    description,
                    enabled,
                    position,
                    zone_id,
                    protocol,
                    port_start,
                    port_end,
                    source_ip,
                    action,
                    log_enabled,
                    log_prefix,
                    rate_limit,
                )| {
                    InputRule {
                        id: Some(id),
                        name,
                        description,
                        enabled,
                        position: position as i32,
                        zone: zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                        port_start: port_start.map(|p| p as u16),
                        port_end: port_end.map(|p| p as u16),
                        source_ip,
                        action: action.parse().unwrap_or(FirewallAction::Accept),
                        log_enabled,
                        log_prefix,
                        rate_limit,
                    }
                },
            )
            .collect();

        Ok(rules)
    }

    /// Save (insert or update) an input rule
    pub async fn save_input_rule(&self, rule: &keystone_core::InputRule) -> Result<i64> {
        if rule.name.is_empty() {
            anyhow::bail!("Input rule name is required");
        }

        // Look up zone ID if specified
        let zone_id = if let Some(ref zone_name) = rule.zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let id = if let Some(id) = rule.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_input_rules SET 
                   name = ?, description = ?, enabled = ?, position = ?, zone_id = ?,
                   protocol = ?, port_start = ?, port_end = ?, source_ip = ?,
                   action = ?, log_enabled = ?, log_prefix = ?, rate_limit = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.port_start.map(|p| p as i64))
            .bind(rule.port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update input rule")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO firewall_input_rules 
                   (name, description, enabled, position, zone_id, protocol,
                    port_start, port_end, source_ip, action, log_enabled, log_prefix, rate_limit,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.port_start.map(|p| p as i64))
            .bind(rule.port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .execute(&self.pool)
            .await
            .context("Failed to insert input rule")?;
            result.last_insert_rowid()
        };

        info!("Saved input rule '{}' with id {}", rule.name, id);
        Ok(id)
    }

    /// Delete an input rule by ID
    pub async fn delete_input_rule(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_input_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete input rule")?;

        Ok(result.rows_affected() > 0)
    }

    // ========================================================================
    // Forward Rule CRUD Operations
    // ========================================================================

    /// Get all forward rules
    pub async fn get_forward_rules(&self) -> Result<Vec<keystone_core::ForwardRule>> {
        use keystone_core::{FirewallAction, ForwardRule, RuleProtocol};

        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, source_zone_id, dest_zone_id,
                      protocol, dest_port_start, dest_port_end, source_ip, dest_ip,
                      action, log_enabled, log_prefix, rate_limit
               FROM firewall_forward_rules
               ORDER BY position, id"#,
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch forward rules")?;

        // Get zone name lookup
        let zones = self.get_firewall_zones().await?;
        let zone_names: std::collections::HashMap<i64, String> = zones
            .into_iter()
            .filter_map(|z| z.id.map(|id| (id, z.name)))
            .collect();

        let rules = rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    description,
                    enabled,
                    position,
                    source_zone_id,
                    dest_zone_id,
                    protocol,
                    dest_port_start,
                    dest_port_end,
                    source_ip,
                    dest_ip,
                    action,
                    log_enabled,
                    log_prefix,
                    rate_limit,
                )| {
                    ForwardRule {
                        id: Some(id),
                        name,
                        description,
                        enabled,
                        position: position as i32,
                        source_zone: source_zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        dest_zone: dest_zone_id.and_then(|id| zone_names.get(&id).cloned()),
                        protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                        dest_port_start: dest_port_start.map(|p| p as u16),
                        dest_port_end: dest_port_end.map(|p| p as u16),
                        source_ip,
                        dest_ip,
                        action: action.parse().unwrap_or(FirewallAction::Accept),
                        log_enabled,
                        log_prefix,
                        rate_limit,
                    }
                },
            )
            .collect();

        Ok(rules)
    }

    /// Save (insert or update) a forward rule
    pub async fn save_forward_rule(&self, rule: &keystone_core::ForwardRule) -> Result<i64> {
        if rule.name.is_empty() {
            anyhow::bail!("Forward rule name is required");
        }

        // Look up zone IDs if specified
        let source_zone_id = if let Some(ref zone_name) = rule.source_zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Source zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let dest_zone_id = if let Some(ref zone_name) = rule.dest_zone {
            let zone = self
                .get_firewall_zone_by_name(zone_name)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Destination zone '{}' not found", zone_name))?;
            zone.id
        } else {
            None
        };

        let id = if let Some(id) = rule.id {
            // Update existing
            sqlx::query(
                r#"UPDATE firewall_forward_rules SET 
                   name = ?, description = ?, enabled = ?, position = ?,
                   source_zone_id = ?, dest_zone_id = ?, protocol = ?,
                   dest_port_start = ?, dest_port_end = ?, source_ip = ?, dest_ip = ?,
                   action = ?, log_enabled = ?, log_prefix = ?, rate_limit = ?,
                   updated_at = strftime('%s', 'now')
                   WHERE id = ?"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(source_zone_id)
            .bind(dest_zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.dest_port_start.map(|p| p as i64))
            .bind(rule.dest_port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(&rule.dest_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update forward rule")?;
            id
        } else {
            // Insert new
            let result = sqlx::query(
                r#"INSERT INTO firewall_forward_rules 
                   (name, description, enabled, position, source_zone_id, dest_zone_id,
                    protocol, dest_port_start, dest_port_end, source_ip, dest_ip,
                    action, log_enabled, log_prefix, rate_limit, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'), strftime('%s', 'now'))"#,
            )
            .bind(&rule.name)
            .bind(&rule.description)
            .bind(rule.enabled)
            .bind(rule.position as i64)
            .bind(source_zone_id)
            .bind(dest_zone_id)
            .bind(rule.protocol.map(|p| p.to_string()))
            .bind(rule.dest_port_start.map(|p| p as i64))
            .bind(rule.dest_port_end.map(|p| p as i64))
            .bind(&rule.source_ip)
            .bind(&rule.dest_ip)
            .bind(rule.action.to_string())
            .bind(rule.log_enabled)
            .bind(&rule.log_prefix)
            .bind(&rule.rate_limit)
            .execute(&self.pool)
            .await
            .context("Failed to insert forward rule")?;
            result.last_insert_rowid()
        };

        info!("Saved forward rule '{}' with id {}", rule.name, id);
        Ok(id)
    }

    /// Delete a forward rule by ID
    pub async fn delete_forward_rule(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM firewall_forward_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete forward rule")?;

        Ok(result.rows_affected() > 0)
    }

    /// Get a single input rule by ID
    pub async fn get_input_rule(&self, id: i64) -> Result<Option<keystone_core::InputRule>> {
        use keystone_core::{FirewallAction, InputRule, RuleProtocol};

        let row = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, zone_id, protocol,
                      port_start, port_end, source_ip, action, log_enabled, log_prefix, rate_limit
               FROM firewall_input_rules WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch input rule")?;

        match row {
            Some((
                id,
                name,
                description,
                enabled,
                position,
                zone_id,
                protocol,
                port_start,
                port_end,
                source_ip,
                action,
                log_enabled,
                log_prefix,
                rate_limit,
            )) => {
                // Get zone name if zone_id is set
                let zone = if let Some(zid) = zone_id {
                    self.get_firewall_zone(zid).await?.map(|z| z.name)
                } else {
                    None
                };

                Ok(Some(InputRule {
                    id: Some(id),
                    name,
                    description,
                    enabled,
                    position: position as i32,
                    zone,
                    protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                    port_start: port_start.map(|p| p as u16),
                    port_end: port_end.map(|p| p as u16),
                    source_ip,
                    action: action.parse().unwrap_or(FirewallAction::Accept),
                    log_enabled,
                    log_prefix,
                    rate_limit,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get a single forward rule by ID
    pub async fn get_forward_rule(&self, id: i64) -> Result<Option<keystone_core::ForwardRule>> {
        use keystone_core::{FirewallAction, ForwardRule, RuleProtocol};

        let row = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                bool,
                i64,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<i64>,
                Option<i64>,
                Option<String>,
                Option<String>,
                String,
                bool,
                Option<String>,
                Option<String>,
            ),
        >(
            r#"SELECT id, name, description, enabled, position, source_zone_id, dest_zone_id,
                      protocol, dest_port_start, dest_port_end, source_ip, dest_ip,
                      action, log_enabled, log_prefix, rate_limit
               FROM firewall_forward_rules WHERE id = ?"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch forward rule")?;

        match row {
            Some((
                id,
                name,
                description,
                enabled,
                position,
                source_zone_id,
                dest_zone_id,
                protocol,
                dest_port_start,
                dest_port_end,
                source_ip,
                dest_ip,
                action,
                log_enabled,
                log_prefix,
                rate_limit,
            )) => {
                // Get zone names
                let source_zone = if let Some(zid) = source_zone_id {
                    self.get_firewall_zone(zid).await?.map(|z| z.name)
                } else {
                    None
                };
                let dest_zone = if let Some(zid) = dest_zone_id {
                    self.get_firewall_zone(zid).await?.map(|z| z.name)
                } else {
                    None
                };

                Ok(Some(ForwardRule {
                    id: Some(id),
                    name,
                    description,
                    enabled,
                    position: position as i32,
                    source_zone,
                    dest_zone,
                    protocol: protocol.and_then(|p| p.parse::<RuleProtocol>().ok()),
                    dest_port_start: dest_port_start.map(|p| p as u16),
                    dest_port_end: dest_port_end.map(|p| p as u16),
                    source_ip,
                    dest_ip,
                    action: action.parse().unwrap_or(FirewallAction::Accept),
                    log_enabled,
                    log_prefix,
                    rate_limit,
                }))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Firewall Config Aggregate Operations
    // ========================================================================

    /// Get complete firewall configuration
    pub async fn get_firewall_config(&self) -> Result<keystone_core::FirewallConfig> {
        Ok(keystone_core::FirewallConfig {
            zones: self.get_firewall_zones().await?,
            zone_forwards: self.get_zone_forwards().await?,
            port_forwards: self.get_port_forwards().await?,
            input_rules: self.get_input_rules().await?,
            forward_rules: self.get_forward_rules().await?,
            global_settings: self.get_firewall_global_settings().await?,
        })
    }

    // ========================================================================
    // Firewall Global Settings Operations
    // ========================================================================

    /// Get global firewall settings
    pub async fn get_firewall_global_settings(&self) -> Result<keystone_core::FirewallGlobalSettings> {
        let row = sqlx::query_as::<_, (bool, bool, bool)>(
            "SELECT ping_wan_enabled, ping_lan_enabled, hairpin_nat_enabled 
             FROM firewall_global_settings WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch firewall global settings")?;

        match row {
            Some((ping_wan, ping_lan, hairpin)) => Ok(keystone_core::FirewallGlobalSettings {
                ping_wan_enabled: ping_wan,
                ping_lan_enabled: ping_lan,
                hairpin_nat_enabled: hairpin,
            }),
            None => {
                // Return defaults if no row exists (shouldn't happen after migration)
                Ok(keystone_core::FirewallGlobalSettings::default())
            }
        }
    }

    /// Save global firewall settings
    pub async fn save_firewall_global_settings(
        &self,
        settings: &keystone_core::FirewallGlobalSettings,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO firewall_global_settings 
               (id, ping_wan_enabled, ping_lan_enabled, hairpin_nat_enabled, updated_at)
               VALUES (1, ?, ?, ?, strftime('%s', 'now'))"#,
        )
        .bind(settings.ping_wan_enabled)
        .bind(settings.ping_lan_enabled)
        .bind(settings.hairpin_nat_enabled)
        .execute(&self.pool)
        .await
        .context("Failed to save firewall global settings")?;

        info!(
            "Saved firewall global settings: ping_wan={}, ping_lan={}, hairpin={}",
            settings.ping_wan_enabled, settings.ping_lan_enabled, settings.hairpin_nat_enabled
        );
        Ok(())
    }

    // ========================================================================
    // Rollback State Operations
    // ========================================================================

    /// Save rollback state for safe apply
    pub async fn save_rollback_state(
        &self,
        config: &keystone_core::FirewallConfig,
        rollback_at: i64,
    ) -> Result<()> {
        let config_json =
            serde_json::to_string(config).context("Failed to serialize firewall config")?;

        sqlx::query(
            r#"INSERT OR REPLACE INTO firewall_rollback_state 
               (id, previous_config, rollback_at, created_at)
               VALUES (1, ?, ?, strftime('%s', 'now'))"#,
        )
        .bind(&config_json)
        .bind(rollback_at)
        .execute(&self.pool)
        .await
        .context("Failed to save rollback state")?;

        info!("Saved rollback state, will rollback at {}", rollback_at);
        Ok(())
    }

    /// Get pending rollback state
    pub async fn get_rollback_state(
        &self,
    ) -> Result<Option<(keystone_core::FirewallConfig, i64)>> {
        let row = sqlx::query_as::<_, (String, i64)>(
            "SELECT previous_config, rollback_at FROM firewall_rollback_state WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch rollback state")?;

        match row {
            Some((config_json, rollback_at)) => {
                let config: keystone_core::FirewallConfig = serde_json::from_str(&config_json)
                    .context("Failed to deserialize rollback config")?;
                Ok(Some((config, rollback_at)))
            }
            None => Ok(None),
        }
    }

    /// Clear rollback state (called on confirm)
    pub async fn clear_rollback_state(&self) -> Result<()> {
        sqlx::query("DELETE FROM firewall_rollback_state WHERE id = 1")
            .execute(&self.pool)
            .await
            .context("Failed to clear rollback state")?;

        info!("Cleared rollback state");
        Ok(())
    }
}

