//! Interface configuration database operations

use anyhow::{Context, Result};
use keystone_core::{
    ActivationPolicy, AddressScope, DhcpMode, DhcpPrefixDelegationConfig, Dhcpv4ClientConfig,
    Dhcpv6ClientConfig, InterfaceConfig, InterfaceRole, IpForwardMode, IpMasqueradeMode,
    Ipv6AcceptRaConfig, LinkLocalMode, ManagedInterface, RouteType, StaticAddress, StaticRoute,
};
use sqlx::SqlitePool;
use tracing::info;

/// Interface-related database operations
pub struct InterfacesDb<'a> {
    pool: &'a SqlitePool,
}

impl<'a> InterfacesDb<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    // ========================================================================
    // Managed Interfaces (legacy)
    // ========================================================================

    /// Get all managed interfaces
    pub async fn get_managed_interfaces(&self) -> Result<Vec<ManagedInterface>> {
        let rows = sqlx::query_as::<_, (String, String, Option<String>, bool)>(
            "SELECT name, role, static_ip, enabled FROM managed_interfaces ORDER BY name",
        )
        .fetch_all(self.pool)
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
        keystone_core::validation::single_line_fields(&interfaces).map_err(anyhow::Error::msg)?;
        for interface in interfaces {
            keystone_core::validation::interface_name(&interface.name)
                .map_err(anyhow::Error::msg)?;
        }
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

    // ========================================================================
    // Interface Configuration
    // ========================================================================

    /// Get all interface configurations
    pub async fn get_interface_configs(&self) -> Result<Vec<InterfaceConfig>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                bool,
                Option<String>,
                String,
                Option<String>,
                bool,
                bool,
                String,
                String,
                String,
                bool,
                String,
                Option<i64>,
            ),
        >(
            r#"SELECT id, interface_name, role, enabled, description, dhcp_mode, gateway,
                      ipv6_accept_ra, ipv6_send_ra, ip_forward, ip_masquerade,
                      link_local, required_for_online, activation_policy, mtu
               FROM interface_config ORDER BY interface_name"#,
        )
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch interface configs")?;

        let mut configs = Vec::new();
        for (
            id,
            name,
            role,
            enabled,
            description,
            dhcp_mode,
            gateway,
            ipv6_accept_ra,
            ipv6_send_ra,
            ip_forward,
            ip_masquerade,
            link_local,
            required_for_online,
            activation_policy,
            mtu,
        ) in rows
        {
            let addresses = self.get_interface_addresses(id).await?;
            let routes = self.get_interface_routes(id).await?;
            let dns_servers = self.get_interface_dns(id).await?;
            let search_domains = self.get_interface_domains(id).await?;
            let dhcpv4_client = self.get_dhcpv4_client_config(id).await?;
            let dhcpv6_client = self.get_dhcpv6_client_config(id).await?;
            let ipv6_accept_ra_config = self.get_ipv6_accept_ra_config(id).await?;
            let dhcp_prefix_delegation = self.get_dhcp_prefix_delegation_config(id).await?;
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
                activation_policy: activation_policy
                    .parse()
                    .unwrap_or(ActivationPolicy::default()),
                dhcpv4_client,
                dhcpv6_client,
                ipv6_accept_ra,
                ipv6_accept_ra_config,
                ipv6_send_ra,
                dhcp_prefix_delegation,
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
        let row = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                bool,
                Option<String>,
                String,
                Option<String>,
                bool,
                bool,
                String,
                String,
                String,
                bool,
                String,
                Option<i64>,
            ),
        >(
            r#"SELECT id, interface_name, role, enabled, description, dhcp_mode, gateway,
                      ipv6_accept_ra, ipv6_send_ra, ip_forward, ip_masquerade,
                      link_local, required_for_online, activation_policy, mtu
               FROM interface_config WHERE interface_name = ?"#,
        )
        .bind(name)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch interface config")?;

        match row {
            Some((
                id,
                name,
                role,
                enabled,
                description,
                dhcp_mode,
                gateway,
                ipv6_accept_ra,
                ipv6_send_ra,
                ip_forward,
                ip_masquerade,
                link_local,
                required_for_online,
                activation_policy,
                mtu,
            )) => {
                let addresses = self.get_interface_addresses(id).await?;
                let routes = self.get_interface_routes(id).await?;
                let dns_servers = self.get_interface_dns(id).await?;
                let search_domains = self.get_interface_domains(id).await?;
                let dhcpv4_client = self.get_dhcpv4_client_config(id).await?;
                let dhcpv6_client = self.get_dhcpv6_client_config(id).await?;
                let ipv6_accept_ra_config = self.get_ipv6_accept_ra_config(id).await?;
                let dhcp_prefix_delegation = self.get_dhcp_prefix_delegation_config(id).await?;
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
                    activation_policy: activation_policy
                        .parse()
                        .unwrap_or(ActivationPolicy::default()),
                    dhcpv4_client,
                    dhcpv6_client,
                    ipv6_accept_ra,
                    ipv6_accept_ra_config,
                    ipv6_send_ra,
                    dhcp_prefix_delegation,
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
        keystone_core::validation::single_line_fields(config).map_err(anyhow::Error::msg)?;
        keystone_core::validation::interface_name(&config.name).map_err(anyhow::Error::msg)?;
        for name in &config.vlans {
            keystone_core::validation::interface_name(name).map_err(anyhow::Error::msg)?;
        }
        let mut tx = self.pool.begin().await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let prefix_delegation = config.dhcp_prefix_delegation.as_ref();

        let config_id: i64 = if let Some(id) = config.id {
            // Update existing
            sqlx::query(
                r#"UPDATE interface_config SET
                   role = ?, enabled = ?, description = ?, dhcp_mode = ?, gateway = ?,
                   ipv6_accept_ra = ?, ipv6_send_ra = ?,
                   dhcp_prefix_delegation_enabled = ?, dhcp_prefix_delegation_uplink = ?,
                   dhcp_prefix_delegation_subnet_id = ?, dhcp_prefix_delegation_announce = ?,
                   ip_forward = ?, ip_masquerade = ?, link_local = ?, required_for_online = ?,
                   activation_policy = ?, mtu = ?, updated_at = ?
                   WHERE id = ?"#,
            )
            .bind(config.role.to_string())
            .bind(config.enabled)
            .bind(&config.description)
            .bind(config.dhcp_mode.to_string())
            .bind(&config.gateway)
            .bind(config.ipv6_accept_ra)
            .bind(config.ipv6_send_ra)
            .bind(prefix_delegation.is_some())
            .bind(prefix_delegation.and_then(|pd| pd.uplink_interface.as_ref()))
            .bind(
                prefix_delegation
                    .and_then(|pd| pd.subnet_id)
                    .map(|id| id as i64),
            )
            .bind(prefix_delegation.is_some_and(|pd| pd.announce))
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
            // Insert new (or replace existing by interface_name)
            //
            // The wizard and other callers may send configs without `id` even if
            // a row already exists. Since `interface_name` is UNIQUE, use an
            // upsert keyed on `interface_name`.
            let _result = sqlx::query(
                r#"INSERT INTO interface_config
                   (interface_name, role, enabled, description, dhcp_mode, gateway,
                    ipv6_accept_ra, ipv6_send_ra, dhcp_prefix_delegation_enabled,
                    dhcp_prefix_delegation_uplink, dhcp_prefix_delegation_subnet_id,
                    dhcp_prefix_delegation_announce, ip_forward, ip_masquerade, link_local,
                    required_for_online, activation_policy, mtu, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(interface_name) DO UPDATE SET
                     role = excluded.role,
                     enabled = excluded.enabled,
                     description = excluded.description,
                     dhcp_mode = excluded.dhcp_mode,
                     gateway = excluded.gateway,
                     ipv6_accept_ra = excluded.ipv6_accept_ra,
                     ipv6_send_ra = excluded.ipv6_send_ra,
                     dhcp_prefix_delegation_enabled = excluded.dhcp_prefix_delegation_enabled,
                     dhcp_prefix_delegation_uplink = excluded.dhcp_prefix_delegation_uplink,
                     dhcp_prefix_delegation_subnet_id = excluded.dhcp_prefix_delegation_subnet_id,
                     dhcp_prefix_delegation_announce = excluded.dhcp_prefix_delegation_announce,
                     ip_forward = excluded.ip_forward,
                     ip_masquerade = excluded.ip_masquerade,
                     link_local = excluded.link_local,
                     required_for_online = excluded.required_for_online,
                     activation_policy = excluded.activation_policy,
                     mtu = excluded.mtu,
                     updated_at = excluded.updated_at"#,
            )
            .bind(&config.name)
            .bind(config.role.to_string())
            .bind(config.enabled)
            .bind(&config.description)
            .bind(config.dhcp_mode.to_string())
            .bind(&config.gateway)
            .bind(config.ipv6_accept_ra)
            .bind(config.ipv6_send_ra)
            .bind(prefix_delegation.is_some())
            .bind(prefix_delegation.and_then(|pd| pd.uplink_interface.as_ref()))
            .bind(
                prefix_delegation
                    .and_then(|pd| pd.subnet_id)
                    .map(|id| id as i64),
            )
            .bind(prefix_delegation.is_some_and(|pd| pd.announce))
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
            .context("Failed to upsert interface config")?;

            let id_row: Option<(i64,)> =
                sqlx::query_as("SELECT id FROM interface_config WHERE interface_name = ?")
                    .bind(&config.name)
                    .fetch_optional(&mut *tx)
                    .await?;

            id_row
                .map(|(id,)| id)
                .ok_or_else(|| anyhow::anyhow!("Upsert did not create interface config"))?
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
                   (interface_config_id, use_dns, use_ntp, use_domains, use_delegated_prefix,
                    prefix_delegation_hint, rapid_commit, without_ra)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
            )
            .bind(config_id)
            .bind(dhcp_config.use_dns)
            .bind(dhcp_config.use_ntp)
            .bind(&dhcp_config.use_domains)
            .bind(dhcp_config.use_delegated_prefix)
            .bind(&dhcp_config.prefix_delegation_hint)
            .bind(dhcp_config.rapid_commit)
            .bind(&dhcp_config.without_ra)
            .execute(&mut *tx)
            .await?;
        }

        // Save IPv6 Accept RA config
        self.save_ipv6_accept_ra_config_tx(&mut tx, config_id, &config.ipv6_accept_ra_config)
            .await?;

        tx.commit().await.context("Failed to commit transaction")?;
        info!("Saved interface config for {}", config.name);
        Ok(config_id)
    }

    /// Delete an interface configuration
    pub async fn delete_interface_config(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM interface_config WHERE interface_name = ?")
            .bind(name)
            .execute(self.pool)
            .await
            .context("Failed to delete interface config")?;

        info!("Deleted interface config: {}", name);
        Ok(())
    }

    // ========================================================================
    // Helper methods for fetching related data
    // ========================================================================

    async fn get_interface_addresses(&self, config_id: i64) -> Result<Vec<StaticAddress>> {
        let rows = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT address, label FROM interface_addresses WHERE interface_config_id = ? ORDER BY id",
        )
        .bind(config_id)
        .fetch_all(self.pool)
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
        .fetch_all(self.pool)
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
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch interface DNS servers")?;

        Ok(rows.into_iter().map(|(s,)| s).collect())
    }

    async fn get_interface_domains(&self, config_id: i64) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT domain FROM interface_domains WHERE interface_config_id = ? ORDER BY id",
        )
        .bind(config_id)
        .fetch_all(self.pool)
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
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch DHCPv4 client config")?;

        Ok(row.map(
            |(
                send_hostname,
                hostname,
                use_dns,
                use_ntp,
                use_routes,
                use_gateway,
                use_mtu,
                use_domains,
                route_metric,
            )| {
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
            },
        ))
    }

    async fn get_dhcpv6_client_config(&self, config_id: i64) -> Result<Option<Dhcpv6ClientConfig>> {
        let row = sqlx::query_as::<_, (bool, bool, String, bool, Option<String>, bool, String)>(
            r#"SELECT use_dns, use_ntp, use_domains, use_delegated_prefix,
                      prefix_delegation_hint, rapid_commit, without_ra
               FROM dhcpv6_client_config WHERE interface_config_id = ?"#,
        )
        .bind(config_id)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch DHCPv6 client config")?;

        Ok(row.map(
            |(
                use_dns,
                use_ntp,
                use_domains,
                use_delegated_prefix,
                prefix_delegation_hint,
                rapid_commit,
                without_ra,
            )| Dhcpv6ClientConfig {
                use_dns,
                use_ntp,
                use_domains,
                use_delegated_prefix,
                prefix_delegation_hint,
                rapid_commit,
                without_ra,
            },
        ))
    }

    async fn get_ipv6_accept_ra_config(
        &self,
        config_id: i64,
    ) -> Result<Option<Ipv6AcceptRaConfig>> {
        let row = sqlx::query_as::<_, (bool, bool, bool, bool)>(
            r#"SELECT use_dns, use_gateway, use_route_prefix, use_autonomous_prefix
               FROM ipv6_accept_ra_config WHERE interface_config_id = ?"#,
        )
        .bind(config_id)
        .fetch_optional(self.pool)
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

    async fn get_dhcp_prefix_delegation_config(
        &self,
        config_id: i64,
    ) -> Result<Option<DhcpPrefixDelegationConfig>> {
        let row = sqlx::query_as::<_, (bool, Option<String>, Option<i64>, bool)>(
            r#"SELECT dhcp_prefix_delegation_enabled, dhcp_prefix_delegation_uplink,
                      dhcp_prefix_delegation_subnet_id, dhcp_prefix_delegation_announce
               FROM interface_config WHERE id = ?"#,
        )
        .bind(config_id)
        .fetch_optional(self.pool)
        .await
        .context("Failed to fetch DHCP prefix delegation config")?;

        Ok(
            row.and_then(|(enabled, uplink_interface, subnet_id, announce)| {
                enabled.then_some(DhcpPrefixDelegationConfig {
                    uplink_interface,
                    subnet_id: subnet_id.map(|id| id as u64),
                    announce,
                })
            }),
        )
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

    /// Get VLAN names attached to an interface (for populating vlans field in InterfaceConfig)
    async fn get_vlan_names_for_interface(&self, parent_interface: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT name FROM vlan_config WHERE parent_interface = ? ORDER BY vlan_id",
        )
        .bind(parent_interface)
        .fetch_all(self.pool)
        .await
        .context("Failed to fetch VLAN names")?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }
}
