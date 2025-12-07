use super::dicts::{COMMON_PASSWORDS, COMMON_USERNAMES};
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio_postgres::{Config, NoTls};
use tracing::info;

pub struct PostgresPlugin;

#[async_trait]
impl ScanPlugin for PostgresPlugin {
    fn name(&self) -> &str {
        "PostgreSQL"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![5432]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port: u16 = info.port.parse().unwrap_or(5432);

        let users = if COMMON_USERNAMES.contains(&"postgres") {
            COMMON_USERNAMES.to_vec()
        } else {
            let mut u = vec!["postgres"];
            u.extend_from_slice(COMMON_USERNAMES);
            u
        };

        for user in users {
            for pass in COMMON_PASSWORDS {
                let mut config = Config::new();
                config.user(user);
                config.password(pass);
                config.host(&host);
                config.port(port);
                config.dbname("postgres");
                config.connect_timeout(Duration::from_secs(3));

                let connect_future = config.connect(NoTls);

                match tokio::time::timeout(Duration::from_secs(5), connect_future).await {
                    Ok(Ok((client, connection))) => {
                        tokio::spawn(async move {
                            if let Err(_) = connection.await {
                            }
                        });

                        if client.simple_query("SELECT 1").await.is_ok() {
                            let msg = format!(
                                "[+] PostgreSQL 弱口令: {}:{} -> {}:{}",
                                host, port, user, pass
                            );
                            info!("{}", msg);
                            return Ok(Some(msg));
                        }
                    }
                    Ok(Err(e)) => {
                        let err_msg = e.to_string();
                        if !err_msg.contains("authentication failed") {
                            return Ok(None);
                        }
                    }
                    Err(_) => return Ok(None),
                }
            }
        }

        Ok(None)
    }
}
