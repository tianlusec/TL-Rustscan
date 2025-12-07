use super::dicts::{COMMON_PASSWORDS, COMMON_USERNAMES};
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use mysql::{Conn, OptsBuilder};
use std::time::Duration;
use tracing::info;

pub struct MysqlPlugin;

#[async_trait]
impl ScanPlugin for MysqlPlugin {
    fn name(&self) -> &str {
        "MySQL"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![3306, 3307]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port: u16 = info.port.parse().unwrap_or(3306);

        let result = tokio::task::spawn_blocking(move || {
            for user in COMMON_USERNAMES {
                for pass in COMMON_PASSWORDS {
                    let opts = OptsBuilder::new()
                        .ip_or_hostname(Some(host.clone()))
                        .tcp_port(port)
                        .user(Some(*user))
                        .pass(Some(*pass))
                        .db_name(Some("mysql"))
                        .tcp_connect_timeout(Some(Duration::from_secs(3)))
                        .read_timeout(Some(Duration::from_secs(5)))
                        .write_timeout(Some(Duration::from_secs(5)));

                    match Conn::new(opts) {
                        Ok(_) => {
                            let msg =
                                format!("[+] MySQL 弱口令: {}:{} -> {}:{}", host, port, user, pass);
                            info!("{}", msg);
                            return Some(msg);
                        }
                        Err(_) => continue,
                    }
                }
            }
            None
        })
        .await?;

        Ok(result)
    }
}
