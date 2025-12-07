use super::dicts::{COMMON_PASSWORDS, COMMON_USERNAMES};
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tiberius::{AuthMethod, Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use tracing::info;

pub struct MssqlPlugin;

#[async_trait]
impl ScanPlugin for MssqlPlugin {
    fn name(&self) -> &str {
        "MSSQL"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![1433]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port: u16 = info.port.parse().unwrap_or(1433);

        let users = if COMMON_USERNAMES.contains(&"sa") {
            COMMON_USERNAMES.to_vec()
        } else {
            let mut u = vec!["sa"];
            u.extend_from_slice(COMMON_USERNAMES);
            u
        };

        for user in users {
            for pass in COMMON_PASSWORDS {
                let mut config = Config::new();
                config.host(&host);
                config.port(port);
                config.authentication(AuthMethod::sql_server(user, pass));
                config.trust_cert();

                let tcp = match tokio::time::timeout(
                    Duration::from_secs(3),
                    TcpStream::connect(format!("{}:{}", host, port)),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    _ => return Ok(None),
                };

                let tcp = tcp.compat_write();

                match tokio::time::timeout(Duration::from_secs(3), Client::connect(config, tcp))
                    .await
                {
                    Ok(Ok(_)) => {
                        let msg =
                            format!("[+] MSSQL 弱口令: {}:{} -> {}:{}", host, port, user, pass);
                        info!("{}", msg);
                        return Ok(Some(msg));
                    }
                    _ => continue,
                }
            }
        }

        Ok(None)
    }
}
