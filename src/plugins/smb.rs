use super::dicts;
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tracing::info;

#[cfg(target_os = "windows")]
use smb::{Client, ClientConfig};
#[cfg(target_os = "windows")]
use sspi::{AuthIdentity, Secret, Username};

pub struct SmbPlugin;

#[async_trait]
impl ScanPlugin for SmbPlugin {
    fn name(&self) -> &str {
        "SMB"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![445]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    #[cfg(not(target_os = "windows"))]
    async fn scan(&self, _info: &HostInfo) -> Result<Option<String>> {
        Ok(None)
    }

    #[cfg(target_os = "windows")]
    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port = 445;
        let addr = format!("{}:{}", host, port);

        let mut users = vec!["Administrator", "guest"];
        users.extend_from_slice(dicts::COMMON_USERNAMES);

        let passwords = dicts::COMMON_PASSWORDS;

        for user in users {
            for pass in passwords {
                let username = match Username::new(user, None) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                let password = Secret::new(pass.to_string());
                let auth = AuthIdentity { username, password };

                let config = ClientConfig::default();
                let client = Client::new(config);

                let connect_result =
                    tokio::time::timeout(Duration::from_secs(3), client.connect(&host)).await;

                if let Ok(Ok(connection)) = connect_result {
                    let auth_result =
                        tokio::time::timeout(Duration::from_secs(3), connection.authenticate(auth))
                            .await;
                    match auth_result {
                        Ok(Ok(_)) => {
                            let msg =
                                format!("[+] SMB 弱口令: {} -> {}\\{}:{}", addr, "", user, pass);
                            info!("{}", msg);
                            return Ok(Some(msg));
                        }
                        _ => continue,
                    }
                }
            }
        }

        Ok(None)
    }
}
