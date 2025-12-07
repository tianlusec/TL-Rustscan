use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct LdapPlugin;

#[async_trait]
impl ScanPlugin for LdapPlugin {
    fn name(&self) -> &str {
        "LDAP"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![389]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let addr = format!("{}:389", info.host);
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let bind_req = [
                    0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80,
                    0x00,
                ];

                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&bind_req))
                    .await
                    .is_err()
                {
                    return Ok(None);
                }

                let mut buf = [0u8; 1024];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await
                {
                    if n > 0 {
                        if buf[0] == 0x30 {
                            if n > 5 && buf[5] == 0x61 {
                                let msg = format!("[+] LDAP Service detected on {}", addr);
                                info!("{}", msg);

                                for i in 0..n - 2 {
                                    if buf[i] == 0x0a && buf[i + 1] == 0x01 && buf[i + 2] == 0x00 {
                                        let msg2 =
                                            format!("[+] LDAP Anonymous Bind Allowed on {}", addr);
                                        println!("{}", msg2);
                                        return Ok(Some(format!("{}\n{}", msg, msg2)));
                                    }
                                }
                                return Ok(Some(msg));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(None)
    }
}
