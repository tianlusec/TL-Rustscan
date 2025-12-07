use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct JdwpPlugin;

#[async_trait]
impl ScanPlugin for JdwpPlugin {
    fn name(&self) -> &str {
        "JDWP"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![8000, 5005, 8453]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let port = info.port.parse::<u16>().unwrap_or(8000);
        let addr = format!("{}:{}", info.host, port);

        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let handshake = b"JDWP-Handshake";

                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(handshake))
                    .await
                    .is_err()
                {
                    return Ok(None);
                }

                let mut buf = [0u8; 14];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf)).await
                {
                    if n == 14 && &buf == handshake {
                        let msg = format!(
                            "[+] JDWP Service detected on {}\n[+] Vuln: JDWP RCE possible on {}",
                            addr, addr
                        );
                        println!("{}", msg);
                        return Ok(Some(msg));
                    }
                }
            }
            _ => {}
        }
        Ok(None)
    }
}
