use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct FcgiPlugin;

#[async_trait]
impl ScanPlugin for FcgiPlugin {
    fn name(&self) -> &str {
        "FCGI"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![9000]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let addr = format!("{}:9000", info.host);
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let header = [
                    0x01, 
                    0x09, 
                    0x00, 0x01, 
                    0x00, 0x00, 
                    0x00, 
                    0x00, 
                ];

                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&header))
                    .await
                    .is_err()
                {
                    return Ok(None);
                }

                let mut buf = [0u8; 8];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await
                {
                    
                    if n == 8 && buf[0] == 0x01 && buf[1] == 0x0a {
                        let msg = format!("[+] FCGI (PHP-FPM) Service detected on {}", addr);
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
