use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct RdpPlugin;

#[async_trait]
impl ScanPlugin for RdpPlugin {
    fn name(&self) -> &str {
        "RDP"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![3389]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Info
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let target = format!("{}:3389", info.host);

        let mut stream =
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target)).await {
                Ok(Ok(s)) => s,
                _ => return Ok(None),
            };

        let payload: [u8; 19] = [
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&payload))
            .await
            .is_err()
        {
            return Ok(None);
        }

        let mut buf = [0u8; 1024];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await
        {
            if n > 0 {
                if n >= 6 && buf[0] == 0x03 && buf[5] == 0xd0 {
                    let msg = format!("[+] RDP Service: {}", target);
                    info!("{}", msg);
                    return Ok(Some(msg));
                }
            }
        }

        Ok(None)
    }
}
