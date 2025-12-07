use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct Ms17010Plugin;

#[async_trait]
impl ScanPlugin for Ms17010Plugin {
    fn name(&self) -> &str {
        "MS17-010"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![445]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let target = format!("{}:{}", info.host, info.port);

        let mut stream =
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target)).await {
                Ok(Ok(s)) => s,
                _ => return Ok(None),
            };

        let neg_proto_req = [
            0x00, 0x00, 0x00, 0x54,
            0xff, 0x53, 0x4d, 0x42,
            0x72,
            0x00, 0x00, 0x00, 0x00,
            0x18,
            0x01, 0x28,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x2f, 0x4b,
            0x00, 0x00,
            0x00, 0x00,
            0x00,
            0x31, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30,
            0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
            0x00,
        ];

        if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&neg_proto_req))
            .await
            .is_err()
        {
            return Ok(None);
        }

        let mut buffer = [0u8; 1024];
        let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(None),
        };

        if n > 8 && &buffer[4..8] == b"\xffSMB" {
            if buffer[8] == 0x72 {
                let msg = format!("[*] SMBv1 Enabled: {}", target);
                info!("{}", msg);
                return Ok(Some(msg));
            }
        }

        Ok(None)
    }
}
