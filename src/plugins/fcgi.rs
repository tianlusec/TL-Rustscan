use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;

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
                // 构造 FCGI_GET_VALUES 数据包
                // Version: 1
                // Type: 9 (FCGI_GET_VALUES)
                // Request ID: 1
                // Content Length: 0
                // Padding Length: 0
                // Reserved: 0
                let header = [
                    0x01, // Version
                    0x09, // Type: Get Values
                    0x00, 0x01, // Request ID: 1
                    0x00, 0x00, // Content Length: 0
                    0x00, // Padding Length
                    0x00, // Reserved
                ];

                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&header)).await.is_err() {
                    return Ok(None);
                }

                let mut buf = [0u8; 8];
                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
                    // 响应 Type 10 (FCGI_GET_VALUES_RESULT) 表示服务正常响应
                    if n == 8 && buf[0] == 0x01 && buf[1] == 0x0a {
                        let msg = format!("[+] FCGI (PHP-FPM) Service detected on {}", addr);
                        println!("{}", msg);
                        return Ok(Some(msg));
                        // 注意: 进一步的未授权 RCE 检测需要构造复杂的 Params 包 (SCRIPT_FILENAME 等)
                        // 这里仅做服务发现
                    }
                }
            }
            _ => {}
        }
        Ok(None)
    }
}
