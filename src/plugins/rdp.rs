use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

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
        
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&target)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        // 构造 RDP 连接请求 (TPKT + X.224 Connection Request)
        // TPKT Header: Version 3, Reserved 0, Length 19 (0x0013)
        // X.224 CR: Length 14 (0x0e), Code 0xe0 (CR), DstRef 0, SrcRef 0, Class 0
        // RDP Neg Req: Type 1, Flags 0, Len 8, Protocol 0
        let payload: [u8; 19] = [
            0x03, 0x00, 0x00, 0x13, // TPKT
            0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
            0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 // RDP Negotiation Request
        ];

        if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&payload)).await.is_err() {
            return Ok(None);
        }

        let mut buf = [0u8; 1024];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
            if n > 0 {
                // 检查是否是 Connection Confirm (0xd0)
                // TPKT Header (4 bytes) + X.224 Length (1 byte) + Code (1 byte)
                // 03 00 00 13 0e d0 ...
                if n >= 6 && buf[0] == 0x03 && buf[5] == 0xd0 {
                    let msg = format!("[+] RDP Service: {}", target);
                    println!("{}", msg);
                    return Ok(Some(msg));
                    // 进一步解析可以获取 NTLM 信息，但比较复杂，这里仅做服务识别
                }
            }
        }

        Ok(None)
    }
}
