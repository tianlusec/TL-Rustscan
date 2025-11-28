use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

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
        
        // 1. 建立连接
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&target)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        // 2. 构造 SMB1 Negotiate Protocol Request
        // 这是触发 MS17-010 检测的关键包
        let neg_proto_req = [
            0x00, 0x00, 0x00, 0x54, // NetBIOS Session Service, Length: 84
            0xff, 0x53, 0x4d, 0x42, // SMB Header: Server Component: SMB
            0x72, // Command: Negotiate Protocol
            0x00, 0x00, 0x00, 0x00, // NT Status: STATUS_SUCCESS
            0x18, // Flags: Canonicalized Pathnames, Caseless Pathnames
            0x01, 0x28, // Flags2: Unicode, NT Status, Extended Security
            0x00, 0x00, // PID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
            0x00, 0x00, // Reserved
            0x00, 0x00, // TID
            0x2f, 0x4b, // PID
            0x00, 0x00, // UID
            0x00, 0x00, // MID
            0x00, // Word Count
            0x31, 0x00, // Byte Count
            // Dialects
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, // LANMAN1.0
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, // LM1.2X002
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, // NT LANMAN 1.0
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // NT LM 0.12
        ];

        if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&neg_proto_req)).await.is_err() {
            return Ok(None);
        }

        let mut buffer = [0u8; 1024];
        let n = match tokio::time::timeout(
            Duration::from_secs(3),
            stream.read(&mut buffer)
        ).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return Ok(None),
        };

        // 3. 简单的指纹判断
        // 如果服务器响应了 SMB1 协议协商，并且 Security Mode 暗示了特定版本，可能存在漏洞
        // 这里做一个简化的判断：如果响应是 SMB1 且包含 NT LM 0.12，则进一步判断
        // 真正的 MS17-010 检测需要更复杂的 Trans2 请求，这里先实现基础版本探测
        
        if n > 8 && &buffer[4..8] == b"\xffSMB" {
            // 检查 Command 是否为 Negotiate Protocol (0x72)
            if buffer[8] == 0x72 {
                // 这是一个非常粗略的判断，仅表示开启了 SMBv1
                // 准确的 MS17-010 需要检查 Transaction 响应中的 Multiplex ID 等
                // 为了不误报，我们这里只打印 "SMBv1 Enabled"
                // 如果需要精确打击，需要实现完整的 Trans2 溢出检测逻辑
                let msg = format!("[*] SMBv1 Enabled: {}", target);
                println!("{}", msg);
                return Ok(Some(msg));
                
                // 许多 MS17-010 脚本会检查是否支持 NT LM 0.12
                // 这里我们暂时标记为可疑
                // println!("[?] Suspected MS17-010 (SMBv1 Open): {}", target);
            }
        }

        Ok(None)
    }
}
