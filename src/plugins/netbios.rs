use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use std::time::Duration;
use tokio::time::timeout;

pub struct NetbiosPlugin;

#[async_trait]
impl ScanPlugin for NetbiosPlugin {
    fn name(&self) -> &str {
        "NetBIOS"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![139, 445] // 如果 TCP 139/445 开放，尝试 UDP 137 获取主机名
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Info
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        // 绑定随机端口
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = format!("{}:137", info.host);
        
        // NetBIOS Name Query for * (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
        let payload: [u8; 50] = [
            0x81, 0xca, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ];

        // 发送请求
        if socket.send_to(&payload, &target).await.is_err() {
            return Ok(None);
        }

        let mut buf = [0u8; 1024];
        // 等待响应
        if let Ok(Ok((n, _src))) = timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
            if n > 56 {
                // 解析 NetBIOS 响应
                // 响应格式通常包含 Number of Names (offset 56)
                let num_names = buf[56] as usize;
                let mut offset = 57;
                
                for _ in 0..num_names {
                    if offset + 18 > n { break; }
                    
                    // 每个名字 16 字节 + 2 字节标志
                    let name_bytes = &buf[offset..offset+15]; // 取前15字节
                    let type_byte = buf[offset+15];
                    
                    // 类型 0x20 (Server Service) 或 0x00 (Workstation Service) 通常是主机名
                    if type_byte == 0x20 || type_byte == 0x00 {
                        let name = String::from_utf8_lossy(name_bytes).trim().to_string();
                        if !name.is_empty() && name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                            let msg = format!("[+] NetBIOS: {:<15} | Hostname: {}", info.host, name);
                            println!("{}", msg);
                            return Ok(Some(msg));
                        }
                    }
                    offset += 18;
                }
            }
        }

        Ok(None)
    }
}
