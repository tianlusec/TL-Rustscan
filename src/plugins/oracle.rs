use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;

pub struct OraclePlugin;

#[async_trait]
impl ScanPlugin for OraclePlugin {
    fn name(&self) -> &str {
        "Oracle"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![1521]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Info
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port = 1521;
        let addr = format!("{}:{}", host, port);

        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // Construct TNS Connect Packet
                // Based on Nmap tns.lua
                
                let connect_data = format!(
                    "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={})(PORT={}))(CONNECT_DATA=(SERVICE_NAME=orcl)(CID=(PROGRAM=client)(HOST=client)(USER=client))))",
                    host, port
                );
                let connect_data_bytes = connect_data.as_bytes();
                let connect_data_len = connect_data_bytes.len() as u16;

                // Header + Connect Payload fixed part size = 8 + 50 = 58 bytes
                // But Nmap says offset is 58.
                // Header is 8 bytes.
                // Payload fixed part:
                // Version (2) + Version Comp (2) + Options (2) + SDU (2) + TDU (2) + NT Proto (2) + Line Turn (2) + Value 1 (2) + Data Len (2) + Data Offset (2) + Max Data (4) + Flags (2) + Trace (8) + Trace Unique (8) = 46 bytes?
                // Let's count carefully from Nmap:
                // I2 (2) * 10 = 20 bytes
                // I4 (4) * 1 = 4 bytes
                // B (1) * 2 = 2 bytes
                // I4 (4) * 2 = 8 bytes
                // I8 (8) * 2 = 16 bytes
                // Total payload fixed: 20 + 4 + 2 + 8 + 16 = 50 bytes.
                // Header: 8 bytes.
                // Total offset to data: 58 bytes. Correct.

                let packet_len = 58 + connect_data_len;
                if packet_len > u16::MAX {
                    return Ok(None);
                }
                
                let mut packet = Vec::new();
                // Header
                packet.extend_from_slice(&(packet_len as u16).to_be_bytes()); // Length
                packet.extend_from_slice(&[0x00, 0x00]); // Packet Checksum
                packet.push(0x01); // Type: CONNECT
                packet.push(0x00); // Reserved
                packet.extend_from_slice(&[0x00, 0x00]); // Header Checksum

                // Payload
                packet.extend_from_slice(&314u16.to_be_bytes()); // Version (314)
                packet.extend_from_slice(&300u16.to_be_bytes()); // Version Compatible (300)
                packet.extend_from_slice(&0x0c41u16.to_be_bytes()); // Service Options
                packet.extend_from_slice(&8192u16.to_be_bytes()); // Session SDU
                packet.extend_from_slice(&32767u16.to_be_bytes()); // Max TDU
                packet.extend_from_slice(&0x7f08u16.to_be_bytes()); // NT Proto Characteristics
                packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Line Turnaround
                packet.extend_from_slice(&0x0100u16.to_be_bytes()); // Value of 1 in Hardware
                packet.extend_from_slice(&connect_data_len.to_be_bytes()); // Connect Data Length
                packet.extend_from_slice(&58u16.to_be_bytes()); // Connect Data Offset
                packet.extend_from_slice(&2048u32.to_be_bytes()); // Max Receivable Connect Data
                packet.push(0x41); // Flags 0
                packet.push(0x41); // Flags 1
                packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Trace Cross 1
                packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Trace Cross 2
                packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Trace Unique Connection ID
                packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Trace Unique Connection ID (Wait, Nmap has I8, I8. One is trace unique, one is 0?)
                // Nmap: self.trace_unique_conn, 0
                // So 8 bytes for trace unique, 8 bytes of 0.
                
                // Wait, my count above:
                // I2 * 10 = 20
                // I4 * 1 = 4
                // B * 2 = 2
                // I4 * 2 = 8
                // I8 * 2 = 16
                // Total 50.
                // My code:
                // 2 (Ver) + 2 (VerComp) + 2 (Opt) + 2 (SDU) + 2 (TDU) + 2 (NT) + 2 (Line) + 2 (Val1) + 2 (Len) + 2 (Off) = 20.
                // 4 (MaxRecv) = 4.
                // 1 (F0) + 1 (F1) = 2.
                // 4 (Trace1) + 4 (Trace2) = 8.
                // 8 (TraceUnique) + 8 (Zero) = 16.
                // Total 50. Correct.

                // Remove the extra 8 bytes I added in the comment above and fix the code
                // I added Trace Unique (8) and then another 8 bytes of 0.
                // Let's verify Nmap again:
                // self.trace_cross_1, self.trace_cross_2, self.trace_unique_conn, 0
                // I4, I4, I8, I8.
                // Yes.

                packet.extend_from_slice(connect_data_bytes);

                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&packet)).await.is_err() {
                    return Ok(None);
                }

                let mut buf = [0u8; 1024];
                let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    _ => return Ok(None),
                };

                if n >= 8 {
                    // Check TNS Header
                    // Length is first 2 bytes
                    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let packet_type = buf[4];

                    if len >= 8 && (packet_type == 2 || packet_type == 4) {
                        // Type 2 = ACCEPT, Type 4 = REFUSE
                        // Both indicate an Oracle listener is responding
                        let msg = format!("[+] Oracle detected on {}", addr);
                        println!("{}", msg);
                        return Ok(Some(msg));
                        
                        // If ACCEPT, we might extract version info, but for now detection is enough.
                        // REFUSE usually means SID not found, but still Oracle.
                    }
                }
            }
            _ => {}
        }

        Ok(None)
    }
}
