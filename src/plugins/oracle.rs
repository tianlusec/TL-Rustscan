use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

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

        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await
        {
            let connect_data = format!(
                    "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={})(PORT={}))(CONNECT_DATA=(SERVICE_NAME=orcl)(CID=(PROGRAM=client)(HOST=client)(USER=client))))",
                    host, port
                );
            let connect_data_bytes = connect_data.as_bytes();
            let connect_data_len = connect_data_bytes.len();

            let packet_len = 58 + connect_data_len;
            if packet_len > u16::MAX as usize {
                return Ok(None);
            }

            let mut packet = Vec::new();
            packet.extend_from_slice(&(packet_len as u16).to_be_bytes());
            packet.extend_from_slice(&[0x00, 0x00]);
            packet.push(0x01);
            packet.push(0x00);
            packet.extend_from_slice(&[0x00, 0x00]);

            packet.extend_from_slice(&314u16.to_be_bytes());
            packet.extend_from_slice(&300u16.to_be_bytes());
            packet.extend_from_slice(&0x0c41u16.to_be_bytes());
            packet.extend_from_slice(&8192u16.to_be_bytes());
            packet.extend_from_slice(&32767u16.to_be_bytes());
            packet.extend_from_slice(&0x7f08u16.to_be_bytes());
            packet.extend_from_slice(&0x0000u16.to_be_bytes());
            packet.extend_from_slice(&0x0100u16.to_be_bytes());
            packet.extend_from_slice(&(connect_data_len as u16).to_be_bytes());
            packet.extend_from_slice(&58u16.to_be_bytes());
            packet.extend_from_slice(&2048u32.to_be_bytes());
            packet.push(0x41);
            packet.push(0x41);
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

            packet.extend_from_slice(connect_data_bytes);

            if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&packet))
                .await
                .is_err()
            {
                return Ok(None);
            }

            let mut buf = [0u8; 1024];
            let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) => n,
                _ => return Ok(None),
            };

            if n >= 8 {
                let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                let packet_type = buf[4];

                if len >= 8 && (packet_type == 2 || packet_type == 4) {
                    let msg = format!("[+] Oracle detected on {}", addr);
                    info!("{}", msg);
                    return Ok(Some(msg));
                }
            }
        }

        Ok(None)
    }
}
