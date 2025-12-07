use super::dicts::COMMON_PASSWORDS;
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::info;

pub struct SnmpPlugin;

#[async_trait]
impl ScanPlugin for SnmpPlugin {
    fn name(&self) -> &str {
        "SNMP"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![161]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = format!("{}:161", info.host);

        let mut communities = vec!["public", "private", "cisco", "manager"];
        communities.extend_from_slice(COMMON_PASSWORDS);

        for community in communities {
            let mut payload = Vec::new();

            payload.extend_from_slice(&[0x02, 0x01, 0x01]);

            payload.push(0x04);
            encode_ber_length(community.len(), &mut payload);
            payload.extend_from_slice(community.as_bytes());

            let mut pdu = Vec::new();
            pdu.extend_from_slice(&[0x02, 0x04, 0x12, 0x34, 0x56, 0x78]);
            pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
            pdu.extend_from_slice(&[0x02, 0x01, 0x00]);

            let mut varbind_list = Vec::new();
            let mut varbind = Vec::new();
            varbind
                .extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
            varbind.extend_from_slice(&[0x05, 0x00]);

            varbind_list.push(0x30);
            encode_ber_length(varbind.len(), &mut varbind_list);
            varbind_list.extend(varbind);

            pdu.push(0x30);
            encode_ber_length(varbind_list.len(), &mut pdu);
            pdu.extend(varbind_list);

            payload.push(0xa0);
            encode_ber_length(pdu.len(), &mut payload);
            payload.extend(pdu);

            let mut final_packet = Vec::new();
            final_packet.push(0x30);
            encode_ber_length(payload.len(), &mut final_packet);
            final_packet.extend(payload);

            if socket.send_to(&final_packet, &target).await.is_err() {
                continue;
            }

            let mut buf = [0u8; 2048];
            if let Ok(Ok((n, _src))) =
                timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await
            {
                if n > 0 {
                    let resp_data = &buf[..n];
                    let desc = extract_ascii(resp_data);
                    if !desc.is_empty() {
                        let msg = format!(
                            "[+] SNMP Info: {}:161 | Community: {} | Info: {}",
                            info.host, community, desc
                        );
                        info!("{}", msg);
                        return Ok(Some(msg));
                    }
                }
            }
        }

        Ok(None)
    }
}

fn extract_ascii(data: &[u8]) -> String {
    let mut result = String::new();
    let mut current_segment = String::new();

    for &b in data {
        if b >= 32 && b <= 126 {
            current_segment.push(b as char);
        } else {
            if current_segment.len() > 4 {
                if !["public", "private", "cisco", "manager"].contains(&current_segment.as_str()) {
                    if !result.is_empty() {
                        result.push_str(" | ");
                    }
                    result.push_str(&current_segment);
                }
            }
            current_segment.clear();
        }
    }
    if current_segment.len() > 4
        && !["public", "private", "cisco", "manager"].contains(&current_segment.as_str())
    {
        if !result.is_empty() {
            result.push_str(" | ");
        }
        result.push_str(&current_segment);
    }

    result
}

fn encode_ber_length(len: usize, buf: &mut Vec<u8>) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let mut temp = len;
        let mut bytes = Vec::new();
        while temp > 0 {
            bytes.push((temp & 0xFF) as u8);
            temp >>= 8;
        }
        buf.push(0x80 | bytes.len() as u8);
        for b in bytes.iter().rev() {
            buf.push(*b);
        }
    }
}
