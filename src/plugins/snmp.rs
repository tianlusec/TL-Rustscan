use super::{HostInfo, ScanPlugin, PluginType};
use super::dicts::COMMON_PASSWORDS;
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::UdpSocket;
use std::time::Duration;
use tokio::time::timeout;

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

        // 常见的 Community 列表 + 全局密码字典
        let mut communities = vec!["public", "private", "cisco", "manager"];
        communities.extend_from_slice(COMMON_PASSWORDS);

        for community in communities {
            // 构造 SNMP v2c GetRequest (sysDescr: 1.3.6.1.2.1.1.1.0)
            // ASN.1 BER 编码
            let mut payload = Vec::new();
            
            // Version: 1 (0x01)
            payload.extend_from_slice(&[0x02, 0x01, 0x01]);
            
            // Community
            payload.push(0x04); // OctetString
            encode_ber_length(community.len(), &mut payload);
            payload.extend_from_slice(community.as_bytes());

            // PDU (GetRequest: 0xA0)
            let mut pdu = Vec::new();
            // Request ID (random: 0x12345678)
            pdu.extend_from_slice(&[0x02, 0x04, 0x12, 0x34, 0x56, 0x78]);
            // Error Status: 0
            pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
            // Error Index: 0
            pdu.extend_from_slice(&[0x02, 0x01, 0x00]);
            
            // VarBindList
            let mut varbind_list = Vec::new();
            let mut varbind = Vec::new();
            // OID: 1.3.6.1.2.1.1.1.0 (iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0)
            // 编码: 06 08 2b 06 01 02 01 01 01 00
            varbind.extend_from_slice(&[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
            // Value: Null (05 00)
            varbind.extend_from_slice(&[0x05, 0x00]);

            // Wrap VarBind
            varbind_list.push(0x30);
            encode_ber_length(varbind.len(), &mut varbind_list);
            varbind_list.extend(varbind);

            // Wrap VarBindList
            pdu.push(0x30);
            encode_ber_length(varbind_list.len(), &mut pdu);
            pdu.extend(varbind_list);

            // Wrap PDU
            payload.push(0xa0);
            encode_ber_length(pdu.len(), &mut payload);
            payload.extend(pdu);

            // Wrap Full Sequence
            let mut final_packet = Vec::new();
            final_packet.push(0x30);
            encode_ber_length(payload.len(), &mut final_packet);
            final_packet.extend(payload);

            // 发送
            if socket.send_to(&final_packet, &target).await.is_err() {
                continue;
            }

            let mut buf = [0u8; 2048];
            if let Ok(Ok((n, _src))) = timeout(Duration::from_secs(1), socket.recv_from(&mut buf)).await {
                if n > 0 {
                    // 简单解析：查找 Community 后的字符串
                    // 响应通常包含 sysDescr 的值
                    // 我们简单地打印出来，或者尝试提取 ASCII 字符串
                    let resp_data = &buf[..n];
                    // 尝试提取可见字符作为描述
                    let desc = extract_ascii(resp_data);
                    if !desc.is_empty() {
                        let msg = format!("[+] SNMP Info: {}:161 | Community: {} | Info: {}", info.host, community, desc);
                        println!("{}", msg);
                        return Ok(Some(msg)); // 找到一个 Community 就停止
                    }
                }
            }
        }

        Ok(None)
    }
}

fn extract_ascii(data: &[u8]) -> String {
    // 简单的提取逻辑：过滤出连续的可打印字符
    // 实际 SNMP 解析比较复杂，这里为了轻量化做一个近似处理
    // 通常 sysDescr 在包的后半部分
    let mut result = String::new();
    let mut current_segment = String::new();
    
    for &b in data {
        if b >= 32 && b <= 126 {
            current_segment.push(b as char);
        } else {
            if current_segment.len() > 4 {
                // 过滤掉短的干扰字符，保留较长的描述
                // 排除 Community 本身
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
    // 检查最后一段
    if current_segment.len() > 4 && !["public", "private", "cisco", "manager"].contains(&current_segment.as_str()) {
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
        // bytes is LSB first, we need MSB first (Big Endian)
        for b in bytes.iter().rev() {
            buf.push(*b);
        }
    }
}
