use crate::scanner::tcp_connect::PortState;
use crate::scanner::udp_config::UdpScanConfig;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

pub async fn scan_single_port(ip: IpAddr, port: u16, base_timeout_ms: u64) -> (PortState, Option<String>) {
    let addr = std::net::SocketAddr::new(ip, port);
    let config = UdpScanConfig::for_port(port);

    debug!(
        "UDP扫描 {}:{} - 配置: 重试{}次, 初始超时{}ms, 确认阈值{}",
        ip, port, config.max_retries, config.initial_timeout, config.confirmation_threshold
    );

    let mut backoff = 20;
    let bind_addr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = loop {
        match UdpSocket::bind(bind_addr).await {
            Ok(s) => break s,
            Err(e) => {
                let raw_err = e.raw_os_error().unwrap_or(0);
                if raw_err == 24
                    || raw_err == 10024
                    || raw_err == 99
                    || raw_err == 10048
                    || raw_err == 10049
                {
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    backoff = (backoff * 2).min(1000);
                    continue;
                }
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    warn!("UDP 端口绑定失败 (权限不足)。请尝试以管理员/Root 身份运行。");
                } else {
                }
                return (PortState::Filtered, None);
            }
        }
    };

    let payload = get_udp_payload(port);
    let mut success_count = 0;
    let mut timeout_count = 0;

    
    for attempt in 0..config.max_retries {
        let current_timeout = if config.adaptive {
            Duration::from_millis(config.timeout_for_attempt(attempt))
        } else {
            Duration::from_millis(base_timeout_ms)
        };

        debug!(
            "UDP扫描 {}:{} - 尝试 {}/{}, 超时 {}ms",
            ip,
            port,
            attempt + 1,
            config.max_retries,
            current_timeout.as_millis()
        );

        let mut sent = false;
        for send_attempt in 0..3 {
            match socket.send_to(payload, addr).await {
                Ok(_) => {
                    sent = true;
                    break;
                }
                Err(e) => {
                    let raw_err = e.raw_os_error().unwrap_or(0);
                    if raw_err == 105 || raw_err == 10055 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    if e.kind() == std::io::ErrorKind::ConnectionRefused
                        || e.kind() == std::io::ErrorKind::ConnectionReset
                    {
                        debug!("UDP扫描 {}:{} - 收到明确的端口关闭响应", ip, port);
                        return (PortState::Closed, None);
                    }
                    if send_attempt == 2 {
                        debug!("UDP扫描 {}:{} - 发送失败: {}", ip, port, e);
                    }
                    break;
                }
            }
        }

        if !sent {
            timeout_count += 1;
            continue;
        }

        let mut buf = [0u8; 2048];
        let start = std::time::Instant::now();
        let mut received_response = false;

        loop {
            let elapsed = start.elapsed();
            if elapsed >= current_timeout {
                break;
            }
            let remaining = current_timeout.saturating_sub(elapsed);

            match timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, src_addr))) => {
                    if n > 0 {
                        if src_addr.ip() == addr.ip() && (src_addr.port() == port || port == 69) {
                            success_count += 1;
                            received_response = true;
                            debug!("UDP扫描 {}:{} - 收到有效响应 ({}字节)", ip, port, n); 
                            if success_count >= config.confirmation_threshold {
                                debug!(
                                    "UDP扫描 {}:{} - 确认开放 (成功{}/{}次)",
                                    ip,
                                    port,
                                    success_count,
                                    attempt + 1
                                );
                                let banner = parse_udp_response(port, &buf[..n]);
                                return (PortState::Open, banner);
                            }
                            break;
                        } else {
                            debug!(
                                "UDP扫描 {}:{} - 收到来自 {} 的响应，忽略",
                                ip, port, src_addr
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    if e.kind() == std::io::ErrorKind::ConnectionRefused
                        || e.kind() == std::io::ErrorKind::ConnectionReset
                    {
                        debug!("UDP扫描 {}:{} - 收到ICMP端口不可达", ip, port);
                        return (PortState::Closed, None);
                    }
                    break;
                }
                Err(_) => {
                    timeout_count += 1;
                    break;
                }
            }
        }

        if !received_response && attempt < config.max_retries - 1 {
            let backoff_ms = config.backoff_for_attempt(attempt);
            debug!(
                "UDP扫描 {}:{} - 等待 {}ms 后重试",
                ip,
                port,
                backoff_ms
            );
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    if success_count > 0 {
        debug!(
            "UDP扫描 {}:{} - 判定为开放 (成功{}/{}次)",
            ip, port, success_count, config.max_retries
        );
        (PortState::Open, None)
    } else if timeout_count == config.max_retries {
        debug!("UDP扫描 {}:{} - 全部超时，判定为过滤", ip, port);
        (PortState::Filtered, None)
    } else {
        debug!("UDP扫描 {}:{} - 判定为过滤", ip, port);
        (PortState::Filtered, None)
    }
}

fn get_udp_payload(port: u16) -> &'static [u8] {
    match port {
        53 => {
            static DNS_PAYLOAD: [u8; 28] = [
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            ];
            &DNS_PAYLOAD
        }
        123 => {
            static NTP_PAYLOAD: [u8; 48] = [
                0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            &NTP_PAYLOAD
        }
        161 => {
            static SNMP_PAYLOAD: [u8; 43] = [
                0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa1,
                0x1c, 0x02, 0x04, 0x1b, 0xc8, 0x8f, 0x4e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
                0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05,
                0x00,
            ];
            &SNMP_PAYLOAD
        }
        137 => {
            static NETBIOS_PAYLOAD: [u8; 50] = [
                0x81, 0xca, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            &NETBIOS_PAYLOAD
        }
        5060 => {
            static SIP_PAYLOAD: &[u8] = b"OPTIONS sip:nm SIP/2.0\r\nTo: sip:nm\r\nFrom: sip:nm;tag=root\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK-nm\r\nContact: <sip:nm@nm>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
            SIP_PAYLOAD
        }
        69 => {
            static TFTP_PAYLOAD: [u8; 20] = [
                0x00, 0x01, 0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00,
                0x6f, 0x63, 0x74, 0x65, 0x74, 0x00,
            ];
            &TFTP_PAYLOAD
        }
        1194 => {
            static OPENVPN_PAYLOAD: [u8; 14] = [
                0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            &OPENVPN_PAYLOAD
        }
        11211 => {
            static MEMCACHED_PAYLOAD: &[u8] = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n";
            MEMCACHED_PAYLOAD
        }
        1900 => {
            static SSDP_PAYLOAD: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\n\r\n";
            SSDP_PAYLOAD
        }
        5353 => {
            static MDNS_PAYLOAD: [u8; 12] = [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            &MDNS_PAYLOAD
        }
        1434 => {
            static MSSQL_PAYLOAD: &[u8] = b"\x02";
            MSSQL_PAYLOAD
        }
        67 => {
            static DHCP_PAYLOAD: [u8; 204] = [
                0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
                0x35, 0x01, 0x01, 0x39, 0x02, 0x05, 0xdc, 0xff,
            ];
            &DHCP_PAYLOAD
        }
        111 => {
            static PORTMAP_PAYLOAD: [u8; 56] = [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            &PORTMAP_PAYLOAD
        }
        5683 => {
            static COAP_PAYLOAD: [u8; 4] = [0x40, 0x01, 0x00, 0x00];
            &COAP_PAYLOAD
        }
        500 => {
            static IKE_PAYLOAD: [u8; 28] = [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                0x01, 
                0x10, 
                0x02, 
                0x00, 
                0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x1c, 
            ];
            &IKE_PAYLOAD
        }
        1701 => {
            static L2TP_PAYLOAD: [u8; 12] = [
                0xc8, 0x02, 
                0x00, 0x0c, 
                0x00, 0x00, 
                0x00, 0x00, 
                0x00, 0x00, 
                0x00, 0x00, 
            ];
            &L2TP_PAYLOAD
        }
        1604 => {
            static CITRIX_PAYLOAD: [u8; 30] = [
                0x1e, 0x00, 0x01, 0x30, 0x02, 0xfd, 0xa8, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            &CITRIX_PAYLOAD
        }
        623 => {
            static IPMI_PAYLOAD: [u8; 12] = [
                0x06, 0x00, 0xff, 0x07, 
                0x00, 0x00, 0x00, 0x00, 
                0x00, 0x00, 0x00, 0x00,
            ];
            &IPMI_PAYLOAD
        }

        _ => {
            static DEFAULT_PAYLOAD: [u8; 4] = [0xbe, 0xef, 0xbe, 0xef];
            &DEFAULT_PAYLOAD
        }
    }
}

fn parse_udp_response(port: u16, data: &[u8]) -> Option<String> {
    match port {
        53 => Some("DNS".to_string()),
        123 => Some("NTP".to_string()),
        161 => Some("SNMP".to_string()),
        137 => Some("NetBIOS".to_string()),
        1900 => Some("SSDP".to_string()),
        _ => {
            if !data.is_empty() {
                let s = String::from_utf8_lossy(data);
                let clean = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect::<String>();
                if !clean.is_empty() {
                    return Some(clean);
                }
            }
            None
        }
    }
}
