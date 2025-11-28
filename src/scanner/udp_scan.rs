use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use crate::scanner::tcp_connect::PortState;
pub async fn scan_single_port(ip: IpAddr, port: u16, timeout_ms: u64) -> PortState {
    let addr = std::net::SocketAddr::new(ip, port);
    let timeout_duration = Duration::from_millis(timeout_ms);
    
    let mut backoff = 20;
    let bind_addr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = loop {
        match UdpSocket::bind(bind_addr).await {
            Ok(s) => break s,
            Err(e) => {
                let raw_err = e.raw_os_error().unwrap_or(0);
                if raw_err == 24 || raw_err == 10024 || raw_err == 99 || raw_err == 10048 || raw_err == 10049 {
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    backoff = (backoff * 2).min(1000);
                    continue;
                }
                // 记录权限错误或其他不可恢复的错误
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    eprintln!("警告: UDP 端口绑定失败 (权限不足)。请尝试以管理员/Root 身份运行。");
                } else {
                    // 仅在调试时显示其他错误，避免刷屏
                    // eprintln!("警告: UDP 端口绑定失败: {}", e);
                }
                return PortState::Filtered;
            }
        }
    };

    let payload = get_udp_payload(port);
    for _ in 0..3 {
        // 使用 send_to 而不是 connect + send，避免 socket 状态绑定导致错过来自其他 IP (如网关) 的 ICMP 错误
        // 虽然 UdpSocket::connect 主要是为了过滤，但在扫描场景下，无连接模式更健壮。
        let mut sent = false;
        for _ in 0..3 {
            match socket.send_to(payload, addr).await {
                Ok(_) => { sent = true; break; },
                Err(e) => {
                    let raw_err = e.raw_os_error().unwrap_or(0);
                    if raw_err == 105 || raw_err == 10055 { // Buffer full
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                    if e.kind() == std::io::ErrorKind::ConnectionRefused || e.kind() == std::io::ErrorKind::ConnectionReset {
                        return PortState::Closed;
                    }
                    break;
                }
            }
        }
        if !sent {
            return PortState::Filtered;
        }

        let mut buf = [0u8; 2048];
        let start = std::time::Instant::now();
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout_duration {
                break;
            }
            let remaining = timeout_duration.saturating_sub(elapsed);
            
            match timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, src_addr))) => {
                    if n > 0 {
                        // 验证源地址是否匹配
                        // 必须检查端口，防止高并发下收到其他任务的回包导致误报
                        // 特例：TFTP (69) 通常从随机端口回包，不需要匹配源端口
                        if src_addr.ip() == addr.ip() && (src_addr.port() == port || port == 69) {
                            return PortState::Open;
                        }
                    }
                },
                Ok(Err(e)) => {
                    if e.kind() == std::io::ErrorKind::ConnectionRefused || e.kind() == std::io::ErrorKind::ConnectionReset {
                        return PortState::Closed;
                    }
                    break; 
                }
                Err(_) => {
                    break;
                }
            }
        }
    }
    PortState::Filtered 
}
fn get_udp_payload(port: u16) -> &'static [u8] {
    match port {
        53 => {
            static DNS_PAYLOAD: [u8; 28] = [
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
                0x00, 0x01, 0x00, 0x01
            ];
            &DNS_PAYLOAD
        },
        123 => {
            static NTP_PAYLOAD: [u8; 48] = [
                0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ];
            &NTP_PAYLOAD
        },
        161 => {
            static SNMP_PAYLOAD: [u8; 43] = [
                0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa1, 0x1c, 0x02,
                0x04, 0x1b, 0xc8, 0x8f, 0x4e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06,
                0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00
            ];
            &SNMP_PAYLOAD
        },
        137 => {
            static NETBIOS_PAYLOAD: [u8; 50] = [
                0x81, 0xca, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ];
            &NETBIOS_PAYLOAD
        },
        5060 => {
            static SIP_PAYLOAD: &[u8] = b"OPTIONS sip:nm SIP/2.0\r\nTo: sip:nm\r\nFrom: sip:nm;tag=root\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK-nm\r\nContact: <sip:nm@nm>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
            SIP_PAYLOAD
        },
        69 => {
            static TFTP_PAYLOAD: [u8; 20] = [
                0x00, 0x01,
                0x72, 0x66, 0x63, 0x31, 0x33, 0x35, 0x30, 0x2e, 0x74, 0x78, 0x74, 0x00,
                0x6f, 0x63, 0x74, 0x65, 0x74, 0x00
            ];
            &TFTP_PAYLOAD
        },
        1194 => {
            static OPENVPN_PAYLOAD: [u8; 14] = [
                0x38,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
                0x00, 0x00, 0x00, 0x00
            ];
            &OPENVPN_PAYLOAD
        },
        11211 => { // Memcached
            static MEMCACHED_PAYLOAD: &[u8] = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n";
            MEMCACHED_PAYLOAD
        },
        1900 => { // SSDP
            static SSDP_PAYLOAD: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\n\r\n";
            SSDP_PAYLOAD
        },
        5353 => { // mDNS
            static MDNS_PAYLOAD: [u8; 12] = [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ];
            &MDNS_PAYLOAD
        },
        1434 => { // MSSQL Browser
            static MSSQL_PAYLOAD: &[u8] = b"\x02";
            MSSQL_PAYLOAD
        },
        67 => { // DHCP
            static DHCP_PAYLOAD: [u8; 204] = [
                0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0x39, 0x02, 0x05, 0xdc, 0xff
            ];
            &DHCP_PAYLOAD
        },
        111 => { // Portmapper
            static PORTMAP_PAYLOAD: [u8; 56] = [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02,
                0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ];
            &PORTMAP_PAYLOAD
        },
        5683 => { // CoAP
            static COAP_PAYLOAD: [u8; 4] = [0x40, 0x01, 0x00, 0x00];
            &COAP_PAYLOAD
        },
        500 => { // IKE (IPsec)
            static IKE_PAYLOAD: [u8; 28] = [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Initiator SPI
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Responder SPI
                0x01, // Next Payload: SA
                0x10, // Version: 1.0
                0x02, // Exchange Type: Identity Protection
                0x00, // Flags
                0x00, 0x00, 0x00, 0x00, // Message ID
                0x00, 0x00, 0x00, 0x1c  // Length: 28
            ];
            &IKE_PAYLOAD
        },
        1701 => { // L2TP
            static L2TP_PAYLOAD: [u8; 12] = [
                0xc8, 0x02, // Type/Length: Control Message
                0x00, 0x0c, // Length: 12
                0x00, 0x00, // Tunnel ID
                0x00, 0x00, // Session ID
                0x00, 0x00, // Ns
                0x00, 0x00  // Nr
            ];
            &L2TP_PAYLOAD
        },
        1604 => { // Citrix ICA
            static CITRIX_PAYLOAD: [u8; 30] = [
                0x1e, 0x00, 0x01, 0x30, 0x02, 0xfd, 0xa8, 0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ];
            &CITRIX_PAYLOAD
        },
        623 => { // IPMI (RMCP Ping)
            static IPMI_PAYLOAD: [u8; 12] = [
                0x06, 0x00, 0xff, 0x07, // RMCP Header
                0x00, 0x00, 0x00, 0x00, // ASF Message Header
                0x00, 0x00, 0x00, 0x00
            ];
            &IPMI_PAYLOAD
        },
        _ => {
            static DEFAULT_PAYLOAD: [u8; 4] = [0xbe, 0xef, 0xbe, 0xef];
            &DEFAULT_PAYLOAD
        }, 
    }
}