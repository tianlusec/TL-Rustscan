use std::collections::HashMap;
use std::sync::OnceLock;
static TCP_SERVICES: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
static UDP_SERVICES: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
fn init_tcp_services() -> HashMap<u16, &'static str> {
    let mut m = HashMap::new();
    m.insert(21, "ftp");
    m.insert(22, "ssh");
    m.insert(23, "telnet");
    m.insert(25, "smtp");
    m.insert(53, "domain");
    m.insert(80, "http");
    m.insert(81, "http-alt");
    m.insert(88, "kerberos-sec");
    m.insert(110, "pop3");
    m.insert(111, "rpcbind");
    m.insert(135, "msrpc");
    m.insert(139, "netbios-ssn");
    m.insert(143, "imap");
    m.insert(389, "ldap");
    m.insert(443, "https");
    m.insert(445, "microsoft-ds");
    m.insert(465, "smtps");
    m.insert(587, "submission");
    m.insert(636, "ldaps");
    m.insert(873, "rsync");
    m.insert(993, "imaps");
    m.insert(995, "pop3s");
    m.insert(1080, "socks");
    m.insert(1433, "ms-sql-s");
    m.insert(1521, "oracle");
    m.insert(2049, "nfs");
    m.insert(2181, "zookeeper");
    m.insert(2375, "docker");
    m.insert(3306, "mysql");
    m.insert(3389, "ms-wbt-server");
    m.insert(3690, "svn");
    m.insert(5432, "postgresql");
    m.insert(5672, "amqp");
    m.insert(5900, "vnc");
    m.insert(6379, "redis");
    m.insert(8000, "http-alt");
    m.insert(8080, "http-proxy");
    m.insert(8443, "https-alt");
    m.insert(9000, "cslistener");
    m.insert(9092, "kafka");
    m.insert(9200, "wap-wsp");
    m.insert(11211, "memcache");
    m.insert(27017, "mongod");
    m
}
fn init_udp_services() -> HashMap<u16, &'static str> {
    let mut m = HashMap::new();
    m.insert(53, "domain");
    m.insert(67, "dhcps");
    m.insert(68, "dhcpc");
    m.insert(69, "tftp");
    m.insert(123, "ntp");
    m.insert(137, "netbios-ns");
    m.insert(138, "netbios-dgm");
    m.insert(161, "snmp");
    m.insert(162, "snmptrap");
    m.insert(500, "isakmp");
    m.insert(514, "syslog");
    m.insert(520, "route");
    m.insert(1900, "upnp");
    m.insert(4500, "ipsec-nat-t");
    m.insert(5353, "mdns");
    m
}
pub fn get_service_name(port: u16, protocol: &str) -> Option<&'static str> {
    match protocol {
        "tcp" => TCP_SERVICES.get_or_init(init_tcp_services).get(&port).copied(),
        "udp" => UDP_SERVICES.get_or_init(init_udp_services).get(&port).copied(),
        _ => None,
    }
}