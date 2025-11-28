pub mod redis;
pub mod webtitle;
pub mod ssh;
pub mod mysql;
pub mod ms17010;
pub mod ftp;
pub mod memcached;
pub mod mongodb;
pub mod elasticsearch;
pub mod zookeeper;
pub mod docker;
pub mod telnet;
pub mod mssql;
pub mod postgres;
pub mod dicts;
pub mod web_fingerprints;
pub mod web_pocs;
pub mod netbios;
pub mod snmp;
pub mod rdp;
pub mod smb;
pub mod oracle;
pub mod fcgi;
pub mod vnc;
pub mod ldap;
pub mod jdwp;

use std::sync::Arc;
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginType {
    Brute, // 弱口令爆破
    Poc,   // 漏洞检测
    Info,  // 信息收集 (WebTitle, NetBIOS)
}

// 对应 fscan Common/Types.go 中的 HostInfo
#[derive(Debug, Clone)]
pub struct HostInfo {
    pub host: String,
    pub port: String, // fscan 使用 string 存储端口
    pub url: String,
    pub infostr: Vec<String>,
}

// 对应 fscan Common/Types.go 中的 ScanPlugin
// 在 Rust 中我们使用 Trait 来定义接口
#[async_trait]
pub trait ScanPlugin: Send + Sync {
    // 插件名称
    fn name(&self) -> &str;
    
    // 适用端口，对应 fscan 的 Ports []int
    fn interested_ports(&self) -> Vec<u16>;
    
    // 扫描逻辑，对应 fscan 的 ScanFunc
    // 修改返回值，允许返回漏洞信息字符串
    async fn scan(&self, info: &HostInfo) -> Result<Option<String>>;

    // 插件类型
    fn plugin_type(&self) -> PluginType;

    // 是否为 rscan 专属功能 (默认为 true)
    // 如果为 true，则只有在开启 --rscan 时才会运行
    // 如果为 false，则默认运行 (如 WebTitle)
    fn is_rscan_only(&self) -> bool {
        match self.plugin_type() {
            PluginType::Brute | PluginType::Poc => true,
            PluginType::Info => false,
        }
    }
}

// 插件管理器，对应 fscan Core/Registry.go
pub struct PluginManager {
    plugins: Vec<Arc<dyn ScanPlugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        let mut pm = Self { plugins: Vec::new() };
        // 注册默认插件
        pm.register(Arc::new(redis::RedisPlugin));
        pm.register(Arc::new(webtitle::WebTitlePlugin));
        pm.register(Arc::new(ssh::SshPlugin));
        pm.register(Arc::new(mysql::MysqlPlugin));
        pm.register(Arc::new(ms17010::Ms17010Plugin));
        pm.register(Arc::new(ftp::FtpPlugin));
        pm.register(Arc::new(memcached::MemcachedPlugin));
        pm.register(Arc::new(mongodb::MongodbPlugin));
        pm.register(Arc::new(elasticsearch::ElasticsearchPlugin));
        pm.register(Arc::new(zookeeper::ZookeeperPlugin));
        pm.register(Arc::new(docker::DockerPlugin));
        pm.register(Arc::new(telnet::TelnetPlugin));
        pm.register(Arc::new(mssql::MssqlPlugin));
        pm.register(Arc::new(postgres::PostgresPlugin));
        pm.register(Arc::new(web_pocs::WebPocPlugin));
        pm.register(Arc::new(netbios::NetbiosPlugin));
        pm.register(Arc::new(snmp::SnmpPlugin));
        pm.register(Arc::new(rdp::RdpPlugin));
        #[cfg(target_os = "windows")]
        pm.register(Arc::new(smb::SmbPlugin));
        pm.register(Arc::new(oracle::OraclePlugin));
        pm.register(Arc::new(fcgi::FcgiPlugin));
        pm.register(Arc::new(vnc::VncPlugin));
        pm.register(Arc::new(ldap::LdapPlugin));
        pm.register(Arc::new(jdwp::JdwpPlugin));
        pm
    }

    pub fn register(&mut self, plugin: Arc<dyn ScanPlugin>) {
        self.plugins.push(plugin);
    }

    // 根据端口获取合适的插件
    pub fn get_plugins_for_port(&self, port: u16) -> Vec<Arc<dyn ScanPlugin>> {
        self.plugins
            .iter()
            .filter(|p| p.interested_ports().contains(&port) || p.interested_ports().is_empty())
            .cloned()
            .collect()
    }
}
