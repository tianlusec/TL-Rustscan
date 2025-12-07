pub mod dicts;
pub mod docker;
pub mod elasticsearch;
pub mod fcgi;
pub mod ftp;
pub mod jdwp;
pub mod ldap;
pub mod memcached;
pub mod mongodb;
pub mod ms17010;
pub mod mssql;
pub mod mysql;
pub mod netbios;
pub mod oracle;
pub mod postgres;
pub mod rdp;
pub mod redis;
pub mod smb;
pub mod snmp;
pub mod ssh;
pub mod telnet;
pub mod vnc;
pub mod web_fingerprints;
pub mod web_pocs;
pub mod webtitle;
pub mod zookeeper;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginType {
    Brute,
    Poc,
    Info,
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub host: String,
    pub port: String,
    pub url: String,
    pub infostr: Vec<String>,
    pub proxy: Option<String>,
}

#[async_trait]
pub trait ScanPlugin: Send + Sync {
    fn name(&self) -> &str;

    fn interested_ports(&self) -> Vec<u16>;

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>>;

    fn plugin_type(&self) -> PluginType;

    fn is_rscan_only(&self) -> bool {
        match self.plugin_type() {
            PluginType::Brute | PluginType::Poc => true,
            PluginType::Info => false,
        }
    }
}

pub struct PluginManager {
    plugins: Vec<Arc<dyn ScanPlugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        let mut pm = Self {
            plugins: Vec::new(),
        };
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

    pub fn get_plugins_for_port(&self, port: u16) -> Vec<Arc<dyn ScanPlugin>> {
        self.plugins
            .iter()
            .filter(|p| p.interested_ports().contains(&port) || p.interested_ports().is_empty())
            .cloned()
            .collect()
    }
}
