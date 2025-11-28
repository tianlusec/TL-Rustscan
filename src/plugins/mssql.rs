use super::{HostInfo, ScanPlugin, PluginType};
use super::dicts::{COMMON_USERNAMES, COMMON_PASSWORDS};
use anyhow::Result;
use async_trait::async_trait;
use tiberius::{Config, Client, AuthMethod};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use std::time::Duration;

pub struct MssqlPlugin;

#[async_trait]
impl ScanPlugin for MssqlPlugin {
    fn name(&self) -> &str {
        "MSSQL"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![1433]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port: u16 = info.port.parse().unwrap_or(1433);

        // MSSQL 爆破
        // 由于 tiberius 是异步的，我们可以直接在 async fn 中运行，不需要 spawn_blocking
        // 但为了控制并发和超时，我们还是小心处理
        
        // 针对 MSSQL，常用的用户名通常是 sa
        let users = if COMMON_USERNAMES.contains(&"sa") {
            COMMON_USERNAMES.to_vec()
        } else {
            let mut u = vec!["sa"];
            u.extend_from_slice(COMMON_USERNAMES);
            u
        };

        for user in users {
            for pass in COMMON_PASSWORDS {
                let mut config = Config::new();
                config.host(&host);
                config.port(port);
                config.authentication(AuthMethod::sql_server(user, pass));
                config.trust_cert(); // 忽略证书

                // 建立 TCP 连接
                let tcp = match tokio::time::timeout(
                    Duration::from_secs(3),
                    TcpStream::connect(format!("{}:{}", host, port))
                ).await {
                    Ok(Ok(s)) => s,
                    _ => return Ok(None), // 连接失败直接退出当前 host 的扫描
                };

                // 建立 TDS 连接
                // tiberius 需要 compat 层
                let tcp = tcp.compat_write();
                
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    Client::connect(config, tcp)
                ).await {
                    Ok(Ok(_)) => {
                        let msg = format!("[+] MSSQL 弱口令: {}:{} -> {}:{}", host, port, user, pass);
                        println!("{}", msg);
                        return Ok(Some(msg));
                    },
                    _ => continue,
                }
            }
        }

        Ok(None)
    }
}
