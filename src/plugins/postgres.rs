use super::{HostInfo, ScanPlugin, PluginType};
use super::dicts::{COMMON_USERNAMES, COMMON_PASSWORDS};
use anyhow::Result;
use async_trait::async_trait;
use tokio_postgres::{NoTls, Config};
use std::time::Duration;

pub struct PostgresPlugin;

#[async_trait]
impl ScanPlugin for PostgresPlugin {
    fn name(&self) -> &str {
        "PostgreSQL"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![5432]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port: u16 = info.port.parse().unwrap_or(5432);

        // Postgres 默认用户通常是 postgres
        let users = if COMMON_USERNAMES.contains(&"postgres") {
            COMMON_USERNAMES.to_vec()
        } else {
            let mut u = vec!["postgres"];
            u.extend_from_slice(COMMON_USERNAMES);
            u
        };

        for user in users {
            for pass in COMMON_PASSWORDS {
                // 构造连接配置
                // 注意：Postgres 连接如果密码错误会返回 Error，如果超时也会返回 Error
                // 我们需要区分
                let mut config = Config::new();
                config.user(user);
                config.password(pass);
                config.host(&host);
                config.port(port);
                config.dbname("postgres");
                config.connect_timeout(Duration::from_secs(3));

                let connect_future = config.connect(NoTls);

                match tokio::time::timeout(Duration::from_secs(5), connect_future).await {
                    Ok(Ok((client, connection))) => {
                        // 连接成功，需要 spawn connection 才能让 client 工作
                        tokio::spawn(async move {
                            if let Err(_) = connection.await {
                                // connection error
                            }
                        });
                        
                        // 简单验证一下
                        if client.simple_query("SELECT 1").await.is_ok() {
                            let msg = format!("[+] PostgreSQL 弱口令: {}:{} -> {}:{}", host, port, user, pass);
                            println!("{}", msg);
                            return Ok(Some(msg));
                        }
                    },
                    Ok(Err(e)) => {
                        // 认证失败通常包含 "password authentication failed"
                        // 如果是连接错误（如端口未开放），则应该停止
                        let err_msg = e.to_string();
                        if !err_msg.contains("authentication failed") {
                            // 可能是网络问题，跳过后续尝试
                            return Ok(None);
                        }
                    },
                    Err(_) => return Ok(None), // 超时
                }
            }
        }

        Ok(None)
    }
}
