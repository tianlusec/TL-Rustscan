use super::dicts;
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct RedisPlugin;

#[async_trait]
impl ScanPlugin for RedisPlugin {
    fn name(&self) -> &str {
        "Redis"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![6379]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let target = format!("{}:{}", info.host, info.port);

        let timeout = Duration::from_secs(3);
        let stream_result = tokio::time::timeout(timeout, TcpStream::connect(&target)).await;

        let mut stream = match stream_result {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        if tokio::time::timeout(timeout, stream.write_all(b"INFO\r\n"))
            .await
            .is_err()
        {
            return Ok(None);
        }

        let mut buffer = [0; 1024];
        let read_result = tokio::time::timeout(timeout, stream.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(n)) if n > 0 => {
                let response = String::from_utf8_lossy(&buffer[..n]);
                if response.contains("redis_version") {
                    let msg = format!("[+] Redis 未授权访问: {}", target);
                    info!("{}", msg);
                    return Ok(Some(msg));
                } else if response.contains("NOAUTH") {
                    let passwords = dicts::COMMON_PASSWORDS;
                    let start_time = std::time::Instant::now();
                    let max_duration = Duration::from_secs(60);

                    for pass in passwords {
                        if start_time.elapsed() > max_duration {
                            break;
                        }
                        let auth_cmd = format!("AUTH {}\r\n", pass);
                        let write_result =
                            tokio::time::timeout(timeout, stream.write_all(auth_cmd.as_bytes()))
                                .await;

                        let is_write_err = match &write_result {
                            Ok(Ok(_)) => false,
                            _ => true,
                        };

                        if is_write_err {
                            if let Ok(Ok(s)) =
                                tokio::time::timeout(timeout, TcpStream::connect(&target)).await
                            {
                                stream = s;
                                let _ = tokio::time::timeout(
                                    timeout,
                                    stream.write_all(auth_cmd.as_bytes()),
                                )
                                .await;
                            } else {
                                break;
                            }
                        }

                        let mut auth_buf = [0; 1024];
                        match tokio::time::timeout(timeout, stream.read(&mut auth_buf)).await {
                            Ok(Ok(m)) => {
                                let auth_resp = String::from_utf8_lossy(&auth_buf[..m]);
                                if auth_resp.contains("+OK") {
                                    let msg = format!("[+] Redis 弱口令: {} -> {}", target, pass);
                                    info!("{}", msg);
                                    return Ok(Some(msg));
                                }
                            }
                            _ => {
                                if let Ok(Ok(s)) =
                                    tokio::time::timeout(timeout, TcpStream::connect(&target)).await
                                {
                                    stream = s;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(None)
    }
}
