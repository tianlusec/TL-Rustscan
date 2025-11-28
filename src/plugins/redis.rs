use super::{HostInfo, ScanPlugin, PluginType};
use super::dicts;
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;

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
        // println!("正在扫描 Redis: {}", target);

        let timeout = Duration::from_secs(3);
        let stream_result = tokio::time::timeout(timeout, TcpStream::connect(&target)).await;

        let mut stream = match stream_result {
            Ok(Ok(s)) => s,
            _ => return Ok(None), // 连接失败或超时，直接返回
        };

        // 发送 INFO 命令
        if tokio::time::timeout(timeout, stream.write_all(b"INFO\r\n")).await.is_err() {
            return Ok(None);
        }

        let mut buffer = [0; 1024];
        let read_result = tokio::time::timeout(timeout, stream.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(n)) if n > 0 => {
                let response = String::from_utf8_lossy(&buffer[..n]);
                if response.contains("redis_version") {
                    let msg = format!("[+] Redis 未授权访问: {}", target);
                    println!("{}", msg);
                    return Ok(Some(msg));
                } else if response.contains("NOAUTH") {
                    // println!("[-] Redis 需要认证: {}", target);
                    // 开始爆破
                    let passwords = dicts::COMMON_PASSWORDS;
                    let start_time = std::time::Instant::now();
                    let max_duration = Duration::from_secs(60); // 限制最大爆破时间为 60 秒

                    for pass in passwords {
                        if start_time.elapsed() > max_duration {
                            break;
                        }
                        let auth_cmd = format!("AUTH {}\r\n", pass);
                        let write_result = tokio::time::timeout(timeout, stream.write_all(auth_cmd.as_bytes())).await;
                        
                        // 修复 unwrap panic: 如果超时，write_result 是 Err(Elapsed)，unwrap 会 panic
                        let is_write_err = match &write_result {
                            Ok(Ok(_)) => false,
                            _ => true,
                        };

                        if is_write_err {
                            // 如果连接断开，尝试重连
                            if let Ok(Ok(s)) = tokio::time::timeout(timeout, TcpStream::connect(&target)).await {
                                stream = s;
                                let _ = tokio::time::timeout(timeout, stream.write_all(auth_cmd.as_bytes())).await;
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
                                    println!("{}", msg);
                                    return Ok(Some(msg));
                                }
                            },
                            _ => {
                                // 读取超时或失败，协议可能错位，强制重连
                                if let Ok(Ok(s)) = tokio::time::timeout(timeout, TcpStream::connect(&target)).await {
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
