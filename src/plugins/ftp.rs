use super::{HostInfo, ScanPlugin, PluginType};
use super::dicts::{COMMON_USERNAMES, COMMON_PASSWORDS};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

pub struct FtpPlugin;

#[async_trait]
impl ScanPlugin for FtpPlugin {
    fn name(&self) -> &str {
        "FTP"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![21]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let target = format!("{}:{}", info.host, info.port);
        
        // 1. 建立连接
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&target)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        // 2. 读取欢迎 Banner
        let mut buffer = [0u8; 1024];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            if n == 0 || !buffer[..n].starts_with(b"220") {
                return Ok(None); // 不是 FTP 服务
            }
        } else {
            return Ok(None);
        }

        // 3. 尝试匿名登录
        if try_login(&mut stream, "anonymous", "anonymous").await {
            let msg = format!("[+] FTP 匿名登录: {}", target);
            println!("{}", msg);
            return Ok(Some(msg));
        }

        // 4. 尝试弱口令爆破
        // 使用全局字典进行爆破
        for user in COMMON_USERNAMES {
            for pass in COMMON_PASSWORDS {
                // 每次都需要重新连接，因为 FTP 登录失败通常会断开或需要重置状态
                let mut stream = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target)).await {
                    Ok(Ok(s)) => s,
                    _ => continue,
                };
                // 读 Banner
                let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;

                if try_login(&mut stream, user, pass).await {
                    let msg = format!("[+] FTP 弱口令: {} -> {}:{}", target, user, pass);
                    println!("{}", msg);
                    return Ok(Some(msg));
                }
            }
        }

        Ok(None)
    }
}

async fn try_login(stream: &mut TcpStream, user: &str, pass: &str) -> bool {
    let mut buffer = [0u8; 1024];

    // 发送 USER
    if tokio::time::timeout(Duration::from_secs(3), stream.write_all(format!("USER {}\r\n", user).as_bytes())).await.is_err() { return false; }
    
    // 修复: 增加超时控制
    let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    if n == 0 || !buffer[..n].starts_with(b"331") { return false; }

    // 发送 PASS
    if tokio::time::timeout(Duration::from_secs(3), stream.write_all(format!("PASS {}\r\n", pass).as_bytes())).await.is_err() { return false; }
    
    // 修复: 增加超时控制
    let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    
    if n > 0 && buffer[..n].starts_with(b"230") {
        return true;
    }
    false
}
