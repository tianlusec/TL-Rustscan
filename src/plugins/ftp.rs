use super::dicts::{COMMON_PASSWORDS, COMMON_USERNAMES};
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

        let mut stream =
            match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target)).await {
                Ok(Ok(s)) => s,
                _ => return Ok(None),
            };

        let mut buffer = [0u8; 1024];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await
        {
            if n == 0 || !buffer[..n].starts_with(b"220") {
                return Ok(None); 
            }
        } else {
            return Ok(None);
        }

        if try_login(&mut stream, "anonymous", "anonymous").await {
            let msg = format!("[+] FTP 匿名登录: {}", target);
            println!("{}", msg);
            return Ok(Some(msg));
        }

        for user in COMMON_USERNAMES {
            for pass in COMMON_PASSWORDS {
                let mut stream =
                    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&target))
                        .await
                    {
                        Ok(Ok(s)) => s,
                        _ => continue,
                    };
                let _ =
                    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await;

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

    if tokio::time::timeout(
        Duration::from_secs(3),
        stream.write_all(format!("USER {}\r\n", user).as_bytes()),
    )
    .await
    .is_err()
    {
        return false;
    }

    let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };
    if n == 0 || !buffer[..n].starts_with(b"331") {
        return false;
    }

    if tokio::time::timeout(
        Duration::from_secs(3),
        stream.write_all(format!("PASS {}\r\n", pass).as_bytes()),
    )
    .await
    .is_err()
    {
        return false;
    }

    let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        _ => return false,
    };

    if n > 0 && buffer[..n].starts_with(b"230") {
        return true;
    }
    false
}
