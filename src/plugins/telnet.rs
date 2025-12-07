use super::dicts::{COMMON_PASSWORDS, COMMON_USERNAMES};
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

pub struct TelnetPlugin;

#[async_trait]
impl ScanPlugin for TelnetPlugin {
    fn name(&self) -> &str {
        "Telnet"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![23]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let target = format!("{}:{}", info.host, info.port);

        for user in COMMON_USERNAMES {
            for pass in COMMON_PASSWORDS {
                if try_telnet_login(&target, user, pass).await {
                    let msg = format!("[+] Telnet 弱口令: {} -> {}:{}", target, user, pass);
                    info!("{}", msg);
                    return Ok(Some(msg));
                }
            }
        }

        Ok(None)
    }
}

async fn try_telnet_login(addr: &str, user: &str, pass: &str) -> bool {
    let mut stream =
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

    let mut buffer = [0u8; 2048];
    let mut stage = 0;

    for _ in 0..5 {
        let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return false,
        };

        let response = String::from_utf8_lossy(&buffer[..n]);
        let response_lower = response.to_lowercase();

        if stage == 0 {
            if response_lower.contains("login")
                || response_lower.contains("user")
                || response_lower.contains("name:")
            {
                if tokio::time::timeout(
                    Duration::from_secs(3),
                    stream.write_all(format!("{}\r\n", user).as_bytes()),
                )
                .await
                .is_err()
                {
                    return false;
                }
                stage = 1;
            }
        } else if stage == 1 {
            if response_lower.contains("password") || response_lower.contains("pass") {
                if tokio::time::timeout(
                    Duration::from_secs(3),
                    stream.write_all(format!("{}\r\n", pass).as_bytes()),
                )
                .await
                .is_err()
                {
                    return false;
                }
                stage = 2;
            }
        } else if stage == 2 {
            if (response.contains('$') || response.contains('#') || response.contains('>'))
                && !response_lower.contains("incorrect")
                && !response_lower.contains("fail")
                && !response_lower.contains("denied")
                && !response_lower.contains("login")
            {
                return true;
            }
            if response_lower.contains("incorrect") || response_lower.contains("fail") {
                return false;
            }
        }
    }

    false
}
