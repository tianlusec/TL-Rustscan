use super::{HostInfo, ScanPlugin, PluginType};
use super::dicts::{COMMON_USERNAMES, COMMON_PASSWORDS};
use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

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
        
        // 简单的连接测试，如果连接成功，尝试爆破
        // Telnet 爆破比较复杂，需要处理 IAC 协商和 Prompt 识别
        // 这里实现一个基础的状态机

        for user in COMMON_USERNAMES {
            for pass in COMMON_PASSWORDS {
                if try_telnet_login(&target, user, pass).await {
                    let msg = format!("[+] Telnet 弱口令: {} -> {}:{}", target, user, pass);
                    println!("{}", msg);
                    return Ok(Some(msg));
                }
            }
        }
        
        Ok(None)
    }
}

async fn try_telnet_login(addr: &str, user: &str, pass: &str) -> bool {
    let mut stream = match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return false,
    };

    let mut buffer = [0u8; 2048];
    let mut stage = 0; // 0: Wait Login, 1: Wait Password, 2: Check Success

    // 简单的交互循环
    // 最多交互 5 次
    for _ in 0..5 {
        let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return false,
        };

        // 处理 IAC (Interpret As Command)
        // Telnet 命令以 0xFF (IAC) 开头，通常是 3 字节序列 (IAC, CMD, OPT)
        // 我们简单地过滤掉它们，或者直接在字符串中查找关键词
        // 为了简化，我们直接转字符串并忽略乱码
        let response = String::from_utf8_lossy(&buffer[..n]);
        let response_lower = response.to_lowercase();

        // 简单的状态机
        if stage == 0 {
            if response_lower.contains("login") || response_lower.contains("user") || response_lower.contains("name:") {
                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(format!("{}\r\n", user).as_bytes())).await.is_err() { return false; }
                stage = 1;
            }
        } else if stage == 1 {
            if response_lower.contains("password") || response_lower.contains("pass") {
                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(format!("{}\r\n", pass).as_bytes())).await.is_err() { return false; }
                stage = 2;
            }
        } else if stage == 2 {
            // 登录成功特征：
            // 1. 出现 Shell 提示符 ($, #, >)
            // 2. 没有 "incorrect", "fail", "denied" 等错误词
            if (response.contains('$') || response.contains('#') || response.contains('>')) 
                && !response_lower.contains("incorrect") 
                && !response_lower.contains("fail") 
                && !response_lower.contains("denied") 
                && !response_lower.contains("login") { // 防止循环回到 login
                return true;
            }
            // 如果收到 "Login incorrect" 之类的，直接返回 false
            if response_lower.contains("incorrect") || response_lower.contains("fail") {
                return false;
            }
        }
    }

    false
}
