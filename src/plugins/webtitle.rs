use super::{HostInfo, ScanPlugin, PluginType};
use super::web_fingerprints;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::time::Duration;
use regex::Regex;
use std::sync::OnceLock;

pub struct WebTitlePlugin;

static TITLE_REGEX: OnceLock<Regex> = OnceLock::new();

#[async_trait]
impl ScanPlugin for WebTitlePlugin {
    fn name(&self) -> &str {
        "WebTitle"
    }

    fn interested_ports(&self) -> Vec<u16> {
        // fscan 关注的常见 Web 端口
        vec![
            80, 81, 443, 7001, 8000, 8001, 8008, 8080, 8081, 
            8443, 8888, 9000, 9001, 9043, 9090, 9200, 9443
        ]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Info
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        // 配置 HTTP 客户端：忽略证书错误，设置超时
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3)) // 允许少量重定向
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()?;

        // 智能判断协议：如果是 443/8443 等端口优先尝试 HTTPS，否则优先 HTTP
        let port_int: u16 = info.port.parse().unwrap_or(80);
        let schemes = if [443, 8443, 9443].contains(&port_int) {
            vec!["https", "http"]
        } else {
            vec!["http", "https"]
        };

        for scheme in schemes {
            let url = format!("{}://{}:{}", scheme, info.host, info.port);
            
            // 发送请求
            if let Ok(mut resp) = client.get(&url).send().await {
                let status = resp.status();
                let headers = resp.headers().clone();
                
                // 修复: 限制读取 Body 大小，防止 OOM
                // 读取 Body (Max 1MB)
                let mut body_bytes = Vec::new();
                let limit = 1024 * 1024; // 1MB

                while let Ok(Some(chunk)) = resp.chunk().await {
                    if body_bytes.len() + chunk.len() > limit {
                        body_bytes.extend_from_slice(&chunk[..limit - body_bytes.len()]);
                        break;
                    }
                    body_bytes.extend_from_slice(&chunk);
                }

                if !body_bytes.is_empty() {
                    // 尝试将 Body 转为字符串 (lossy 转换，忽略错误字符)
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    
                    // 使用正则提取 <title>
                    let re = TITLE_REGEX.get_or_init(|| Regex::new(r"(?i)<title>(.*?)</title>").unwrap());
                    let title = if let Some(caps) = re.captures(&body_str) {
                        caps.get(1).map_or("No Title", |m| m.as_str().trim())
                    } else {
                        "No Title"
                    };

                    // 指纹识别
                    let fingers = web_fingerprints::detect(&headers, &body_str);
                    let finger_str = if fingers.is_empty() {
                        String::new()
                    } else {
                        format!(" | Finger: [{}]", fingers.join(", "))
                    };

                    // 只有当获取到有效标题或状态码为 200 时才输出，减少干扰
                    if title != "No Title" || status.is_success() {
                        let msg = format!("[+] WebTitle: {:<25} | Code: {:<3} | Title: {}{}", url, status.as_u16(), title, finger_str);
                        println!("{}", msg);
                        return Ok(Some(msg)); // 成功获取一个协议的标题后就停止，避免重复输出
                    }
                }
            }
        }

        Ok(None)
    }
}
