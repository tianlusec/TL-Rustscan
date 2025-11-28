use super::{HostInfo, ScanPlugin, PluginType};
use super::dicts::{COMMON_USERNAMES, COMMON_PASSWORDS};
use anyhow::Result;
use async_trait::async_trait;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use ssh2::Session;

pub struct SshPlugin;

#[async_trait]
impl ScanPlugin for SshPlugin {
    fn name(&self) -> &str {
        "SSH"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![22, 2222]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let target_host = info.host.clone();
        let target_port = info.port.clone();
        let target = format!("{}:{}", target_host, target_port);

        // SSH 连接和认证是阻塞操作，放入 blocking 线程池
        let result = tokio::task::spawn_blocking(move || {
            // 1. 尝试建立 TCP 连接
            let socket_addrs = match target.to_socket_addrs() {
                Ok(addrs) => addrs,
                Err(_) => return None,
            };

            let mut tcp = None;
            for addr in socket_addrs.clone() {
                if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                    // 设置 Socket 读写超时，防止蜜罐或网络异常导致线程永久阻塞
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    tcp = Some(stream);
                    break;
                }
            }

            let tcp_stream = match tcp {
                Some(s) => s,
                None => return None,
            };

            // 2. 建立 SSH 会话
            let mut sess = match Session::new() {
                Ok(s) => s,
                Err(_) => return None,
            };
            
            sess.set_tcp_stream(tcp_stream);
            if let Err(_) = sess.handshake() {
                return None;
            }

            // 3. 尝试爆破
            for user in COMMON_USERNAMES {
                for pass in COMMON_PASSWORDS {
                    // 尝试密码认证
                    match sess.userauth_password(user, pass) {
                        Ok(_) => {
                            if sess.authenticated() {
                                let msg = format!("[+] SSH 弱口令: {} -> {}:{}", target, user, pass);
                                println!("{}", msg);
                                return Some(msg);
                            }
                        },
                        Err(_) => {
                            // 如果认证失败，检查是否需要重连
                            // 简单判断：如果 handshake 失败或者 authenticated 抛错，说明连接断了
                            // 这里我们采取激进策略：如果 userauth 失败，我们尝试发送一个简单的 keepalive 或检查 error
                            // 但 ssh2 api 有限。
                            // 最稳妥的方式：如果认证失败，我们假设连接可能断开，尝试重新建立连接
                            // 为了避免每次都重连（太慢），我们可以只在连续失败 N 次后重连，或者捕获特定错误
                            // 但 libssh2 的错误码在 Rust 绑定中不明显。
                            // 既然是高并发扫描，我们宁可慢一点也要准。
                            // 重新连接逻辑：
                            
                            // 尝试创建一个新会话来测试连接是否存活？不，直接重连最稳。
                            // 但每次重连太慢了。
                            // 优化：仅当 sess.authenticated() 调用失败（即 socket 错误）时重连？
                            // 不，userauth_password 返回 Err 可能是密码错误，也可能是网络错误。
                            
                            // 让我们尝试重新连接，如果重连失败则彻底放弃
                            if let Ok(addrs) = target.to_socket_addrs() {
                                for addr in addrs {
                                    if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                                        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                                        if let Ok(mut new_sess) = Session::new() {
                                            new_sess.set_tcp_stream(stream);
                                            if new_sess.handshake().is_ok() {
                                                sess = new_sess;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            None
        }).await?;

        Ok(result)
    }
}
