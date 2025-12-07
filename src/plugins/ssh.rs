use super::dicts::{COMMON_PASSWORDS, COMMON_USERNAMES};
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use ssh2::Session;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use tracing::info;

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

        let result = tokio::task::spawn_blocking(move || {
            let socket_addrs = match target.to_socket_addrs() {
                Ok(addrs) => addrs,
                Err(_) => return None,
            };

            let mut tcp = None;
            for addr in socket_addrs.clone() {
                if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
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

            let mut sess = match Session::new() {
                Ok(s) => s,
                Err(_) => return None,
            };

            sess.set_tcp_stream(tcp_stream);
            if let Err(_) = sess.handshake() {
                return None;
            }

            for user in COMMON_USERNAMES {
                for pass in COMMON_PASSWORDS {
                    match sess.userauth_password(user, pass) {
                        Ok(_) => {
                            if sess.authenticated() {
                                let msg =
                                    format!("[+] SSH 弱口令: {} -> {}:{}", target, user, pass);
                                info!("{}", msg);
                                return Some(msg);
                            }
                        }
                        Err(_) => {
                            if let Ok(addrs) = target.to_socket_addrs() {
                                for addr in addrs {
                                    if let Ok(stream) =
                                        TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                                    {
                                        let _ =
                                            stream.set_read_timeout(Some(Duration::from_secs(5)));
                                        let _ =
                                            stream.set_write_timeout(Some(Duration::from_secs(5)));
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
        })
        .await?;

        Ok(result)
    }
}
