use super::{HostInfo, ScanPlugin, PluginType};
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;

pub struct LdapPlugin;

#[async_trait]
impl ScanPlugin for LdapPlugin {
    fn name(&self) -> &str {
        "LDAP"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![389]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Poc
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let addr = format!("{}:389", info.host);
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                // Construct LDAP Simple Bind Request (Anonymous)
                // Sequence {
                //   Integer(1) // MessageID
                //   Application(0) { // BindRequest
                //     Integer(3) // Version 3
                //     OctetString("") // Name (Anonymous)
                //     ContextSpecific(0) { // Simple Auth
                //       OctetString("") // Password
                //     }
                //   }
                // }
                // Hex: 30 0c 02 01 01 60 07 02 01 03 04 00 80 00
                let bind_req = [
                    0x30, 0x0c, 
                    0x02, 0x01, 0x01, 
                    0x60, 0x07, 
                    0x02, 0x01, 0x03, 
                    0x04, 0x00, 
                    0x80, 0x00
                ];

                if tokio::time::timeout(Duration::from_secs(3), stream.write_all(&bind_req)).await.is_err() {
                    return Ok(None);
                }

                let mut buf = [0u8; 1024];
                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
                    if n > 0 {
                        // Check for BindResponse
                        // Sequence (0x30) ... Application(1) (0x61) ...
                        // 0x61 is BindResponse
                        if buf[0] == 0x30 {
                            // Simple check for 0x61 inside
                            // Usually 30 xx 02 01 01 61 ...
                            if n > 5 && buf[5] == 0x61 {
                                let msg = format!("[+] LDAP Service detected on {}", addr);
                                println!("{}", msg);
                                
                                // Check Result Code in BindResponse
                                // BindResponse ::= [APPLICATION 1] SEQUENCE {
                                //      resultCode ENUMERATED { success(0), ... },
                                //      ...
                                // }
                                // 61 xx 0a 01 00 (Success)
                                // Let's look for 0a 01 00
                                for i in 0..n-2 {
                                    if buf[i] == 0x0a && buf[i+1] == 0x01 && buf[i+2] == 0x00 {
                                        let msg2 = format!("[+] LDAP Anonymous Bind Allowed on {}", addr);
                                        println!("{}", msg2);
                                        return Ok(Some(format!("{}\n{}", msg, msg2)));
                                    }
                                }
                                return Ok(Some(msg));
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
