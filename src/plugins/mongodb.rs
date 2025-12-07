use super::dicts::{COMMON_PASSWORDS, COMMON_USERNAMES};
use super::{HostInfo, PluginType, ScanPlugin};
use anyhow::Result;
use async_trait::async_trait;
use mongodb::{
    options::{ClientOptions, Credential},
    Client,
};
use std::time::Duration;
use tracing::info;

pub struct MongodbPlugin;

#[async_trait]
impl ScanPlugin for MongodbPlugin {
    fn name(&self) -> &str {
        "MongoDB"
    }

    fn interested_ports(&self) -> Vec<u16> {
        vec![27017]
    }

    fn plugin_type(&self) -> PluginType {
        PluginType::Brute
    }

    async fn scan(&self, info: &HostInfo) -> Result<Option<String>> {
        let host = info.host.clone();
        let port = info.port.parse::<u16>().unwrap_or(27017);
        let target = format!("{}:{}", host, port);

        let mut options = ClientOptions::parse(format!("mongodb://{}:{}", host, port)).await?;
        options.connect_timeout = Some(Duration::from_secs(3));
        options.server_selection_timeout = Some(Duration::from_secs(3));

        if let Ok(client) = Client::with_options(options.clone()) {
            if client.list_database_names(None, None).await.is_ok() {
                let msg = format!("[+] MongoDB 未授权访问: {}", target);
                info!("{}", msg);
                return Ok(Some(msg));
            }
        }

        let users = if COMMON_USERNAMES.contains(&"admin") {
            COMMON_USERNAMES.to_vec()
        } else {
            let mut u = vec!["admin"];
            u.extend_from_slice(COMMON_USERNAMES);
            u
        };

        for user in users {
            for pass in COMMON_PASSWORDS {
                let credential = Credential::builder()
                    .username(user.to_string())
                    .password(pass.to_string())
                    .source("admin".to_string())
                    .build();

                let mut auth_options = options.clone();
                auth_options.credential = Some(credential);

                if let Ok(client) = Client::with_options(auth_options) {
                    if client.list_database_names(None, None).await.is_ok() {
                        let msg = format!("[+] MongoDB 弱口令: {} -> {}:{}", target, user, pass);
                        info!("{}", msg);
                        return Ok(Some(msg));
                    }
                }
            }
        }

        Ok(None)
    }
}
