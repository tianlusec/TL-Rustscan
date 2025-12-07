















use crate::output::PortResult;
use serde_json;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex;
use tracing::{debug, warn};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    
    JsonLines,
    
    Text,
    
    Csv,
}




pub struct StreamingOutput {
    
    writer: Arc<Mutex<BufWriter<File>>>,
    
    format: OutputFormat,
    
    buffer: Arc<Mutex<Vec<String>>>,
    
    buffer_limit: usize,
    
    stats: Arc<Mutex<OutputStats>>,
}


#[derive(Debug, Clone, Default)]
pub struct OutputStats {
    
    pub total_writes: u64,
    
    pub total_bytes: u64,
    
    pub batch_writes: u64,
    
    pub write_errors: u64,
}

impl OutputStats {
    
    pub fn format(&self) -> String {
        format!(
            "写入: {} 次 | 字节: {} | 批量: {} 次 | 错误: {}",
            self.total_writes, self.total_bytes, self.batch_writes, self.write_errors
        )
    }
}

impl StreamingOutput {
    
    
    
    
    
    
    
    
    
    pub async fn new(path: impl AsRef<Path>, format: OutputFormat) -> std::io::Result<Self> {
        let file = File::create(path).await?;
        let writer = BufWriter::new(file);
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            format,
            buffer: Arc::new(Mutex::new(Vec::new())),
            buffer_limit: 100, 
            stats: Arc::new(Mutex::new(OutputStats::default())),
        })
    }

    
    
    
    
    
    pub fn with_buffer_limit(mut self, limit: usize) -> Self {
        self.buffer_limit = limit;
        self
    }

    
    
    
    
    
    
    pub async fn write_port_result(&self, ip: &str, result: &PortResult) -> std::io::Result<()> {
        let line = match self.format {
            OutputFormat::JsonLines => {
                
                let json_obj = serde_json::json!({
                    "ip": ip,
                    "port": result.port,
                    "protocol": result.protocol,
                    "state": format!("{:?}", result.state),
                    "banner": result.banner,
                    "dirs": result.dirs,
                });
                format!("{}\n", serde_json::to_string(&json_obj).unwrap_or_default())
            }
            OutputFormat::Text => {
                
                let banner_str = result.banner.as_deref().unwrap_or("N/A");
                format!(
                    "{}:{}/{} - {} - {}\n",
                    ip,
                    result.port,
                    result.protocol,
                    format!("{:?}", result.state),
                    banner_str
                )
            }
            OutputFormat::Csv => {
                
                let banner_str = result.banner.as_deref().unwrap_or("");
                let dirs_str = result.dirs.join(";");
                format!(
                    "{},{},{},{},{},{}\n",
                    ip,
                    result.port,
                    result.protocol,
                    format!("{:?}", result.state),
                    banner_str,
                    dirs_str
                )
            }
        };

        
        {
            let mut buffer = self.buffer.lock().await;
            buffer.push(line);

            
            if buffer.len() >= self.buffer_limit {
                self.flush_buffer(&mut buffer).await?;
            }
        }

        
        {
            let mut stats = self.stats.lock().await;
            stats.total_writes += 1;
        }

        Ok(())
    }

    
    
    
    
    
    
    
    pub async fn write_host_summary(
        &self,
        ip: &str,
        open_ports: usize,
        total_ports: usize,
    ) -> std::io::Result<()> {
        let line = match self.format {
            OutputFormat::JsonLines => {
                let json_obj = serde_json::json!({
                    "type": "summary",
                    "ip": ip,
                    "open_ports": open_ports,
                    "total_ports": total_ports,
                });
                format!("{}\n", serde_json::to_string(&json_obj).unwrap_or_default())
            }
            OutputFormat::Text => {
                format!("=== {} - {}/{} 端口开放 ===\n", ip, open_ports, total_ports)
            }
            OutputFormat::Csv => {
                format!("# Summary,{},{},{}\n", ip, open_ports, total_ports)
            }
        };

        
        let mut writer = self.writer.lock().await;
        writer.write_all(line.as_bytes()).await?;

        let mut stats = self.stats.lock().await;
        stats.total_bytes += line.len() as u64;
        Ok(())
    }

    
    
    
    pub async fn flush(&self) -> std::io::Result<()> {
        let mut buffer = self.buffer.lock().await;
        if !buffer.is_empty() {
            self.flush_buffer(&mut buffer).await?;
        }
        let mut writer = self.writer.lock().await;
        writer.flush().await?;

        Ok(())
    }

    
    async fn flush_buffer(&self, buffer: &mut Vec<String>) -> std::io::Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }

        let content = buffer.join("");
        let bytes = content.as_bytes();

        {
            let mut writer = self.writer.lock().await;
            match writer.write_all(bytes).await {
                Ok(_) => {
                    debug!("批量写入 {} 条记录，{} 字节", buffer.len(), bytes.len());

                    let mut stats = self.stats.lock().await;
                    stats.batch_writes += 1;
                    stats.total_bytes += bytes.len() as u64;
                }
                Err(e) => {
                    warn!("写入失败: {}", e);
                    let mut stats = self.stats.lock().await;
                    stats.write_errors += 1;
                    return Err(e);
                }
            }
        }

        buffer.clear();
        Ok(())
    }

    
    pub async fn get_stats(&self) -> OutputStats {
        self.stats.lock().await.clone()
    }

    
    pub async fn write_csv_header(&self) -> std::io::Result<()> {
        if self.format == OutputFormat::Csv {
            let header = "IP,Port,Protocol,State,Banner,Directories\n";
            let mut writer = self.writer.lock().await;
            writer.write_all(header.as_bytes()).await?;

            let mut stats = self.stats.lock().await;
            stats.total_bytes += header.len() as u64;
        }
        Ok(())
    }
}

impl Drop for StreamingOutput {
    fn drop(&mut self) {
        
        
        debug!("StreamingOutput被释放");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::tcp_connect::PortState;

    #[tokio::test]
    async fn test_streaming_output_json() {
        let temp_file = "test_output.jsonl";
        let output = StreamingOutput::new(temp_file, OutputFormat::JsonLines)
            .await
            .unwrap();

        let result = PortResult {
            port: 80,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            banner: Some("HTTP/1.1".to_string()),
            dirs: vec![],
        };

        output
            .write_port_result("192.168.1.1", &result)
            .await
            .unwrap();
        output.flush().await.unwrap();

        let stats = output.get_stats().await;
        assert_eq!(stats.total_writes, 1);
        assert!(stats.total_bytes > 0);

        
        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_streaming_output_text() {
        let temp_file = "test_output.txt";
        let output = StreamingOutput::new(temp_file, OutputFormat::Text)
            .await
            .unwrap();

        let result = PortResult {
            port: 443,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            banner: Some("HTTPS".to_string()),
            dirs: vec![],
        };

        output.write_port_result("10.0.0.1", &result).await.unwrap();
        output.flush().await.unwrap();

        
        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_buffer_flush() {
        let temp_file = "test_buffer.jsonl";
        let output = StreamingOutput::new(temp_file, OutputFormat::JsonLines)
            .await
            .unwrap()
            .with_buffer_limit(5);

        
        for i in 1..=5 {
            let result = PortResult {
                port: 80 + i,
                protocol: "tcp".to_string(),
                state: PortState::Open,
                banner: None,
                dirs: vec![],
            };
            output
                .write_port_result("192.168.1.1", &result)
                .await
                .unwrap();
        }

        let stats = output.get_stats().await;
        assert_eq!(stats.batch_writes, 1);

        output.flush().await.unwrap();

        
        let _ = tokio::fs::remove_file(temp_file).await;
    }
}
