



use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;


#[derive(Serialize, Deserialize)]
pub struct Checkpoint {
    
    pub scanned_targets: HashSet<(String, u16)>,
    
    pub timestamp: u64,
}

impl Checkpoint {
    
    pub fn new() -> Self {
        Self {
            scanned_targets: HashSet::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    
    
    pub fn save(&self, path: &Path) -> Result<(), std::io::Error> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
    
    
    pub fn is_scanned(&self, target: &str, port: u16) -> bool {
        self.scanned_targets.contains(&(target.to_string(), port))
    }
    
    
    pub fn mark_scanned(&mut self, target: &str, port: u16) {
        self.scanned_targets.insert((target.to_string(), port));
    }
    
    
    pub fn scanned_count(&self) -> usize {
        self.scanned_targets.len()
    }
}

impl Default for Checkpoint {
    fn default() -> Self {
        Self::new()
    }
}
