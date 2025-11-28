use serde::Deserialize;
use serde::de::Error as SerdeError;
use std::sync::OnceLock;
use regex::Regex;
use std::path::PathBuf;
use std::fs;
use aho_corasick::AhoCorasick;

#[derive(Debug, Deserialize, Clone)]
pub struct Fingerprint {
    pub name: String,
    pub match_mode: MatchMode,
    pub pattern: String,
    pub location: MatchLocation,
}

#[derive(Debug, Clone)]
pub struct CompiledFingerprint {
    pub name: String,
    pub match_mode: MatchMode,
    pub pattern: String,
    pub location: MatchLocation,
    pub regex: Option<Regex>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    Keyword,
    Regex,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum MatchLocation {
    Body,
    Header,
    Title,
    Banner,
    FaviconHash,
}

#[derive(Debug, Clone)]
pub struct FingerprintDatabase {
    pub regex_rules: Vec<CompiledFingerprint>,
    
    pub keyword_rules_body: Vec<CompiledFingerprint>,
    pub keyword_rules_header: Vec<CompiledFingerprint>,
    pub keyword_rules_title: Vec<CompiledFingerprint>,
    pub keyword_rules_banner: Vec<CompiledFingerprint>,
    pub favicon_rules: std::collections::HashMap<i32, String>,

    pub ac_body: Option<AhoCorasick>,
    pub ac_header: Option<AhoCorasick>,
    pub ac_title: Option<AhoCorasick>,
    pub ac_banner: Option<AhoCorasick>,
}

static DB: OnceLock<FingerprintDatabase> = OnceLock::new();

impl FingerprintDatabase {
    pub fn init(path: Option<PathBuf>) -> Result<(), String> {
        let db = if let Some(p) = path {
            let content = fs::read_to_string(&p).map_err(|e| format!("无法读取指纹文件 {:?}: {}", p, e))?;
            Self::load_from_str(&content).map_err(|e| format!("解析指纹文件失败: {}", e))?
        } else {
            // 优先尝试加载可执行文件所在目录下的 fingerprints.json
            let mut target_path = None;
            if let Ok(exe_path) = std::env::current_exe() {
                if let Some(exe_dir) = exe_path.parent() {
                    let p = exe_dir.join("fingerprints.json");
                    if p.exists() {
                        target_path = Some(p);
                    }
                }
            }
            
            // 如果 exe 目录下没有，再尝试当前工作目录
            if target_path.is_none() {
                let p = std::env::current_dir().unwrap_or_default().join("fingerprints.json");
                if p.exists() {
                    target_path = Some(p);
                }
            }

            if let Some(path) = target_path {
                eprintln!("[*] 自动加载外部指纹库: {:?}", path);
                let content = fs::read_to_string(&path).map_err(|e| format!("无法读取本地指纹文件: {}", e))?;
                Self::load_from_str(&content).map_err(|e| format!("解析本地指纹文件失败: {}", e))?
            } else {
                Self::load_default()
            }
        };
        let _ = DB.set(db);
        Ok(())
    }

    pub fn dump_default_to_file(path: &PathBuf) -> std::io::Result<()> {
        let json = include_str!("../../fingerprints.json");
        fs::write(path, json)
    }

    fn load_default() -> FingerprintDatabase {
        let json = include_str!("../../fingerprints.json");
        match Self::load_from_str(json) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("错误: 内置指纹库解析失败: {}", e);
                eprintln!("请检查 fingerprints.json 的格式是否正确。");
                std::process::exit(1);
            }
        }
    }

    fn load_from_str(json: &str) -> Result<FingerprintDatabase, serde_json::Error> {
        let raw_rules: Vec<Fingerprint> = serde_json::from_str(json)?;
        
        let mut regex_rules = Vec::new();
        let mut keyword_rules_body = Vec::new();
        let mut keyword_rules_header = Vec::new();
        let mut keyword_rules_title = Vec::new();
        let mut keyword_rules_banner = Vec::new();
        let mut favicon_rules = std::collections::HashMap::new();

        let mut skipped_count = 0;

        for mut r in raw_rules {
            // 过滤无效或过于通用的规则
            let p_lower = r.pattern.to_lowercase();
            let name_lower = r.name.to_lowercase();
            
            // 1. 过滤过于通用的模式
            if r.pattern.trim().is_empty() 
                || p_lower.contains("text/html") 
                || p_lower == "<html" 
                || p_lower == "<body"
                || p_lower == "index.jsp"
                || p_lower.contains("(v[0-9.]+)")
                || p_lower.contains("(v[0-9a-z-_.]+)")
                || p_lower.contains("v=([^\"]+)")
                || p_lower == "default"
                || p_lower == "my_id"
                || p_lower == "root_url"
                || p_lower == "ok"
                || p_lower == "text/plain"
                || p_lower == "documentation"
                || p_lower == "user"
                || p_lower == "admin"
                || p_lower == "login"
                || p_lower == "error"
                || p_lower == "json"
                || p_lower == "xml"
                || p_lower == "script"
                || p_lower == "style"
                || p_lower == "link"
                || p_lower == "meta"
                || p_lower == "div"
                || p_lower == "span"
                || p_lower == "可能原因"
                || p_lower == "没有找到站点"
                || p_lower == "入口校验失败"
                || p_lower == "[^\\s]+"
                || p_lower == "[0-9]+"
                || p_lower == "[a-z]+"
                || p_lower == ".*"
            {
                skipped_count += 1;
                continue;
            }

            // 2. 过滤特定的噪音指纹名称
            if name_lower.contains("wappalyzer technology detection")
                || name_lower.contains("mcp inspector detect")
                || name_lower.contains("kubelet healthz")
                || name_lower.contains("graphql apollo detect")
                || name_lower.contains("graphql ariadne detect")
                || name_lower.contains("graphql graphene detect")
                || name_lower.contains("graphql hasura detect")
                || name_lower.contains("graphql sangria detect")
                || name_lower.contains("element web - detect")
                || name_lower.contains("detect redmine cli configuration file")
                || name_lower.contains("apache-axis-detect")
                || name_lower.contains("nginx with version info")
                || name_lower.contains("nginx without version info")
                || name_lower.contains("symfony default page")
                || name_lower == "nginx" // 仅过滤纯 "Nginx" 名称，保留具体的 Nginx 模块或版本指纹
            {
                skipped_count += 1;
                continue;
            }

            // 3. 过滤过于短的关键词 (除非是 FaviconHash)
            if r.location != MatchLocation::FaviconHash && r.match_mode == MatchMode::Keyword && r.pattern.len() < 4 {
                skipped_count += 1;
                continue;
            }

            if r.location == MatchLocation::FaviconHash {
                if let Ok(hash) = r.pattern.parse::<i32>() {
                    favicon_rules.insert(hash, r.name);
                }
                continue;
            }

            let regex = if r.match_mode == MatchMode::Regex {
                regex::RegexBuilder::new(&r.pattern)
                    .case_insensitive(true)
                    .size_limit(10 * 1024 * 1024) // 10MB limit to prevent DoS
                    .build()
                    .ok()
            } else {
                r.pattern = r.pattern.to_lowercase();
                None
            };
            
            let compiled = CompiledFingerprint {
                name: r.name,
                match_mode: r.match_mode.clone(),
                pattern: r.pattern.clone(),
                location: r.location.clone(),
                regex,
            };

            if compiled.match_mode == MatchMode::Regex {
                regex_rules.push(compiled);
            } else {
                match compiled.location {
                    MatchLocation::Body => keyword_rules_body.push(compiled),
                    MatchLocation::Header => keyword_rules_header.push(compiled),
                    MatchLocation::Title => keyword_rules_title.push(compiled),
                    MatchLocation::Banner => keyword_rules_banner.push(compiled),
                    _ => {}
                }
            }
        }

        if skipped_count > 0 {
            // 仅在调试模式或 verbose 模式下显示，或者只显示一次
            // eprintln!("[*] 已过滤 {} 条过于通用的指纹规则", skipped_count);
        }

        let ac_body = if !keyword_rules_body.is_empty() {
            Some(AhoCorasick::new(keyword_rules_body.iter().map(|r| &r.pattern)).map_err(|e| serde_json::Error::custom(format!("Failed to build AC automaton for body: {}", e)))?)
        } else { None };

        let ac_header = if !keyword_rules_header.is_empty() {
            Some(AhoCorasick::new(keyword_rules_header.iter().map(|r| &r.pattern)).map_err(|e| serde_json::Error::custom(format!("Failed to build AC automaton for header: {}", e)))?)
        } else { None };

        let ac_title = if !keyword_rules_title.is_empty() {
            Some(AhoCorasick::new(keyword_rules_title.iter().map(|r| &r.pattern)).map_err(|e| serde_json::Error::custom(format!("Failed to build AC automaton for title: {}", e)))?)
        } else { None };

        let ac_banner = if !keyword_rules_banner.is_empty() {
            Some(AhoCorasick::new(keyword_rules_banner.iter().map(|r| &r.pattern)).map_err(|e| serde_json::Error::custom(format!("Failed to build AC automaton for banner: {}", e)))?)
        } else { None };

        Ok(FingerprintDatabase { 
            regex_rules,
            keyword_rules_body,
            keyword_rules_header,
            keyword_rules_title,
            keyword_rules_banner,
            favicon_rules,
            ac_body,
            ac_header,
            ac_title,
            ac_banner,
        })
    }

    pub fn global() -> &'static FingerprintDatabase {
        DB.get_or_init(|| {
            Self::load_default()
        })
    }

    pub fn match_favicon(&self, hash: i32) -> Option<String> {
        self.favicon_rules.get(&hash).cloned()
    }

    pub fn match_http(&self, body: &str, headers: &str, title: &str) -> Vec<String> {
        let mut matches = Vec::new();
        
        let body_lower = body.to_lowercase();
        let headers_lower = headers.to_lowercase();
        let title_lower = title.to_lowercase();

        // 1. Keyword Matching (Aho-Corasick) - O(N)
        if let Some(ac) = &self.ac_body {
            for mat in ac.find_iter(&body_lower) {
                matches.push(self.keyword_rules_body[mat.pattern()].name.clone());
            }
        }
        if let Some(ac) = &self.ac_header {
            for mat in ac.find_iter(&headers_lower) {
                matches.push(self.keyword_rules_header[mat.pattern()].name.clone());
            }
        }
        if let Some(ac) = &self.ac_title {
            for mat in ac.find_iter(&title_lower) {
                matches.push(self.keyword_rules_title[mat.pattern()].name.clone());
            }
        }

        // 2. Regex Matching - O(M * N)
        for rule in &self.regex_rules {
            let target_text = match rule.location {
                MatchLocation::Body => body,
                MatchLocation::Header => headers,
                MatchLocation::Title => title,
                MatchLocation::Banner => continue,
                MatchLocation::FaviconHash => continue,
            };

            if let Some(re) = &rule.regex {
                if re.is_match(target_text) {
                    matches.push(rule.name.clone());
                }
            }
        }
        matches
    }

    pub fn match_service_banner(&self, banner: &str) -> Option<String> {
        let banner_lower = banner.to_lowercase();
        
        // Keyword
        if let Some(ac) = &self.ac_banner {
            if let Some(mat) = ac.find(&banner_lower) {
                return Some(self.keyword_rules_banner[mat.pattern()].name.clone());
            }
        }

        // Regex
        for rule in &self.regex_rules {
            if rule.location != MatchLocation::Banner {
                continue;
            }
            if let Some(re) = &rule.regex {
                if re.is_match(banner) {
                    return Some(rule.name.clone());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn validate_all_fingerprints() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("fingerprints.json");
        
        if !path.exists() {
            println!("Skipping test: fingerprints.json not found at {:?}", path);
            return;
        }

        let content = std::fs::read_to_string(&path).expect("Failed to read fingerprints.json");
        let raw_rules: Vec<Fingerprint> = serde_json::from_str(&content).expect("Failed to parse JSON");
        
        let mut failed_count = 0;
        for rule in raw_rules {
            if rule.match_mode == MatchMode::Regex {
                if let Err(e) = Regex::new(&rule.pattern) {
                    println!("\n[INVALID REGEX] Name: {}", rule.name);
                    println!("Pattern: {}", rule.pattern);
                    println!("Error: {}", e);
                    failed_count += 1;
                }
            }
        }

        if failed_count > 0 {
            panic!("Found {} invalid regexes in fingerprints.json. Please fix them.", failed_count);
        } else {
            println!("All regexes in fingerprints.json are valid!");
        }
    }
}
