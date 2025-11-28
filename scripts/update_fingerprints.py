import json
import urllib.request
import re
import os
import sys
import xml.etree.ElementTree as ET
import zipfile
import io
import shutil

WAPPALYZER_URL = "https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json"
RECOG_URLS = [
    "https://raw.githubusercontent.com/rapid7/recog/master/xml/http_servers.xml",
    "https://raw.githubusercontent.com/rapid7/recog/master/xml/http_cookies.xml"
]
NUCLEI_ZIP_URL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"

OUTPUT_FILE = "fingerprints.json"

def download_url(url):
    print(f"[*] 正在从 {url} 下载...")
    try:
        req = urllib.request.Request(
            url, 
            data=None, 
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        with urllib.request.urlopen(req) as response:
            return response.read()
    except Exception as e:
        print(f"[!] 下载失败 {url}: {e}")
        return None

def is_valid_rust_regex(pattern):
    try:
        if '(?=' in pattern or '(?!' in pattern or '(?<=' in pattern or '(?<!' in pattern:
            return False
        
        if re.search(r'(?<!\\)\\[1-9]', pattern):
            return False

        if ";version:" in pattern:
             return False

        if re.search(r'\{,\d+\}', pattern):
            return False

        if "[^]" in pattern:
            return False

        if re.search(r'(?<!\\)\{(?:["a-zA-Z{])', pattern):
            return False

        re.compile(pattern)
        return True
    except re.error:
        return False

def clean_wappalyzer_pattern(pattern):
    if r"\;version:" in pattern:
        pattern = pattern.split(r"\;version:")[0]
    
    return pattern

def convert_to_internal_format(wappalyzer_data):
    internal_rules = []
    
    technologies = wappalyzer_data.get("technologies", {})
    
    for name, rules in technologies.items():
        def process_patterns(patterns, location):
            if not patterns:
                return
            if isinstance(patterns, str):
                patterns = [patterns]
            for pat in patterns:
                cleaned_pat = clean_wappalyzer_pattern(pat)
                if not cleaned_pat.startswith("(?i)"):
                    cleaned_pat = "(?i)" + cleaned_pat

                if is_valid_rust_regex(cleaned_pat):
                    internal_rules.append({
                        "name": name,
                        "match_mode": "regex",
                        "pattern": cleaned_pat,
                        "location": location
                    })

        if "html" in rules:
            process_patterns(rules["html"], "body")

        if "script" in rules:
             process_patterns(rules["script"], "body")
        
        if "headers" in rules:
            headers = rules["headers"]
            if headers:
                for header_name, header_val in headers.items():
                    if header_val:
                        pat = f"(?i){header_name}:.*{header_val}"
                        cleaned_pat = clean_wappalyzer_pattern(pat)
                        if is_valid_rust_regex(cleaned_pat):
                            internal_rules.append({
                                "name": name,
                                "match_mode": "regex",
                                "pattern": cleaned_pat,
                                "location": "header"
                            })
                    else:
                        internal_rules.append({
                            "name": name,
                            "match_mode": "keyword",
                            "pattern": header_name,
                            "location": "header"
                        })

        if "meta" in rules:
            metas = rules["meta"]
            if metas:
                for meta_name, meta_content in metas.items():
                    if meta_content:
                         pat = f"(?i)meta[^>]+name=[\"']{re.escape(meta_name)}[\"'][^>]+content=[\"'][^\"'>]*{meta_content}"
                         cleaned_pat = clean_wappalyzer_pattern(pat)
                         if is_valid_rust_regex(cleaned_pat):
                             internal_rules.append({
                                "name": name,
                                "match_mode": "regex",
                                "pattern": cleaned_pat,
                                "location": "body"
                            })

    return internal_rules

def convert_recog_to_internal(xml_content):
    rules = []
    if not xml_content:
        return rules
        
    try:
        root = ET.fromstring(xml_content)
        match_key = root.get("matches")
        
        location = None
        header_name = None
        
        if match_key == "http_header.server":
            location = "header"
            header_name = "Server"
        elif match_key == "http_header.set_cookie" or match_key == "http_header.cookie":
            location = "header"
            header_name = "Set-Cookie"
        elif match_key == "http_body":
            location = "body"
        
        if not location:
            return []

        for fp in root.findall("fingerprint"):
            pattern = fp.get("pattern")
            desc = fp.find("description")
            name = desc.text if desc is not None else "Unknown"
            
            if not pattern:
                continue
            
            final_pattern = pattern
            if location == "header" and header_name:
                if final_pattern.startswith("^"):
                    final_pattern = final_pattern[1:]
                if final_pattern.endswith("$"):
                    final_pattern = final_pattern[:-1]
                
                final_pattern = f"(?i){header_name}:\\s*.*{final_pattern}"
            
            if is_valid_rust_regex(final_pattern):
                rules.append({
                    "name": name,
                    "match_mode": "regex",
                    "pattern": final_pattern,
                    "location": location
                })
    except Exception as e:
        print(f"[!] 解析 Recog XML 失败: {e}")
    
    return rules

def parse_nuclei_yaml(content):
    rules = []
    try:
        id_match = re.search(r'^id:\s*(.+)$', content, re.MULTILINE)
        name_match = re.search(r'^\s+name:\s*(.+)$', content, re.MULTILINE)
        
        tech_name = name_match.group(1).strip().strip('"\'') if name_match else (id_match.group(1).strip() if id_match else "Unknown")
        
        matcher_blocks = re.split(r'\n\s*-\s*type:', content)
        
        for block in matcher_blocks[1:]:
            m_type = "word"
            if block.strip().startswith("regex"):
                m_type = "regex"
            elif block.strip().startswith("word"):
                m_type = "word"
            else:
                continue
            
            location = "body"
            if re.search(r'part:\s*header', block):
                location = "header"
            elif re.search(r'part:\s*body', block):
                location = "body"
            
            patterns = []
            if m_type == "regex":
                regex_lines = re.findall(r'^\s*-\s*[\'"]?(.+?)[\'"]?\s*$', block, re.MULTILINE)
                patterns = [p for p in regex_lines if not p.strip().endswith(':')]
            elif m_type == "word":
                word_lines = re.findall(r'^\s*-\s*[\'"](.+?)[\'"]\s*$', block, re.MULTILINE)
                patterns = [re.escape(w) for w in word_lines if not w.strip().endswith(':')]
            
            for pat in patterns:
                pat = pat.strip()
                if not pat.startswith("(?i)"):
                    pat = "(?i)" + pat
                
                if is_valid_rust_regex(pat):
                    rules.append({
                        "name": tech_name,
                        "match_mode": "regex",
                        "pattern": pat,
                        "location": location
                    })

    except Exception:
        pass
    return rules

def process_nuclei_zip(zip_bytes):
    rules = []
    if not zip_bytes:
        return rules
    
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for filename in z.namelist():
                if "http/technologies/" in filename and filename.endswith(".yaml"):
                    with z.open(filename) as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        rules.extend(parse_nuclei_yaml(content))
    except Exception as e:
        print(f"[!] 处理 Nuclei ZIP 失败: {e}")
    
    return rules

def main():
    new_rules = []

    wappalyzer_bytes = download_url(WAPPALYZER_URL)
    if wappalyzer_bytes:
        try:
            data = json.loads(wappalyzer_bytes.decode('utf-8'))
            new_rules.extend(convert_to_internal_format(data))
            print(f"[*] 从 Wappalyzer 转换了 {len(new_rules)} 条规则。")
        except Exception as e:
            print(f"[!] Wappalyzer JSON 解析失败: {e}")

    recog_count = 0
    for url in RECOG_URLS:
        xml_bytes = download_url(url)
        if xml_bytes:
            recog_rules = convert_recog_to_internal(xml_bytes.decode('utf-8'))
            new_rules.extend(recog_rules)
            recog_count += len(recog_rules)
    print(f"[*] 从 Recog 转换了 {recog_count} 条规则。")

    print(f"[*] 正在下载 Nuclei Templates (ZIP)... 这可能需要一点时间")
    nuclei_bytes = download_url(NUCLEI_ZIP_URL)
    if nuclei_bytes:
        nuclei_rules = process_nuclei_zip(nuclei_bytes)
        print(f"[*] 从 Nuclei 转换了 {len(nuclei_rules)} 条规则。")
        new_rules.extend(nuclei_rules)

    existing_rules = []
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                existing_rules = json.load(f)
            print(f"[*] 读取了 {len(existing_rules)} 条现有规则。")
        except:
            pass
    
    seen = set()
    final_rules = []
    
    for r in existing_rules:
        if r.get("match_mode") == "regex":
            if ";version:" in r["pattern"]:
                 r["pattern"] = clean_wappalyzer_pattern(r["pattern"])
            
            if not is_valid_rust_regex(r["pattern"]):
                print(f"[-] 移除无效的现有规则: {r['name']} - {r['pattern']}")
                continue

        key = (r['name'], r['pattern'], r['location'])
        if key not in seen:
            seen.add(key)
            final_rules.append(r)
            
    added_count = 0
    for r in new_rules:
        key = (r['name'], r['pattern'], r['location'])
        if key not in seen:
            seen.add(key)
            final_rules.append(r)
            added_count += 1

    print(f"[*] 新增了 {added_count} 条规则。")
    print(f"[*] 总计规则数: {len(final_rules)}")
    
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(final_rules, f, indent=2, ensure_ascii=False)
        print(f"[+] 成功保存至 {OUTPUT_FILE}")
    except Exception as e:
        print(f"[!] 保存文件失败: {e}")

if __name__ == "__main__":
    main()
