
import json
import re
import sys
import os
import time

BUILTIN_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fingerprints.json')

ALLOWED_MATCH_MODES = {'keyword', 'regex'}
ALLOWED_LOCATIONS = {'body', 'header', 'title', 'banner'}

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


def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
        if isinstance(data, dict) and "fingerprint" in data:
            return data["fingerprint"]
        
        if isinstance(data, list):
            return data
        return []

def validate_rule(r):
    
    
    
    
    name = r.get('cms') or r.get('name')
    method = r.get('method') or r.get('match_mode')
    location = r.get('location')
    
    pattern = r.get('keyword') or r.get('pattern')

    
    if name and not method and not location:
        rules_to_add = []
        
        
        if pattern and isinstance(pattern, list):
            for p in pattern:
                rules_to_add.append({
                    'name': name,
                    'match_mode': 'keyword',
                    'location': 'body',
                    'pattern': p
                })
        
        
        headers = r.get('headers')
        if headers and isinstance(headers, dict):
            for k, v in headers.items():
                
                
                
                
                if v:
                    regex = f"(?i){re.escape(k)}:.*{re.escape(v)}"
                    rules_to_add.append({
                        'name': name,
                        'match_mode': 'regex',
                        'location': 'header',
                        'pattern': regex
                    })
        
        if rules_to_add:
            return True, '', rules_to_add
    

    if not all((name, method, location, pattern)):
        return False, 'missing_field', None

    
    method = method.lower()
    if method == 'icon_hash':
        
        return False, 'unsupported_method_icon_hash', None
    
    if method not in ALLOWED_MATCH_MODES:
        return False, f'invalid_match_mode_{method}', None

    
    location = location.lower()
    if location not in ALLOWED_LOCATIONS:
        return False, f'invalid_location_{location}', None

    
    rules_to_add = []
    if isinstance(pattern, list):
        for p in pattern:
            rules_to_add.append({
                'name': name,
                'match_mode': method,
                'location': location,
                'pattern': p
            })
    else:
        rules_to_add.append({
            'name': name,
            'match_mode': method,
            'location': location,
            'pattern': pattern
        })

    
    valid_rules = []
    for rule in rules_to_add:
        if rule['match_mode'] == 'regex':
            if not is_valid_rust_regex(rule['pattern']):
                continue 
        valid_rules.append(rule)
    
    if not valid_rules:
        return False, 'no_valid_patterns', None

    return True, '', valid_rules


def merge_rules(builtin, external):
    seen = set()
    final = []
    
    for r in builtin:
        key = (r.get('name'), r.get('pattern'), r.get('location'))
        if key not in seen:
            seen.add(key)
            final.append(r)
    
    added = 0
    skipped_count = 0
    
    for r in external:
        ok, reason, normalized_rules = validate_rule(r)
        if not ok:
            skipped_count += 1
            continue
        
        for rule in normalized_rules:
            
            if rule['match_mode'] == 'keyword':
                rule['pattern'] = rule['pattern'].lower()
            
            key = (rule['name'], rule['pattern'], rule['location'])
            if key in seen:
                continue
            seen.add(key)
            final.append(rule)
            added += 1
            
    return final, added, skipped_count


def backup_file(path):
    if not os.path.exists(path):
        return None
    ts = time.strftime('%Y%m%d%H%M%S')
    bak = f"{path}.bak.{ts}"
    os.rename(path, bak)
    return bak


def main():
    if len(sys.argv) != 2:
        print('Usage: python scripts/import_fingerprints.py <external_json_path>')
        sys.exit(2)
    external_path = sys.argv[1]
    if not os.path.exists(external_path):
        print(f'External file not found: {external_path}')
        sys.exit(2)

    if not os.path.exists(BUILTIN_PATH):
        print(f'Built-in fingerprints not found at expected path: {BUILTIN_PATH}')
        sys.exit(1)

    try:
        builtin = load_json(BUILTIN_PATH)
    except Exception as e:
        print(f'Failed to load built-in fingerprints: {e}')
        sys.exit(1)

    try:
        external = load_json(external_path)
    except Exception as e:
        print(f'Failed to load external fingerprints: {e}')
        sys.exit(1)

    merged, added, skipped = merge_rules(builtin, external)
    print(f'Existing rules: {len(builtin)}, external source items: {len(external)}, added new rules: {added}, skipped source items: {skipped}')
    
    
    bak = backup_file(BUILTIN_PATH)
    if bak:
        print(f'Backed up builtin fingerprints to: {bak}')
    try:
        with open(BUILTIN_PATH, 'w', encoding='utf-8') as f:
            json.dump(merged, f, indent=2, ensure_ascii=False)
        print(f'Merged fingerprints written to {BUILTIN_PATH}')
    except Exception as e:
        print(f'Failed to write merged fingerprints: {e}')
        
        if bak and os.path.exists(bak):
            os.rename(bak, BUILTIN_PATH)
            print('Restored original built-in fingerprints from backup')
        sys.exit(1)

if __name__ == '__main__':
    main()
