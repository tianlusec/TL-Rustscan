import os
import json
import urllib.request
import sys

# Ensure we can import import_fingerprints from the same directory
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

import import_fingerprints

URLS = [
    "https://raw.githubusercontent.com/EdgeSecurityTeam/EHole/main/finger.json",
    "https://raw.githubusercontent.com/0x727/FingerprintHub/main/web_fingerprint_v3.json"
]

def download_file(url, dest):
    print(f"Downloading {url}...")
    try:
        # Add User-Agent to avoid 403
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(dest, 'wb') as out_file:
            out_file.write(response.read())
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def main():
    base_path = import_fingerprints.BUILTIN_PATH
    print(f"Loading base fingerprints from {base_path}...")
    
    if os.path.exists(base_path):
        base_rules = import_fingerprints.load_json(base_path)
    else:
        print("Base fingerprints.json not found, starting empty.")
        base_rules = []
    
    current_rules = base_rules
    total_added = 0
    
    for i, url in enumerate(URLS):
        temp_path = os.path.join(current_dir, f"temp_finger_{i}.json")
        if download_file(url, temp_path):
            print(f"Merging {url}...")
            try:
                external_rules = import_fingerprints.load_json(temp_path)
                # merge_rules(builtin, external) -> returns (merged, added, skipped)
                # We treat current_rules as builtin
                merged, added, skipped = import_fingerprints.merge_rules(current_rules, external_rules)
                print(f"  -> Added {added} new rules (Skipped {skipped} invalid/duplicate items)")
                current_rules = merged
                total_added += added
            except Exception as e:
                print(f"Error merging {url}: {e}")
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            print(f"Skipping {url} due to download failure.")
            
    output_path = os.path.join(os.path.dirname(base_path), 'fingerprints1.json')
    
    print(f"\nTotal rules: {len(current_rules)}")
    print(f"Total added from external sources: {total_added}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(current_rules, f, indent=2, ensure_ascii=False)
    print(f"Saved merged fingerprints to {output_path}")

if __name__ == "__main__":
    main()
