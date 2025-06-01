import yara
import sys
import requests
import os

def load_rules(rule_file):
    try:
        return yara.compile(filepath=rule_file)
    except yara.SyntaxError as e:
        print(f"[!] YARA syntax error: {e}")
        sys.exit(1)

def scan_url(url, rules):
    print(f"[+] Fetching URL: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.content
        matches = rules.match(data=content)
        if matches:
            print(f"\n[!] Match found in URL content: {url}")
            for match in matches:
                print(f" - Rule matched: {match.rule}")
                if match.meta:
                    print(f" - Meta info: {match.meta}")
        else:
            print("[+] No matches found.")
    except requests.RequestException as e:
        print(f"[!] Error fetching URL {url}: {e}")

if __name__ == "__main__":
    url = "http://localhost:3000"

    # Calcule le chemin absolu du script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rule_path = os.path.join(base_dir, "rules.yar")

    if not os.path.exists(rule_path):
        print(f"[!] Rule file not found: {rule_path}")
        sys.exit(1)

    rules = load_rules(rule_path)
    scan_url(url, rules)
