import yara
import sys
import os

def load_rules(rule_file):
    try:
        return yara.compile(filepath=rule_file)
    except yara.SyntaxError as e:
        print(f"[!] YARA syntax error: {e}")
        sys.exit(1)

def scan_directory(directory, rules):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"[+] Scanning file: {file_path}")
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                matches = rules.match(data=content)
                if matches:
                    print(f"\n[!] Match found in file: {file_path}")
                    for match in matches:
                        print(f" - Rule matched: {match.rule}")
                        if match.meta:
                            print(f" - Meta info: {match.meta}")
                else:
                    print("[+] No matches found in this file.")
            except Exception as e:
                print(f"[!] Error reading file {file_path}: {e}")

if __name__ == "__main__":
    # Calcule le chemin absolu du script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rule_path = os.path.join(base_dir, "rules.yar")
    
    # Change l’URL en dossier à scanner
    directory_to_scan = os.path.join(base_dir, "../juiceshop")  

    if not os.path.exists(rule_path):
        print(f"[!] Rule file not found: {rule_path}")
        sys.exit(1)

    if not os.path.exists(directory_to_scan):
        print(f"[!] Directory to scan not found: {directory_to_scan}")
        sys.exit(1)

    rules = load_rules(rule_path)
    scan_directory(directory_to_scan, rules)
