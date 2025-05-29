import yara
import os
import sys
def load_rules(rule_file):
    try:
        return yara.compile(filepath=rule_file)
    except yara.SyntaxError as e:
        print(f"[!] YARA syntax error: {e}")
        sys.exit(1)
def scan_directory(directory, rules):
    print(f"[+] Scanning directory: {directory}")
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                matches = rules.match(filepath=full_path)
                if matches:
                    print(f"\n[!] Match found in file: {full_path}")
                    for match in matches:
                        print(f" - Rule matched: {match.rule}")
                        if match.meta:
                            print(f" - Meta info: {match.meta}")
            except Exception as e:
                print(f"[!] Error scanning {full_path}: {e}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rule_path = os.path.join(base_dir, "../rules/yara-rules.yar")
    target_dir = os.path.join(base_dir, "../app")

    if len(sys.argv) > 1:
        target_dir = sys.argv[1]

    if not os.path.exists(rule_path):
        print(f"[!] Rule file not found: {rule_path}")
        sys.exit(1)
    if not os.path.isdir(target_dir):
        print(f"[!] Target directory not found: {target_dir}")
        sys.exit(1)

    rules = load_rules(rule_path)
    scan_directory(target_dir, rules)
