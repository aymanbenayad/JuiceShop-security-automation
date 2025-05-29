import os
import re
import sys

# Suspicious SQL usage patterns in Python
sql_patterns = [
    r"(cursor|conn)\.execute\s*\(.*\+.*\)",             # SQL with +
    r"(cursor|conn)\.execute\s*\(f?\".*{.*}.*\"\)",     # f-string
    r"(cursor|conn)\.executemany\s*\(.*\+.*\)",         
    r"(cursor|conn)\.executemany\s*\(f?\".*{.*}.*\"\)", 
    r"\.format\s*\(",                                   # .format() used in SQL
]

report_file = "sqli_report.txt"
findings = []

def scan_python_files(directory="."):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for pattern in sql_patterns:
                            if re.search(pattern, line):
                                warning = f"[!] Possible SQLi in {filepath} at line {lineno}:\n    {line.strip()}"
                                print(warning)
                                findings.append(warning)

# Run scan
scan_python_files()

# Final report & exit
if findings:
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(findings))
    print(f"\n Report saved to: {report_file}")
    sys.exit(1)  # Fail the CI pipeline
else:
    print("\n No potential SQLi patterns found.")
    sys.exit(0)  # CI passes
