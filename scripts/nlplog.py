import pandas as pd
import re

SENSITIVE_PATTERNS = {
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "Password": r"(password|passwd|pwd)[=:]\s*['\"]?([^'\"]+)",
    "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
    "SQL Query": r"SELECT\s.*FROM\s.*WHERE\s.*=.*",
}

def scan_logs_for_leaks(log_df):
    leaks_found = False
    for index, row in log_df.iterrows():
        for category, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, str(row["message"]), re.IGNORECASE)
            if matches:
                leaks_found = True
                print(f"[!] Potential {category} leak in log entry (Timestamp: {row['timestamp']}):")
                print(f"  - Event: {row['event']}")
                print(f"  - Message: {row['message']}\n")
    return leaks_found

if __name__ == "__main__":
    print("[*] Scanning log.csv for sensitive data leaks...")
    
    try:
        # Read CSV log file
        log_df = pd.read_csv("logs/nlp.csv")
        
        # Check for leaks
        if not scan_logs_for_leaks(log_df):
            print("[+] No sensitive data leaks detected.")
    except FileNotFoundError:
        print("[!] Error: log.csv not found. Please provide a valid log file.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
