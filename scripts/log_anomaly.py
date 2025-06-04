import pandas as pd
import argparse
import os
import sys

def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['reason'] = ""

    df.loc[df['hour'].between(1, 5), 'reason'] += "Login between 1AM and 5AM; "
    
    sql_pattern = r"(('|--|;|=)|or\s+['\"]?1['\"]?\s*=\s*['\"]?1)"
    df.loc[df['user_id'].str.contains(sql_pattern, regex=True, case=False, na=False), 'reason'] += "Suspicious user_id (SQL injection); "

    anomalies = df[df['reason'] != ""].drop(columns='hour')
    anomalies['reason'] = anomalies['reason'].str.strip("; ")
    return anomalies

def main():
    parser = argparse.ArgumentParser(description="Log anomaly detection")
    parser.add_argument("--file", required=True, help="Path to CSV log file")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)

    df = pd.read_csv(args.file)
    if not {'timestamp', 'user_id', 'ip_address'}.issubset(df.columns):
        print("Error: CSV must contain 'timestamp', 'user_id', and 'ip_address' columns.")
        sys.exit(1)

    anomalies = detect_anomalies(df)
    if anomalies.empty:
        print("No anomalies found.")
    else:
        print("Detected Anomalies:")
        print(anomalies.to_string(index=False))

if __name__ == "__main__":
    main()