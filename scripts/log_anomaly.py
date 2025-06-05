import pandas as pd
import argparse
import os
import sys

HTML_TEMPLATE = """ 
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Log Anomaly Dashboard</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      background-color: #f4f6f8;
      padding: 2rem;
    }}
    .container {{
      max-width: 1000px;
      margin: auto;
      background: #fff;
      padding: 2rem;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }}
    h1 {{
      text-align: center;
      color: #2c3e50;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 2rem;
    }}
    th, td {{
      padding: 0.75rem;
      border: 1px solid #ddd;
      text-align: left;
    }}
    th {{
      background-color: #3498db;
      color: white;
    }}
    tr:nth-child(even) {{
      background-color: #f2f2f2;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Log Anomaly Detection</h1>
    {table}
  </div>
</body>
</html>
"""

def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['reason'] = ""

    df.loc[df['hour'].between(1, 5), 'reason'] += "Login between 1AM and 5AM; "

    sql_pattern = r"(('|--|;|=)|or\s+['\"]?1['\"]?\s*=\s*['\"]?1)"
    if 'user_id' in df.columns:
        df.loc[df['user_id'].str.contains(sql_pattern, regex=True, case=False, na=False), 'reason'] += "Suspicious user_id (SQL injection); "

    anomalies = df[df['reason'] != ""].drop(columns='hour')
    anomalies['reason'] = anomalies['reason'].str.strip("; ")
    return anomalies

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log anomaly report to HTML")
    parser.add_argument("--file", help="Path to CSV log file", required=True)
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)

    df = pd.read_csv(args.file)
    if not {'timestamp'}.issubset(df.columns):
        print("Error: CSV must contain at least the 'timestamp' column.", file=sys.stderr)
        sys.exit(1)

    anomalies = detect_anomalies(df)
    if anomalies.empty:
        html_output = HTML_TEMPLATE.format(table="<p>No anomalies found.</p>")
    else:
        table_html = anomalies.to_html(classes='data', index=False, border=0)
        html_output = HTML_TEMPLATE.format(table=table_html)

    print(html_output)
