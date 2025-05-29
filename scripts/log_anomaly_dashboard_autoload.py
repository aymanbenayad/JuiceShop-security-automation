
import pandas as pd
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn
import argparse
import os
import sys

app = FastAPI()

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

# Global state
global_anomalies_html = "<p>No data loaded.</p>"

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

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return HTML_TEMPLATE.format(table=global_anomalies_html)

def cli_preload(csv_path):
    global global_anomalies_html
    if not os.path.isfile(csv_path):
        print(f"Error: File '{csv_path}' not found.")
        sys.exit(1)

    df = pd.read_csv(csv_path)
    if not {'timestamp', 'user_id', 'ip_address'}.issubset(df.columns):
        print("Error: CSV must contain 'timestamp', 'user_id', and 'ip_address' columns.")
        sys.exit(1)

    anomalies = detect_anomalies(df)
    if anomalies.empty:
        global_anomalies_html = "<p>No anomalies found.</p>"
    else:
        global_anomalies_html = anomalies.to_html(classes='data', index=False, border=0)

    print("✅ Anomalies loaded — open http://localhost:8000 to view the dashboard.")
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log anomaly dashboard")
    parser.add_argument("--file", help="Path to CSV log file")
    args = parser.parse_args()

    if args.file:
        df = pd.read_csv(args.file)
        anomalies = detect_anomalies(df)
        if anomalies.empty:
            global_anomalies_html = "<p>No anomalies found.</p>"
        else:
            global_anomalies_html = anomalies.to_html(classes='data', index=False, border=0)

    uvicorn.run(app, host="0.0.0.0", port=8000)
