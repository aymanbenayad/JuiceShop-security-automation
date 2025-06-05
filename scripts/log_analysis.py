import pandas as pd
import re

df = pd.read_csv('logs/logs.csv')

threat_patterns = {
    'SQLi': [r"' OR 1=1", r'UNION SELECT', r'DROP TABLE', r'--'],
    'XSS': [r'<script>', r'onerror=', r'alert\(', r'<svg', r'<img'],
    'Admin_Breach': [r'/admin', r'/api/Admin', r'role=admin'],
    'Sensitive_Access': ['/rest', '/api', '/profile', '/config']
}

def detect_threats(df):
    for threat_type, patterns in threat_patterns.items():
        df[f'is_{threat_type}'] = df['message'].str.contains('|'.join(patterns), case=False, na=False)
    df['is_error'] = df['event'].str.contains('error', case=False, na=False)
    return df

def generate_stats(df):
    stats = {
        'Période analysée': f"{df['timestamp'].min()} au {df['timestamp'].max()}",
        'Total requêtes': len(df),
        'Requêtes erronées (event contient "error")': df['is_error'].sum(),
        'Adresses IP uniques': df['message'].str.extract(r'(\d+\.\d+\.\d+\.\d+)').dropna().nunique()[0],
        'Heure de pointe': df['timestamp'].str[11:13].value_counts().idxmax()
    }
    for threat in threat_patterns:
        stats[f'Détections {threat}'] = df[f'is_{threat}'].sum()
    return stats

def show_threat_details(df):
    for threat in threat_patterns:
        threat_df = df[df[f'is_{threat}']]
        if not threat_df.empty:
            print(f"\n--- Détails des {threat} détectés ({len(threat_df)} cas) ---")
            for _, row in threat_df.iterrows():
                print(f"{row['timestamp']} | {row['event']} | {row['message']}")

def main():
    df = detect_threats(df)
    stats = generate_stats(df)
    print("=== Statistiques générales ===")
    for k, v in stats.items():
        print(f"{k}: {v}")
    print("\n=== Détails des menaces détectées ===")
    show_threat_details(df)

if __name__ == "__main__":
    main()
