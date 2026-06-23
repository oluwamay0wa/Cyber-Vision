"""
CYBER-VISION | Data Preparation Pipeline
-----------------------------------------
Loads all CSV files from /data, cleans them,
maps labels to unified classes, and saves a
combined dataset ready for training.

OUTPUT: data/combined_clean.csv
-----------------------------------------
"""

import pandas as pd
import numpy as np
import glob
import os
from sklearn.preprocessing import StandardScaler
import joblib

# ─── FEATURE COLUMNS (must match live packet extraction) ─────────────────────
FEATURES = [
    ' Destination Port',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' Total Backward Packets',
    ' Packet Length Mean',
]

LABEL_COL_CANDIDATES = ['Label', ' Label', 'label']

# ─── LABEL MAPPING ────────────────────────────────────────────────────────────
# Covers both UTF-8 and Windows-1252 encoded dash variants
LABEL_MAP = {
    # Benign
    'BENIGN':                               0,
    'Benign':                               0,
    # DDoS
    'DDoS':                                 1,
    # Brute Force
    'FTP-BruteForce':                       2,
    'SSH-Bruteforce':                       2,
    'FTP-Patator':                          2,
    'SSH-Patator':                          2,
    # DoS
    'DoS slowloris':                        3,
    'DoS Slowhttptest':                     3,
    'DoS Hulk':                             3,
    'DoS GoldenEye':                        3,
    'Heartbleed':                           3,
    # Port Scan
    'PortScan':                             4,
    # Bot
    'Bot':                                  5,
    # Web Attack — all encoding variants of the dash character
    'Web Attack \x96 Brute Force':          6,
    'Web Attack \x96 XSS':                  6,
    'Web Attack \x96 Sql Injection':        6,
    'Web Attack \u2013 Brute Force':        6,
    'Web Attack \u2013 XSS':               6,
    'Web Attack \u2013 Sql Injection':      6,
    'Web Attack – Brute Force':            6,
    'Web Attack – XSS':                    6,
    'Web Attack – Sql Injection':          6,
    'Web Attack - Brute Force':             6,
    'Web Attack - XSS':                     6,
    'Web Attack - Sql Injection':           6,
    # Infiltration
    'Infiltration':                         7,
}

CLASS_NAMES = {
    0: 'BENIGN',
    1: 'DDOS',
    2: 'BRUTE_FORCE',
    3: 'DOS',
    4: 'PORT_SCAN',
    5: 'BOT',
    6: 'WEB_ATTACK',
    7: 'INFILTRATION',
}

# Try these encodings in order for each file
ENCODINGS = ['utf-8', 'windows-1252', 'latin-1', 'iso-8859-1']


def find_label_col(df):
    for candidate in LABEL_COL_CANDIDATES:
        if candidate in df.columns:
            return candidate
    for col in df.columns:
        if 'label' in col.lower():
            return col
    return None


def normalize_label(label):
    """
    Strips whitespace and normalizes any dash-like character to \x96
    so the label map always matches regardless of encoding.
    """
    label = str(label).strip()
    # Normalize all dash variants to the Windows-1252 \x96 character
    for dash in ['\u2013', '\u2014', '\u2012', ' - ', '-']:
        label = label.replace(dash, ' \x96 ')
    return label


def load_and_clean(filepath):
    print(f"[*] Loading: {filepath}")
    df = None

    # Try each encoding until one works
    for enc in ENCODINGS:
        try:
            df = pd.read_csv(filepath, low_memory=False, encoding=enc)
            print(f"    Encoding: {enc}")
            break
        except (UnicodeDecodeError, Exception):
            continue

    if df is None:
        print(f"[!] Could not read {filepath} with any encoding. Skipping.")
        return None

    # Find label column
    label_col = find_label_col(df)
    if not label_col:
        print(f"[!] No label column found in {filepath}, skipping.")
        return None

    # Check features exist
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        print(f"[!] Missing features in {filepath}: {missing}")
        return None

    df = df[FEATURES + [label_col]].copy()
    df.rename(columns={label_col: 'Label'}, inplace=True)

    # Normalize and map labels
    df['Label'] = df['Label'].astype(str).apply(normalize_label)
    df['Label'] = df['Label'].map(LABEL_MAP)

    unmapped = df['Label'].isna().sum()
    if unmapped > 0:
        print(f"[!] Dropping {unmapped} unmapped label rows in {filepath}")
    df.dropna(subset=['Label'], inplace=True)
    df['Label'] = df['Label'].astype(int)

    # Clean numeric features
    df[FEATURES] = df[FEATURES].apply(pd.to_numeric, errors='coerce')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    dist = dict(df['Label'].value_counts().sort_index())
    named = {CLASS_NAMES[k]: v for k, v in dist.items()}
    print(f"[+] {len(df)} clean rows | {named}")
    return df


def main():
    files = glob.glob('data/*.csv')
    if not files:
        print("[!] No CSV files found in data/ folder.")
        return

    print(f"[*] Found {len(files)} files. Processing...\n")

    frames = []
    for f in files:
        cleaned = load_and_clean(f)
        if cleaned is not None:
            frames.append(cleaned)

    if not frames:
        print("[!] No valid data loaded.")
        return

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n[+] Combined dataset: {len(combined)} rows")

    dist = dict(combined['Label'].value_counts().sort_index())
    named = {CLASS_NAMES[k]: v for k, v in dist.items()}
    print(f"[+] Class distribution:\n{named}")

    # Oversample minority classes (BOT, INFILTRATION, WEB_ATTACK) to improve recall
    print("\n[*] Balancing minority classes...")
    frames_balanced = []
    majority_count = combined['Label'].value_counts().max()
    for label in combined['Label'].unique():
        subset = combined[combined['Label'] == label]
        if len(subset) < 50000:
            subset = subset.sample(n=min(50000, majority_count), replace=True, random_state=42)
            print(f"    {CLASS_NAMES[label]}: {len(combined[combined['Label']==label])} → {len(subset)} (oversampled)")
        frames_balanced.append(subset)

    combined = pd.concat(frames_balanced, ignore_index=True).sample(frac=1, random_state=42)
    print(f"[+] Balanced dataset: {len(combined)} rows")

    # Scale features
    scaler = StandardScaler()
    combined[FEATURES] = scaler.fit_transform(combined[FEATURES])

    os.makedirs('models', exist_ok=True)
    joblib.dump(scaler, 'models/scaler.pkl')
    print("[+] Scaler saved to models/scaler.pkl")

    combined.to_csv('data/combined_clean.csv', index=False)
    print("[+] Clean dataset saved to data/combined_clean.csv")
    print("\n[✓] Data preparation complete. Run train_model.py next.")


if __name__ == "__main__":
    main()