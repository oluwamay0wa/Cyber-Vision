"""
CYBER-VISION | Model Training Pipeline
----------------------------------------
Trains a Random Forest classifier on the
combined clean dataset from prepare_ai_data.py.

OUTPUT: models/cyber_vision_v1.pkl
----------------------------------------
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# ─── CONFIG ───────────────────────────────────────────────────────────────────
DATA_PATH   = 'data/combined_clean.csv'
MODEL_PATH  = 'models/cyber_vision_v1.pkl'
SCALER_PATH = 'models/scaler.pkl'

FEATURES = [
    ' Destination Port',
    ' Flow Duration',
    ' Total Fwd Packets',
    ' Total Backward Packets',
    ' Packet Length Mean',
]

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


def main():
    # ── Load data ─────────────────────────────────────────────────────────────
    if not os.path.exists(DATA_PATH):
        print(f"[!] {DATA_PATH} not found. Run prepare_ai_data.py first.")
        return

    print(f"[*] Loading {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    print(f"[+] Loaded {len(df)} rows")
    print(f"[+] Class distribution:\n{df['Label'].value_counts().sort_index()}\n")

    X = df[FEATURES].values
    y = df['Label'].values

    # ── Train/test split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[*] Training on {len(X_train)} samples, testing on {len(X_test)} samples")

    # ── Train model ───────────────────────────────────────────────────────────
    print("[*] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        n_jobs=-1,          # use all CPU cores
        random_state=42,
        class_weight='balanced'  # handles class imbalance automatically
    )
    model.fit(X_train, y_train)
    print("[+] Training complete.")

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred = model.predict(X_test)
    target_names = [CLASS_NAMES[i] for i in sorted(CLASS_NAMES.keys()) if i in np.unique(y)]

    print("\n--- CLASSIFICATION REPORT ---")
    print(classification_report(y_test, y_pred, target_names=target_names))

    print("--- CONFUSION MATRIX ---")
    print(confusion_matrix(y_test, y_pred))

    accuracy = (y_pred == y_test).mean()
    print(f"\n[+] Overall Accuracy: {accuracy * 100:.2f}%")

    # ── Save model ────────────────────────────────────────────────────────────
    os.makedirs('models', exist_ok=True)

    # Load scaler if it exists and bundle with model
    scaler = None
    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
        print(f"[+] Scaler loaded from {SCALER_PATH}")

    payload = {
        "model": model,
        "scaler": scaler,
        "features": FEATURES,
        "class_names": CLASS_NAMES
    }

    joblib.dump(payload, MODEL_PATH)
    print(f"[+] Model saved to {MODEL_PATH}")
    print(f"[+] Feature count: {model.n_features_in_}")
    print(f"[+] Classes: {model.classes_}")
    print("\n[✓] Training complete. Your model is ready.")


if __name__ == "__main__":
    main()