import pandas as pd
import glob

for f in glob.glob('data/*.csv'):
    try:
        df = pd.read_csv(f, low_memory=False, encoding='windows-1252')
        col = [c for c in df.columns if 'Label' in c][0]
        unique = list(df[col].unique())
        if any('Web' in str(u) or 'Brute' in str(u) or 'FTP' in str(u) for u in unique):
            print(f"\n{f}:")
            for u in unique:
                print(f"  {repr(u)}")
    except Exception as e:
        print(f"Error {f}: {e}")