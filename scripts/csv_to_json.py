import os
import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
for fname in os.listdir(DATA_DIR):
    if fname.endswith('.csv'):
        csv_path = os.path.join(DATA_DIR, fname)
        json_path = os.path.join(DATA_DIR, fname.replace('.csv', '.json'))
        df = pd.read_csv(csv_path)
        df.to_json(json_path, orient='records', indent=2)
        print(f"Converted {fname} to {os.path.basename(json_path)}") 