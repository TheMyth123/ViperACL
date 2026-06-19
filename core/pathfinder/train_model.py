# core/pathfinder/train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

def train_and_save():
    print("[*] Loading synthetic training data...")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_dir, '..', '..', 'data', 'synthetic_training.csv')
    df = pd.read_csv(csv_path)
    
    # Dynamically select all columns EXCEPT 'Success' as training features
    X = df.drop(columns=['Success'])
    y = df['Success']
    
    print(f"[*] Training Random Forest Classifier on {len(X.columns)} features...")
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    
    model_path = os.path.join(base_dir, '..', '..', 'models', 'viper_rf_model.pkl')
    joblib.dump(model, model_path)
    print(f"[+] Model successfully trained and saved to {model_path}!")

if __name__ == "__main__":
    train_and_save()