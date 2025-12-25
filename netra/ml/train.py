
import os
import io
import json
import random
import pickle
import numpy as np
import pandas as pd
from minio import Minio
from sklearn.ensemble import RandomForestRegressor

# Config
MINIO_URL = os.getenv("MINIO_URL", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")

def get_minio_client():
    return Minio(
        MINIO_URL,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False
    )

def generate_synthetic_data(n_samples=1000):
    """
    Cold Start: Generate synthetic scan profiles to bootstrap the model.
    """
    data = []
    for _ in range(n_samples):
        # Simulate vulnerabilities
        n_crit = 0 if random.random() > 0.2 else random.randint(1, 4)
        n_high = random.randint(0, 5)
        n_med = random.randint(0, 10)
        n_low = random.randint(0, 15)
        
        # Simulate ports
        n_ports = random.randint(0, 5)
        if random.random() > 0.9: n_ports += 10 # Occasional open firewall
        
        # Weak Labeling (The Heuristic from main.py)
        # Score = (Critical * 10) + (High * 5) + (Medium * 2) + (Low * 0.5) + (OpenPorts * 1)
        score = (n_crit * 10) + (n_high * 5) + (n_med * 2) + (n_low * 0.5) + (n_ports * 1)
        score = min(score, 100)
        
        # Add some noise/jitter to simulate "Human Intuition" nuance
        noise = random.uniform(-2, 2) 
        score = max(0, min(100, score + noise))
        
        data.append({
            "critical_count": n_crit,
            "high_count": n_high,
            "medium_count": n_med,
            "low_count": n_low,
            "open_port_count": n_ports,
            "risk_score": score
        })
        
    return pd.DataFrame(data)

def train_and_upload():
    print("ML Trainer: Starting Cold Start Routine...")
    
    # 1. Load Data (Synthetic for now, later fetch from MinIO netra-lake)
    df = generate_synthetic_data()
    print(f"ML Trainer: Generated {len(df)} synthetic samples.")
    
    # 2. Features & Target
    X = df[["critical_count", "high_count", "medium_count", "low_count", "open_port_count"]]
    y = df["risk_score"]
    
    # 3. Train Model
    print("ML Trainer: Training RandomForestRegressor...")
    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X, y)
    print("ML Trainer: Model trained successfully.")
    
    # 4. Serialize
    model_bytes = io.BytesIO()
    pickle.dump(model, model_bytes)
    model_bytes.seek(0)
    file_size = model_bytes.getbuffer().nbytes
    
    # 5. Upload to MinIO
    client = get_minio_client()
    bucket = "ml-models"
    
    try:
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)
            
        client.put_object(
            bucket,
            "risk_model_v1.pkl",
            model_bytes,
            file_size
        )
        print(f"ML Trainer: Uploaded risk_model_v1.pkl to {bucket}")
        
    except Exception as e:
        print(f"ML Trainer Error: {e}")

if __name__ == "__main__":
    train_and_upload()
