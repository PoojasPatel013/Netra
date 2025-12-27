import os
import io
import json
import random
import pickle
import numpy as np
import pandas as pd
from minio import Minio
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
import string
from sklearn.utils import shuffle
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.pipeline import make_pipeline

# Config
MINIO_URL = os.getenv("MINIO_URL", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")


def get_minio_client():
    return Minio(
        MINIO_URL,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
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
        if random.random() > 0.9:
            n_ports += 10  # Occasional open firewall

        # Weak Labeling (The Heuristic from main.py)
        # Score = (Critical * 10) + (High * 5) + (Medium * 2) + (Low * 0.5) + (OpenPorts * 1)
        score = (
            (n_crit * 10) + (n_high * 5) + (n_med * 2) + (n_low * 0.5) + (n_ports * 1)
        )
        score = min(score, 100)

        # Add some noise/jitter to simulate "Human Intuition" nuance
        noise = random.uniform(-2, 2)
        score = max(0, min(100, score + noise))

        data.append(
            {
                "critical_count": n_crit,
                "high_count": n_high,
                "medium_count": n_med,
                "low_count": n_low,
                "open_port_count": n_ports,
                "risk_score": score,
            }
        )

    return pd.DataFrame(data)


def train_risk_model():
    print("ML Trainer: Starting Cold Start Routine...")

    # 1. Load Data (Synthetic for now, later fetch from MinIO netra-lake)
    df = generate_synthetic_data()
    print(f"ML Trainer: Generated {len(df)} synthetic samples.")

    # 2. Features & Target
    X = df[
        ["critical_count", "high_count", "medium_count", "low_count", "open_port_count"]
    ]
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

        client.put_object(bucket, "risk_model_v1.pkl", model_bytes, file_size)
        print(f"ML Trainer: Uploaded risk_model_v1.pkl to {bucket}")

    except Exception as e:
        print(f"ML Trainer Error: {e}")


def train_zombie_hunter():
    """
    Trains a Character-Level N-Gram model to distinguish API Paths from Random Code.
    "TinyLLM" approach for local execution.
    """
    print("Generating Synthetic NLP Dataset...")

    # Positive Samples (API Paths)
    # We want the model to learn structure like /word/word, /v1/, camelCase in paths
    positives = [
        "/api/v1/users",
        "/api/v2/auth/login",
        "/internal/admin/dashboard",
        "/graphql",
        "/rest/api/payments",
        "/hidden/debug/console",
        "/v1/orders/create",
        "/api/user/profile_data",
        "/sso/saml/callback",
        "/health/readiness",
        "/metrics",
        "/oauth/token",
        "/api/private/feature_flags",
        "/test/unit/runner",
        # Common heuristics we want to catch
        "/admin",
        "/login",
        "/setup",
        "/config",
        "/backup",
    ]
    # Augment positives
    for i in range(500):
        v = np.random.choice(["v1", "v2", "v3", "beta", "internal"])
        noun = np.random.choice(
            ["user", "admin", "settings", "data", "conf", "job", "task"]
        )
        action = np.random.choice(["get", "post", "delete", "list", "create"])
        positives.append(f"/api/{v}/{noun}/{action}")
        positives.append(f"/{noun}/{action}")

    # Negative Samples (Random Code / Assets)
    negatives = [
        "var x = 1;",
        "console.log('test')",
        "function() { return true; }",
        "jquery.min.js",
        "bootstrap.css",
        "background-image: url('img.png')",
        "Lorem ipsum dolor sit amet",
        "1234567890",
        "btn-primary",
        "margin-top: 10px;",
        "<div class='container'>",
        "import React from 'react'",
        "node_modules",
        "webpack_chunk",
        "e.target.value",
        "user_id",
        "password",
        "email",  # Single words are usually variables, not paths
    ]
    # Augment negatives
    for i in range(500):
        # Random noise
        negatives.append("".join(np.random.choice(list(string.ascii_letters), size=10)))
        # Code-like constructs
        negatives.append(
            f"var {np.random.choice(list(string.ascii_lowercase))} = {np.random.randint(100)};"
        )

    # Create Labels
    X = positives + negatives
    y = [1] * len(positives) + [0] * len(negatives)

    # Shuffle
    X, y = shuffle(X, y, random_state=42)

    # Pipeline: Char N-Grams -> Random Forest
    # Analyzer='char_wb' looks at characters inside word boundaries (good for /path/structure)
    print("Training NLP Pipeline (CountVectorizer + RandomForest)...")
    model = make_pipeline(
        CountVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=1000),
        RandomForestClassifier(n_estimators=50, random_state=42),
    )

    model.fit(X, y)
    print(f"Model Score: {model.score(X, y):.4f}")

    # Upload
    model_data = pickle.dumps(model)
    model_name = "zombie_model_v1.pkl"

    client = get_minio_client()
    if client:
        try:
            if not client.bucket_exists("ml-models"):
                client.make_bucket("ml-models")

            client.put_object(
                "ml-models", model_name, io.BytesIO(model_data), len(model_data)
            )
            print(f"SAVED: {model_name} uploaded to MinIO.")
        except Exception as e:
            print(f"MinIO Upload Error: {e}")
    else:
        print("MinIO Client not active. Skipping upload.")


def main():
    print("ML Cold Start: Training Risk Model...")
    train_risk_model()

    print("\nML Cold Start: Training ZOMBIE HUNTER (NLP) Model...")
    train_zombie_hunter()

    print("\nTraining Complete.")


if __name__ == "__main__":
    main()
