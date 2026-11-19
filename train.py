import pandas as pd
import joblib
import os
import json
from pathlib import Path

from feature_extractor import extract_features, FEATURES

from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.utils.class_weight import compute_sample_weight

from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Project paths
BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "phishing_features.csv"
MODEL_DIR = BASE_DIR / "models"
METRICS_PATH = MODEL_DIR / "model_metrics.json"

# 1. Load dataset
df = pd.read_csv(DATASET_PATH)

print("Dataset loaded:", df.shape)

# 2. Extract URL features
print("\nExtracting URL features...")

feature_data = pd.DataFrame(
    df["url"].apply(extract_features).tolist()
)

X = feature_data[FEATURES]
y = df["label"]

print("Feature extraction completed!")
print("Features:", FEATURES)

# 3. Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# 4. Define models
models = {
    "random_forest": (
        "Random Forest",
        RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=-1
        )
    ),

    "svm": (
        "Support Vector Machine",
        make_pipeline(
            SimpleImputer(strategy="median"),
            StandardScaler(),
            LinearSVC(
                class_weight="balanced",
                random_state=42,
                max_iter=5000
            )
        )
    ),

    "gradient_boosting": (
        "Gradient Boosting",
        GradientBoostingClassifier(
            n_estimators=100,
            random_state=42
        )
    )
}

MODEL_DIR.mkdir(parents=True, exist_ok=True)

# 5. Train, evaluate and save
all_metrics = {}

for key, (name, model) in models.items():

    print("\n" + "=" * 55)
    print(name)
    print("=" * 55)

    if key == "gradient_boosting":
        weights = compute_sample_weight(
            class_weight="balanced",
            y=y_train
        )
        model.fit(X_train, y_train, sample_weight=weights)
    else:
        model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    # Calculate actual metrics
    accuracy = accuracy_score(y_test, predictions)
    balanced_accuracy = balanced_accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)

    cm = confusion_matrix(y_test, predictions, labels=[0, 1])

    print(f"Accuracy: {accuracy * 100:.4f}%")
    print(f"Balanced Accuracy: {balanced_accuracy * 100:.4f}%")
    print(f"Precision: {precision * 100:.4f}%")
    print(f"Recall: {recall * 100:.4f}%")
    print(f"F1 Score: {f1 * 100:.4f}%")

    print("\nConfusion Matrix:")
    print(cm)

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        zero_division=0
    ))

    # Save trained model
    filename = f"{key}.pkl"
    joblib.dump(model, MODEL_DIR / filename)

    # Save actual evaluation metrics as percentages
    all_metrics[key] = {
        "name": name,
        "accuracy": round(float(accuracy * 100), 6),
        "balanced_accuracy": round(float(balanced_accuracy * 100), 6),
        "precision": round(float(precision * 100), 6),
        "recall": round(float(recall * 100), 6),
        "f1_score": round(float(f1 * 100), 6),
        "confusion_matrix": cm.tolist()
    }

# 6. Save evaluation information
metrics_data = {
    "dataset": {
        "total_samples": int(len(df)),
        "training_samples": int(len(X_train)),
        "testing_samples": int(len(X_test)),
        "legitimate_samples": int((y == 0).sum()),
        "phishing_samples": int((y == 1).sum()),
        "positive_class": "Phishing (1)",
        "negative_class": "Legitimate (0)",
        "feature_count": int(len(FEATURES)),
        "features": FEATURES,
        "test_size": 0.20,
        "split_strategy": "Stratified train-test split",
        "random_state": 42,
        "legitimate_percentage": round(float((y == 0).mean() * 100), 4),
        "phishing_percentage": round(float((y == 1).mean() * 100), 4),
        "imbalance_ratio": round(
            float((y == 1).sum() / max((y == 0).sum(), 1)), 2
        )
    },
    "models": all_metrics
}

with open(METRICS_PATH, "w", encoding="utf-8") as file:
    json.dump(metrics_data, file, indent=4)

print("\n" + "=" * 55)
print("ALL MODELS TRAINED AND SAVED SUCCESSFULLY!")
print("Model files:", MODEL_DIR)
print("Metrics file:", METRICS_PATH)
print("=" * 55)