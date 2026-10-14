
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "cicids2017"
MODEL_PATH = ROOT / "models" / "random_forest.joblib"

CHUNK_SIZE = 50000
PER_CHUNK_PER_CLASS = 200
MAX_PER_CLASS = 20000
RANDOM_STATE = 42

artifact = joblib.load(MODEL_PATH)
model = artifact["model"]
features = artifact["features"]
medians = pd.Series(artifact["medians"]).reindex(features).fillna(0)

files = sorted(DATA_DIR.glob("*.csv"))
if not files:
    raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

samples = {0: [], 1: []}
rng = np.random.default_rng(RANDOM_STATE)

print(f"Found {len(files)} CSV files.")
print("Collecting a balanced evaluation sample...")

for file in files:
    print(f"Reading {file.name}")

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        encoding="utf-8-sig",
        low_memory=False,
    ):
        chunk.columns = chunk.columns.astype(str).str.strip()

        label_cols = [c for c in chunk.columns if c.lower() == "label"]
        if not label_cols:
            continue

        labels = chunk[label_cols[0]].astype("string").str.strip().str.upper()
        y = (labels != "BENIGN").astype("int8").to_numpy()

        X = pd.DataFrame(index=range(len(chunk)))

        for feature in features:
            if feature in chunk.columns:
                X[feature] = pd.to_numeric(
                    chunk[feature], errors="coerce"
                ).to_numpy()
            else:
                X[feature] = np.nan

        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(medians)

        for target in (0, 1):
            indices = np.flatnonzero(y == target)

            if len(indices) > PER_CHUNK_PER_CLASS:
                indices = rng.choice(
                    indices, size=PER_CHUNK_PER_CLASS, replace=False
                )

            if len(indices):
                samples[target].append(X.iloc[indices].reset_index(drop=True))

if not samples[0] or not samples[1]:
    raise ValueError("Dataset sampling did not find both BENIGN and ATTACK rows.")

class_data = {}

for target in (0, 1):
    combined = pd.concat(samples[target], ignore_index=True)

    if len(combined) > MAX_PER_CLASS:
        combined = combined.sample(
            n=MAX_PER_CLASS, random_state=RANDOM_STATE
        ).reset_index(drop=True)

    class_data[target] = combined
    print(
        f"{'BENIGN' if target == 0 else 'ATTACK'} samples: {len(combined)}"
    )

X = pd.concat(
    [class_data[0], class_data[1]], ignore_index=True
)
y = np.concatenate([
    np.zeros(len(class_data[0]), dtype=np.int8),
    np.ones(len(class_data[1]), dtype=np.int8),
])

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=RANDOM_STATE,
    stratify=y,
)

# Evaluate the saved model; do not train it again.
predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

print("\n=== SAVED RANDOM FOREST EVALUATION ===")
print("Evaluation rows:", len(y_test))
print("Feature count:", len(features))
print("Accuracy:", round(accuracy_score(y_test, predictions), 4))
print(
    "Macro precision:",
    round(precision_score(y_test, predictions, average="macro", zero_division=0), 4),
)
print(
    "Macro recall:",
    round(recall_score(y_test, predictions, average="macro", zero_division=0), 4),
)
print(
    "Macro F1:",
    round(f1_score(y_test, predictions, average="macro", zero_division=0), 4),
)
print("ROC-AUC:", round(roc_auc_score(y_test, probabilities), 4))

print("\nClassification report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["BENIGN", "ATTACK"],
        zero_division=0,
    )
)

print("Confusion matrix [BENIGN, ATTACK]:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print(
    "\nNOTE: This is a preliminary evaluation sample from CICIDS2017, "
    "not an independent test set."
)
