
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "cicids2017"
MODEL_PATH = ROOT / "models" / "isolation_forest.joblib"

CHUNK_SIZE = 50000
PER_CHUNK_PER_CLASS = 200
MAX_PER_CLASS = 20000
RANDOM_STATE = 42

artifact = joblib.load(MODEL_PATH)
model = artifact["model"]
features = artifact["features"]
medians = pd.Series(artifact.get("medians", {})).reindex(features).fillna(0)

files = sorted(DATA_DIR.glob("*.csv"))
if not files:
    raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

samples = {0: [], 1: []}
rng = np.random.default_rng(RANDOM_STATE)

print(f"Found {len(files)} CSV files.")
print("Collecting BENIGN and ATTACK samples...")

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

        labels = (
            chunk[label_cols[0]]
            .astype("string")
            .str.strip()
            .str.upper()
        )
        y = (labels != "BENIGN").astype("int8").to_numpy()

        X = pd.DataFrame(index=range(len(chunk)))
        for feature in features:
            if feature in chunk.columns:
                X[feature] = pd.to_numeric(
                    chunk[feature], errors="coerce"
                ).to_numpy()
            else:
                X[feature] = np.nan

        X = X.replace([np.inf, -np.inf], np.nan).fillna(medians)

        for target in (0, 1):
            indices = np.flatnonzero(y == target)
            if len(indices) > PER_CHUNK_PER_CLASS:
                indices = rng.choice(
                    indices, size=PER_CHUNK_PER_CLASS, replace=False
                )

            if len(indices):
                samples[target].append(
                    X.iloc[indices].reset_index(drop=True)
                )

class_data = {}
for target in (0, 1):
    if not samples[target]:
        raise ValueError(f"No samples found for class {target}")

    combined = pd.concat(samples[target], ignore_index=True)
    if len(combined) > MAX_PER_CLASS:
        combined = combined.sample(
            n=MAX_PER_CLASS, random_state=RANDOM_STATE
        ).reset_index(drop=True)

    class_data[target] = combined
    print(
        f"{'BENIGN' if target == 0 else 'ATTACK'} rows: {len(combined)}"
    )

X = pd.concat([class_data[0], class_data[1]], ignore_index=True)
y = np.concatenate([
    np.zeros(len(class_data[0]), dtype=np.int8),
    np.ones(len(class_data[1]), dtype=np.int8),
])

# Isolation Forest: -1 means anomaly; +1 means normal.
raw_predictions = model.predict(X)
predictions = (raw_predictions == -1).astype("int8")

print("\n=== ISOLATION FOREST EVALUATION ===")
print("Evaluation rows:", len(y))
print("Accuracy:", round(accuracy_score(y, predictions), 4))
print(
    "Attack precision:",
    round(precision_score(y, predictions, zero_division=0), 4),
)
print(
    "Attack recall:",
    round(recall_score(y, predictions, zero_division=0), 4),
)
print(
    "Attack F1:",
    round(f1_score(y, predictions, zero_division=0), 4),
)
print(
    "Macro precision:",
    round(precision_score(y, predictions, average="macro", zero_division=0), 4),
)
print(
    "Macro recall:",
    round(recall_score(y, predictions, average="macro", zero_division=0), 4),
)
print(
    "Macro F1:",
    round(f1_score(y, predictions, average="macro", zero_division=0), 4),
)

print("\nClassification report:")
print(
    classification_report(
        y,
        predictions,
        labels=[0, 1],
        target_names=["BENIGN", "ATTACK"],
        zero_division=0,
    )
)

print("Confusion matrix [BENIGN, ATTACK]:")
print(confusion_matrix(y, predictions, labels=[0, 1]))

print(
    "\nNOTE: This is a preliminary sample from CICIDS2017, "
    "not an independent test set."
)
