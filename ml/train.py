
from pathlib import Path
import warnings

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)

warnings.filterwarnings("ignore")

DATA_DIR = Path("data/cicids2017")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 100_000
PER_CHUNK_PER_CLASS = 1_000
MAX_PER_CLASS = 50_000
RANDOM_STATE = 42

# Fields that identify a flow or endpoint rather than its behavior.
DROP_COLUMNS = {
    "flow id",
    "source ip",
    "destination ip",
    "timestamp",
}

files = sorted(DATA_DIR.glob("*.csv"))
if not files:
    raise FileNotFoundError(f"No CSV files found in {DATA_DIR.resolve()}")

samples = []
feature_columns = None

print(f"Found {len(files)} files. Sampling rows...")

for file in files:
    print(f"\nReading {file.name}")

    for chunk in pd.read_csv(
        file,
        chunksize=CHUNK_SIZE,
        encoding="utf-8-sig",
        low_memory=False,
    ):
        chunk.columns = [str(c).strip() for c in chunk.columns]

        label_cols = [
            c for c in chunk.columns if c.lower() == "label"
        ]
        if not label_cols:
            raise ValueError(f"Label column missing in {file.name}")

        label_col = label_cols[0]
        labels = (
            chunk[label_col]
            .astype("string")
            .str.strip()
            .str.upper()
        )

        # Binary classification: BENIGN = 0, all attacks = 1.
        chunk["target"] = (labels != "BENIGN").astype("int8")

        # Remove identifiers, labels, and non-numeric columns.
        excluded = {
            label_col,
            "target",
        } | {
            c for c in chunk.columns
            if c.strip().lower() in DROP_COLUMNS
        }

        candidates = [
            c for c in chunk.columns
            if c not in excluded
        ]

        numeric = chunk[candidates].apply(
            pd.to_numeric, errors="coerce"
        )

        # Keep columns with at least one valid value.
        numeric = numeric.dropna(axis=1, how="all")

        if feature_columns is None:
            feature_columns = list(numeric.columns)
            if not feature_columns:
                raise ValueError("No numeric feature columns found")
        else:
            # Align every chunk to the same feature schema.
            numeric = numeric.reindex(
                columns=feature_columns, fill_value=np.nan
            )

        numeric = numeric.replace([np.inf, -np.inf], np.nan)
        numeric["target"] = chunk["target"].to_numpy()

        # Sample each class separately to retain attack examples.
        for target_value in (0, 1):
            group = numeric[numeric["target"] == target_value]

            if len(group) > PER_CHUNK_PER_CLASS:
                group = group.sample(
                    n=PER_CHUNK_PER_CLASS,
                    random_state=RANDOM_STATE,
                )

            if not group.empty:
                samples.append(group)

if not samples:
    raise ValueError("No rows were sampled from the dataset")

data = pd.concat(samples, ignore_index=True)

# Bound the final training sample for laptop-friendly training.
balanced = []
for target_value in (0, 1):
    group = data[data["target"] == target_value]
    count = min(len(group), MAX_PER_CLASS)

    if count == 0:
        raise ValueError(f"No samples found for class {target_value}")

    balanced.append(
        group.sample(n=count, random_state=RANDOM_STATE)
    )

data = pd.concat(balanced, ignore_index=True)
data = data.sample(frac=1, random_state=RANDOM_STATE)

X = data[feature_columns]
y = data["target"].astype("int8")

print("\nSample size:", len(data))
print("Feature count:", len(feature_columns))
print("Class counts:")
print(y.map({0: "BENIGN", 1: "ATTACK"}).value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=RANDOM_STATE,
    stratify=y,
)

# Fit imputation values using training data only.
medians = X_train.median().fillna(0)
X_train = X_train.fillna(medians)
X_test = X_test.fillna(medians)

model = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",
    random_state=RANDOM_STATE,
    n_jobs=-1,
    max_features="sqrt",
)

print("\nTraining Random Forest...")
model.fit(X_train, y_train)

predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
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

print("Confusion matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print("ROC-AUC:", round(roc_auc_score(y_test, probabilities), 4))

artifact = {
    "model": model,
    "features": feature_columns,
    "medians": medians.to_dict(),
    "classes": {"BENIGN": 0, "ATTACK": 1},
    "dataset": "CICIDS2017",
    "task": "binary_classification",
}

output_path = MODEL_DIR / "random_forest.joblib"
joblib.dump(artifact, output_path)

print(f"\nModel saved to: {output_path}")
print("Training completed.")
