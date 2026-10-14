
from pathlib import Path
import glob
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "cicids2017"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

SAMPLE_PER_FILE = 15000
RANDOM_STATE = 42

print("Searching for CICIDS2017 CSV files...")
files = glob.glob(str(DATA_DIR / "*.csv"))

if not files:
    raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

samples = []

for path in files:
    print(f"Sampling {Path(path).name}...")
    try:
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()

        if " Label" in df.columns:
            df.rename(columns={" Label": "Label"}, inplace=True)

        if "Label" not in df.columns:
            print("Skipping: no Label column")
            continue

        # Sample each file to keep training memory manageable.
        df = df.sample(
            n=min(SAMPLE_PER_FILE, len(df)),
            random_state=RANDOM_STATE
        )
        samples.append(df)
        del df

    except Exception as exc:
        print(f"Skipping {path}: {exc}")

if not samples:
    raise RuntimeError("No usable labeled CSV samples were found.")

data = pd.concat(samples, ignore_index=True)
del samples

data.columns = data.columns.str.strip()
labels = data["Label"].astype(str).str.strip().str.upper()
y = (labels != "BENIGN").astype(int)

# Keep numeric model features only; exclude identifiers and labels.
excluded = {
    "LABEL", "FLOW ID", "SOURCE IP", "DESTINATION IP", "TIMESTAMP"
}

feature_columns = [
    col for col in data.columns
    if col.strip().upper() not in excluded
    and pd.api.types.is_numeric_dtype(data[col])
]

X = data[feature_columns].replace([np.inf, -np.inf], np.nan)
X = X.apply(pd.to_numeric, errors="coerce")
X = X.fillna(X.median()).fillna(0)

if X.shape[1] == 0:
    raise RuntimeError("No numeric features found.")

# Train anomaly detection primarily on benign traffic.
benign = X[y == 0]

if len(benign) < 100:
    raise RuntimeError("Insufficient benign flows for anomaly training.")

X_train, X_test = train_test_split(
    benign,
    test_size=0.2,
    random_state=RANDOM_STATE
)

print(f"Training Isolation Forest on {len(X_train)} benign flows...")
model = IsolationForest(
    n_estimators=150,
    contamination="auto",
    random_state=RANDOM_STATE,
    n_jobs=-1
)
model.fit(X_train)

# Evaluate on held-out benign and attack examples.
attack = X[y == 1]
attack_sample = attack.sample(
    n=min(len(attack), len(X_test)),
    random_state=RANDOM_STATE
) if len(attack) else attack

evaluation = pd.concat([X_test, attack_sample], ignore_index=True)
actual = np.concatenate([
    np.zeros(len(X_test), dtype=int),
    np.ones(len(attack_sample), dtype=int)
])

predicted = (model.predict(evaluation) == -1).astype(int)

print("\nAnomaly detection evaluation (0=benign, 1=attack):")
print(confusion_matrix(actual, predicted, labels=[0, 1]))
print(classification_report(
    actual,
    predicted,
    labels=[0, 1],
    target_names=["BENIGN", "ATTACK"],
    zero_division=0
))

# Save feature order and imputation values for consistent inference.
artifact = {
    "model": model,
    "features": list(X.columns),
    "medians": X.median().fillna(0).to_dict(),
    "dataset": "CICIDS2017",
    "task": "Isolation Forest anomaly detection",
}

output = MODEL_DIR / "isolation_forest.joblib"
joblib.dump(artifact, output)
print(f"\nSaved anomaly model to: {output}")
