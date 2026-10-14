
from pathlib import Path
import json
import urllib.request
import urllib.error

import joblib
import numpy as np
import pandas as pd

project = Path(__file__).resolve().parents[1]
artifact = joblib.load(project / "models" / "random_forest.joblib")

csv_file = next(
    (project / "data" / "cicids2017").glob("*DDoS*.csv"),
    None,
)

if csv_file is None:
    raise FileNotFoundError("Could not find the DDoS CSV file")

# Read just one real network-flow row.
df = pd.read_csv(csv_file, nrows=1, encoding="utf-8-sig")
df.columns = [str(c).strip() for c in df.columns]
row = df.iloc[0]
print("Actual dataset label:", row.get(" Label", row.get("Label", "not found")))
print("CSV columns:", len(df.columns))
print("Model features:", len(artifact["features"]))
print("Features matched:", sum(f in df.columns for f in artifact["features"]))
features = {}
for name in artifact["features"]:
    value = pd.to_numeric(
        pd.Series([row.get(name, np.nan)]),
        errors="coerce",
    ).iloc[0]

    if pd.isna(value) or not np.isfinite(value):
        value = artifact.get("medians", {}).get(name, 0)

    features[name] = float(value)

payload = {
    "features": features,
    "source_ip": str(row.get("Source IP", "unknown")),
    "destination_ip": str(row.get("Destination IP", "unknown")),
}

request = urllib.request.Request(
    "http://127.0.0.1:8000/api/predict",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=30) as response:
        print("HTTP status:", response.status)
        print("API response:")
        print(json.dumps(json.loads(response.read()), indent=2))
except urllib.error.HTTPError as error:
    print("HTTP error:", error.code)
    print(error.read().decode("utf-8", errors="replace"))
except urllib.error.URLError as error:
    print("Could not connect to FastAPI:", error.reason)
