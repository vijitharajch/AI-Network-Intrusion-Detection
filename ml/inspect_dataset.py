
from pathlib import Path
from collections import Counter
import pandas as pd

DATA_DIR = Path("data/cicids2017")
files = sorted(DATA_DIR.glob("*.csv"))

if not files:
    raise FileNotFoundError(
        f"No CSV files found in {DATA_DIR.resolve()}"
    )

print(f"Found {len(files)} CSV files")
total_rows = 0
total_labels = Counter()

for file in files:
    print(f"\nInspecting: {file.name}")
    rows = 0
    labels_count = Counter()

    for chunk in pd.read_csv(
        file,
        chunksize=100_000,
        encoding="utf-8-sig",
        low_memory=False
    ):
        chunk.columns = [str(c).strip() for c in chunk.columns]

        label_cols = [
            c for c in chunk.columns
            if c.strip().lower() == "label"
        ]
        if not label_cols:
            raise ValueError(f"Label column missing in {file.name}")

        label_col = label_cols[0]
        rows += len(chunk)

        counts = (
            chunk[label_col]
            .astype("string")
            .str.strip()
            .fillna("<MISSING>")
            .value_counts()
        )
        labels_count.update(counts.to_dict())

    total_rows += rows
    total_labels.update(labels_count)

    print(f"Rows: {rows:,}")
    print("Labels:")
    for label, count in labels_count.most_common():
        print(f"  {label}: {count:,}")

print(f"\nTOTAL ROWS: {total_rows:,}")
print("\nTOTAL LABEL DISTRIBUTION:")
for label, count in total_labels.most_common():
    print(f"  {label}: {count:,}")

print("\nInspection completed.")
