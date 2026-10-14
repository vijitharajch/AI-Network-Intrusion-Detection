
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .config import MODEL_DIR


class ModelService:
    def __init__(self):
        # Resolve the project root and model directory.
        self.project_root = Path(__file__).resolve().parents[2]
        configured_dir = Path(MODEL_DIR)

        if not configured_dir.is_absolute():
            configured_dir = self.project_root / configured_dir

        self.model_dir = (
            configured_dir
            if configured_dir.exists()
            else self.project_root / "models"
        )

        # Random Forest: supervised BENIGN / ATTACK classifier.
        self.classifier_artifact = self._load("random_forest.joblib")
        self.pipeline = None
        self.features = []
        self.medians = {}

        if self.classifier_artifact is not None:
            self.pipeline = self.classifier_artifact["model"]
            self.features = self.classifier_artifact["features"]
            self.medians = self.classifier_artifact.get("medians", {})

        # Isolation Forest: unsupervised anomaly detector.
        self.anomaly_artifact = self._load("isolation_forest.joblib")
        self.anomaly_model = None
        self.anomaly_features = []
        self.anomaly_medians = {}

        if self.anomaly_artifact is not None:
            self.anomaly_model = self.anomaly_artifact["model"]
            self.anomaly_features = self.anomaly_artifact["features"]
            self.anomaly_medians = self.anomaly_artifact.get("medians", {})

    def _load(self, filename):
        """Load a model artifact if the file exists."""
        path = self.model_dir / filename

        if not path.exists():
            return None

        return joblib.load(path)

    @property
    def ready(self):
        """True when the Random Forest classifier is available."""
        return self.pipeline is not None and bool(self.features)

    @property
    def anomaly_ready(self):
        """True when the Isolation Forest model is available."""
        return (
            self.anomaly_model is not None
            and bool(self.anomaly_features)
        )

    @staticmethod
    def _prepare_features(raw_features, feature_names, medians):
        """
        Build a single-row DataFrame in the exact feature order
        used when the model was trained.
        """
        row = {}

        for feature in feature_names:
            value = raw_features.get(feature)

            if value is None:
                value = medians.get(feature, 0)

            try:
                value = float(value)
            except (TypeError, ValueError):
                value = medians.get(feature, 0)

            if not np.isfinite(value):
                value = medians.get(feature, 0)

            row[feature] = value

        return pd.DataFrame([row], columns=feature_names)

    @staticmethod
    def _prepare_batch(df, feature_names, medians):
        """
        Prepare a batch of CSV rows using the required feature order.
        Missing and invalid values are replaced with training medians.
        """
        X = pd.DataFrame(index=range(len(df)))

        for feature in feature_names:
            if feature in df.columns:
                X[feature] = pd.to_numeric(
                    df[feature],
                    errors="coerce"
                ).to_numpy()
            else:
                X[feature] = medians.get(feature, 0)

        X.replace(
            [np.inf, -np.inf],
            np.nan,
            inplace=True
        )

        for feature in feature_names:
            X[feature] = X[feature].fillna(
                medians.get(feature, 0)
            )

        return X

    def predict(self, raw_features: dict):
        """
        Predict one network flow.

        Returns:
            prediction: BENIGN or ATTACK
            confidence: maximum Random Forest class probability
            anomaly: True if Isolation Forest flags the flow
        """
        if not self.ready:
            raise RuntimeError(
                "Random Forest model is unavailable. "
                "Train it using ml/train.py."
            )

        # 1. Supervised classification.
        X_classifier = self._prepare_features(
            raw_features,
            self.features,
            self.medians
        )

        predicted_value = int(
            self.pipeline.predict(X_classifier)[0]
        )

        probabilities = self.pipeline.predict_proba(X_classifier)[0]
        confidence = float(np.max(probabilities))

        # This assumes the trained binary model uses 0 = BENIGN, 1 = ATTACK.
        prediction = (
            "BENIGN" if predicted_value == 0 else "ATTACK"
        )

        # 2. Independent anomaly detection.
        anomaly = False

        if self.anomaly_ready:
            X_anomaly = self._prepare_features(
                raw_features,
                self.anomaly_features,
                self.anomaly_medians
            )

            anomaly_value = int(
                self.anomaly_model.predict(X_anomaly)[0]
            )

            # Isolation Forest: -1 = outlier, 1 = inlier.
            anomaly = anomaly_value == -1

        return prediction, confidence, anomaly

    def predict_batch(self, df):
        """
        Predict a DataFrame of network flows efficiently.

        Returns a list of dictionaries with prediction, confidence,
        and anomaly fields. This method does not write to the database.
        """
        if not self.ready:
            raise RuntimeError(
                "Random Forest model is unavailable. "
                "Train it using ml/train.py."
            )

        if df.empty:
            return []

        df = df.copy()
        df.columns = df.columns.str.strip()

        # 1. Batch Random Forest prediction.
        X_classifier = self._prepare_batch(
            df,
            self.features,
            self.medians
        )

        predicted_values = self.pipeline.predict(X_classifier)
        probabilities = self.pipeline.predict_proba(
            X_classifier
        ).max(axis=1)

        # 2. Batch Isolation Forest prediction.
        if self.anomaly_ready:
            X_anomaly = self._prepare_batch(
                df,
                self.anomaly_features,
                self.anomaly_medians
            )

            anomaly_values = self.anomaly_model.predict(X_anomaly)
            anomalies = anomaly_values == -1
        else:
            anomalies = np.zeros(len(df), dtype=bool)

        results = []

        for label, confidence, anomaly in zip(
            predicted_values,
            probabilities,
            anomalies
        ):
            prediction = (
                "BENIGN" if int(label) == 0 else "ATTACK"
            )

            results.append({
                "prediction": prediction,
                "confidence": float(confidence),
                "anomaly": bool(anomaly)
            })

        return results
