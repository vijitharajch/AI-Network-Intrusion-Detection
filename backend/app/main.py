
from datetime import datetime
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import CORS_ORIGINS
from .db import init_db, get_db, Alert
from .schemas import PredictionRequest, PredictionResponse
from .model_service import ModelService
from .risk import risk_level, explain


app = FastAPI(title="AI NIDS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()
service = ModelService()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LIVE_FLOWS_CSV = (
    PROJECT_ROOT / "data" / "live_flows" / "scapy_live_flows.csv"
)


# ---------------------------------------------------------
# LIVE NETWORK TRAFFIC
# Uses captured CSV data when available.
# Otherwise, returns clearly labeled presentation simulation.
# ---------------------------------------------------------
@app.get("/api/live-flows")
def get_live_flows():
    if LIVE_FLOWS_CSV.exists():
        try:
            df = pd.read_csv(LIVE_FLOWS_CSV)

            required_columns = {
                "protocol",
                "packets",
                "bytes",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "duration_seconds",
            }

            missing = required_columns - set(df.columns)

            if missing:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Live-flow CSV is missing columns: "
                        + ", ".join(sorted(missing))
                    ),
                )

            df = df.where(pd.notnull(df), None)

            return {
                "mode": "CAPTURED DATA",
                "total": len(df),
                "tcp": int((df["protocol"] == "TCP").sum()),
                "udp": int((df["protocol"] == "UDP").sum()),
                "total_packets": int(df["packets"].sum()),
                "total_bytes": int(df["bytes"].sum()),
                "flows": df.to_dict(orient="records"),
            }

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Could not read live-flow CSV: {e}",
            )

    # Presentation-only traffic simulation.
    # These records are NOT captured packets or AI predictions.
    now = datetime.utcnow()

    flows = [
        {
            "src_ip": "192.168.1.10",
            "src_port": 51001,
            "dst_ip": "142.250.183.14",
            "dst_port": 443,
            "protocol": "TCP",
            "packets": 42 + now.second % 20,
            "bytes": 5200 + now.second * 37,
            "duration_seconds": round(
                1.2 + (now.second % 8) * 0.3, 2
            ),
        },
        {
            "src_ip": "192.168.1.12",
            "src_port": 53002,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "protocol": "UDP",
            "packets": 8 + now.second % 7,
            "bytes": 640 + now.second * 11,
            "duration_seconds": round(
                0.2 + (now.second % 5) * 0.1, 2
            ),
        },
        {
            "src_ip": "192.168.1.15",
            "src_port": 54003,
            "dst_ip": "203.0.113.25",
            "dst_port": 22,
            "protocol": "TCP",
            "packets": 65 + now.second % 25,
            "bytes": 7800 + now.second * 53,
            "duration_seconds": round(
                2.0 + (now.second % 6) * 0.4, 2
            ),
        },
        {
            "src_ip": "192.168.1.20",
            "src_port": 55004,
            "dst_ip": "198.51.100.40",
            "dst_port": 80,
            "protocol": "TCP",
            "packets": 18 + now.second % 12,
            "bytes": 1900 + now.second * 19,
            "duration_seconds": round(
                0.8 + (now.second % 4) * 0.2, 2
            ),
        },
    ]

    return {
        "mode": "SIMULATED DEMO",
        "message": (
            "Presentation simulation only. These are generated "
            "sample flows, not captured network traffic or AI predictions."
        ),
        "total": len(flows),
        "tcp": sum(f["protocol"] == "TCP" for f in flows),
        "udp": sum(f["protocol"] == "UDP" for f in flows),
        "total_packets": sum(f["packets"] for f in flows),
        "total_bytes": sum(f["bytes"] for f in flows),
        "flows": flows,
    }


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "models_ready": service.ready,
    }


# ---------------------------------------------------------
# SINGLE-FLOW AI PREDICTION
# ---------------------------------------------------------
@app.post("/api/predict", response_model=PredictionResponse)
def predict(
    req: PredictionRequest,
    db: Session = Depends(get_db),
):
    try:
        prediction, confidence, anomaly = service.predict(
            req.features
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    risk = risk_level(prediction, confidence, anomaly)
    explanation = explain(
        prediction, confidence, anomaly, risk
    )

    source_ip = req.source_ip or "unknown"
    destination_ip = req.destination_ip or "unknown"

    if risk != "LOW":
        alert = Alert(
            timestamp=datetime.utcnow(),
            prediction=prediction,
            confidence=confidence,
            anomaly=int(anomaly),
            risk=risk,
            source_ip=source_ip,
            destination_ip=destination_ip,
            details="; ".join(explanation),
        )
        db.add(alert)
        db.commit()

    return PredictionResponse(
        prediction=prediction,
        confidence=confidence,
        anomaly=anomaly,
        risk=risk,
        source_ip=source_ip,
        destination_ip=destination_ip,
        explanation=explanation,
    )


# ---------------------------------------------------------
# CSV BATCH PREDICTION
# ---------------------------------------------------------
@app.post("/api/predict/csv")
def predict_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV file.",
        )

    try:
        df = pd.read_csv(file.file)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Could not read CSV file: {e}",
        )

    if df.empty:
        raise HTTPException(
            status_code=400,
            detail="The uploaded CSV is empty.",
        )

    if not service.ready:
        raise HTTPException(
            status_code=503,
            detail="AI models are not ready.",
        )

    # Bound memory and response size for large uploads.
    total_rows = len(df)
    max_returned_rows = 5000
    max_saved_alerts = 500

    try:
        predictions = service.predict_batch(df)
    except (RuntimeError, ValueError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"CSV prediction failed: {e}",
        )

    rows = []
    alerts_saved = 0
    suspicious = 0

    for index, item in enumerate(predictions):
        if isinstance(item, dict):
            prediction = item.get("prediction", "UNKNOWN")
            confidence = float(item.get("confidence", 0.0))
            anomaly = bool(item.get("anomaly", False))
        else:
            prediction, confidence, anomaly = item
            confidence = float(confidence)
            anomaly = bool(anomaly)

        risk = risk_level(prediction, confidence, anomaly)

        row = {
            "prediction": prediction,
            "confidence": confidence,
            "anomaly": anomaly,
            "risk": risk,
        }

        if index < max_returned_rows:
            rows.append(row)

        if risk != "LOW":
            suspicious += 1

            if alerts_saved < max_saved_alerts:
                alert = Alert(
                    timestamp=datetime.utcnow(),
                    prediction=prediction,
                    confidence=confidence,
                    anomaly=int(anomaly),
                    risk=risk,
                    source_ip="CSV",
                    destination_ip="CSV",
                    details="Batch CSV prediction",
                )
                db.add(alert)
                alerts_saved += 1

    if alerts_saved:
        db.commit()

    return {
        "total": total_rows,
        "suspicious": suspicious,
        "alerts_saved": alerts_saved,
        "rows_returned": len(rows),
        "rows": rows,
    }


# ---------------------------------------------------------
# RECENT SECURITY ALERTS
# ---------------------------------------------------------
@app.get("/api/alerts")
def alerts(
    limit: int = 50,
    db: Session = Depends(get_db),
):
    safe_limit = max(1, min(limit, 200))

    items = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc())
        .limit(safe_limit)
        .all()
    )

    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "prediction": a.prediction,
            "confidence": a.confidence,
            "anomaly": bool(a.anomaly),
            "risk": a.risk,
            "source_ip": a.source_ip,
            "destination_ip": a.destination_ip,
            "details": a.details,
        }
        for a in items
    ]


# ---------------------------------------------------------
# ALERT STATISTICS
# ---------------------------------------------------------
@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    items = db.query(Alert).all()

    by_risk = {}
    by_attack = {}

    for alert in items:
        by_risk[alert.risk] = (
            by_risk.get(alert.risk, 0) + 1
        )
        by_attack[alert.prediction] = (
            by_attack.get(alert.prediction, 0) + 1
        )

    return {
        "alerts": len(items),
        "critical": by_risk.get("CRITICAL", 0),
        "high": by_risk.get("HIGH", 0),
        "medium": by_risk.get("MEDIUM", 0),
        "attack_types": by_attack,
    }
