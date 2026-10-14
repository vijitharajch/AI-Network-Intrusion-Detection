
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import pandas as pd

from pathlib import Path

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
# --------------------------------------------------
# Live traffic flow statistics (not AI predictions)
# --------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LIVE_FLOWS_CSV = PROJECT_ROOT / "data" / "live_flows" / "scapy_live_flows.csv"


@app.get("/api/live-flows")
def get_live_flows():
    if not LIVE_FLOWS_CSV.exists():
        return {"total": 0, "flows": [], "message": "No live-flow CSV found"}

    try:
        df = pd.read_csv(LIVE_FLOWS_CSV)
        df = df.where(pd.notnull(df), None)
        return {
            "total": len(df),
            "tcp": int((df["protocol"] == "TCP").sum()),
            "udp": int((df["protocol"] == "UDP").sum()),
            "total_packets": int(df["packets"].sum()),
            "total_bytes": int(df["bytes"].sum()),
            "flows": df.to_dict(orient="records"),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read live-flow CSV: {e}"
        )

# --------------------------------------------------
# Health check
# --------------------------------------------------
@app.get("/health")
def health():
    return {
        "status": "ok",
        "models_ready": service.ready
    }


# --------------------------------------------------
# Single network-flow prediction
# --------------------------------------------------
@app.post("/api/predict", response_model=PredictionResponse)
def predict(
    req: PredictionRequest,
    db: Session = Depends(get_db)
):
    try:
        prediction, confidence, anomaly = service.predict(req.features)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))

    risk = risk_level(prediction, confidence, anomaly)
    explanation = explain(prediction, confidence, anomaly, risk)

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
            details="; ".join(explanation)
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
        explanation=explanation
    )


# --------------------------------------------------
# CSV batch prediction using bounded chunks
# --------------------------------------------------

@app.post("/api/predict/csv")
def predict_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Upload a CSV file")

    if not service.ready:
        raise HTTPException(status_code=503, detail="Classifier is not trained")

    if not service.anomaly_ready:
        raise HTTPException(status_code=503, detail="Anomaly detector is not trained")

    chunk_size = 5000
    max_returned_rows = 5000
    max_saved_alerts = 500

    total = 0
    suspicious = 0
    saved_alerts = 0
    results = []

    try:
        chunks = pd.read_csv(
            file.file,
            chunksize=chunk_size,
            encoding_errors="replace"
        )

        for df in chunks:
            if df.empty:
                continue

            df.columns = df.columns.str.strip()

            # Run Random Forest and Isolation Forest together.
            batch_results = service.predict_batch(df)
            chunk_alerts = []

            for i, item in enumerate(batch_results):
                prediction = item["prediction"]
                confidence = item["confidence"]
                anomaly = item["anomaly"]

                risk = risk_level(prediction, confidence, anomaly)
                total += 1

                if risk != "LOW":
                    suspicious += 1

                    if saved_alerts < max_saved_alerts:
                        chunk_alerts.append(
                            Alert(
                                timestamp=datetime.utcnow(),
                                prediction=prediction,
                                confidence=confidence,
                                anomaly=int(anomaly),
                                risk=risk,
                                source_ip=str(
                                    df.iloc[i].get("Source IP", "unknown")
                                ),
                                destination_ip=str(
                                    df.iloc[i].get("Destination IP", "unknown")
                                ),
                                details=(
                                    f"Random Forest: {prediction}; "
                                    f"Isolation Forest anomaly: {anomaly}"
                                )
                            )
                        )
                        saved_alerts += 1

                if len(results) < max_returned_rows:
                    results.append({
                        "prediction": prediction,
                        "confidence": round(confidence, 4),
                        "anomaly": anomaly,
                        "risk": risk
                    })

            if chunk_alerts:
                db.add_all(chunk_alerts)
                db.commit()

        if total == 0:
            raise HTTPException(status_code=400, detail="CSV file is empty")

        return {
            "total": total,
            "suspicious": suspicious,
            "alerts_saved": saved_alerts,
            "rows_returned": len(results),
            "rows": results
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"CSV processing failed: {str(e)}"
        )
    finally:
        file.file.close()
#----------------------------------
# Recent security alerts
# --------------------------------------------------
@app.get("/api/alerts")
def alerts(
    limit: int = 50,
    db: Session = Depends(get_db)
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
            "details": a.details
        }
        for a in items
    ]


# --------------------------------------------------
# Dashboard statistics
# --------------------------------------------------
@app.get("/api/stats")
def stats(db: Session = Depends(get_db)):
    items = db.query(Alert).all()

    by_risk = {}
    by_attack = {}

    for alert in items:
        by_risk[alert.risk] = by_risk.get(alert.risk, 0) + 1
        by_attack[alert.prediction] = (
            by_attack.get(alert.prediction, 0) + 1
        )

    return {
        "alerts": len(items),
        "critical": by_risk.get("CRITICAL", 0),
        "high": by_risk.get("HIGH", 0),
        "medium": by_risk.get("MEDIUM", 0),
        "attack_types": by_attack
    }
