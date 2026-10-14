# Development Plan

## Phase 1 — ML foundation
1. Obtain CICIDS2017.
2. Merge CSV flow files.
3. Normalize column names and labels.
4. Remove non-numeric identifiers where appropriate.
5. Train Random Forest classifier.
6. Train Isolation Forest only on normal traffic.
7. Save classifier, anomaly model and exact feature list.
8. Record precision, recall, macro F1 and confusion matrix.

## Phase 2 — API
- FastAPI health endpoint
- Single-flow prediction
- CSV batch prediction
- Alert persistence
- Statistics endpoint

## Phase 3 — Dashboard
- Alert counters
- Attack distribution
- Batch analysis
- Recent alerts
- Risk badges

## Phase 4 — Live traffic
- Capture packets with TShark/Wireshark
- Convert packets into the same flow features used during training
- Feed flows into `/api/predict`
- Persist alerts
- Refresh dashboard automatically

## Phase 5 — Production hardening
- PostgreSQL
- Docker
- authentication/RBAC
- rate limiting
- structured logs
- model versioning
- calibration and threshold tuning
- cross-dataset evaluation with UNSW-NB15
