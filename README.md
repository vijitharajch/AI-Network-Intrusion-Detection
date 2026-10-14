# AI-Powered Network Intrusion Detection & Security Monitoring System

A machine-learning-assisted Network Intrusion Detection System (NIDS) that combines network traffic analysis, intrusion classification, anomaly detection, and a web-based security monitoring dashboard.

## Overview

The project demonstrates how machine learning can support network security monitoring by analyzing network-flow features, identifying potentially suspicious activity, and presenting detection results through a web interface.

## Features

- **Random Forest classification:** Classifies compatible network-flow feature records as `BENIGN` or `ATTACK`.
- **Isolation Forest:** Provides a separate anomaly-detection signal.
- **CSV-based detection:** Upload a compatible CSV file for batch predictions.
- **Alert management:** Stores detection alerts for dashboard review.
- **Network traffic monitoring:** Displays packet-capture flow statistics extracted using Scapy.
- **Interactive dashboard:** Displays alert statistics, attack distribution, recent alerts, and observed traffic.
- **REST API:** Provides endpoints for predictions, statistics, alerts, and service health.

## Technology Stack

| Component | Technology |
|---|---|
| Machine learning | Python, scikit-learn, joblib |
| Data processing | Pandas, NumPy |
| Network packet analysis | Scapy |
| Backend API | FastAPI, Uvicorn |
| Frontend | React, Vite |
| Dataset | CICIDS2017 |
| Version control | Git, GitHub |

## System Architecture

1. Network traffic is captured or supplied as a dataset.
2. Traffic records are processed into flow-level statistics.
3. Compatible feature records are passed to the trained machine-learning models.
4. The backend returns classification and anomaly-detection results.
5. Detection alerts are stored and made available to the dashboard.
6. The React frontend presents statistics, alerts, and observed network flows.

## Machine Learning Models

### Random Forest Classifier

The primary supervised model is trained for binary classification:

- `BENIGN` — predicted normal traffic.
- `ATTACK` — predicted potentially malicious traffic.

The model expects the 78 features used in the project's CICIDS2017 training pipeline.

### Isolation Forest

The unsupervised anomaly detector flags observations that differ from learned patterns. An anomaly flag is an indicator for investigation, not proof of malicious activity.

### Dataset

The project uses the CICIDS2017 intrusion-detection dataset.

The dataset and trained model artifacts are excluded from the Git repository. They must be obtained or regenerated locally using the appropriate training workflow.

## Project Structure

```text
nids_project/
├── backend/
│   └── app/
│       ├── main.py
│       └── model_service.py
├── frontend/
│   └── src/
├── ml/
├── docker/
├── docs/
├── data/                 # Local data; not committed
├── models/               # Local model artifacts; not committed
├── .gitignore
├── docker-compose.yml
└── README.md
```

## Local Development

### Prerequisites

- Python 3.11
- Node.js and npm
- Git

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd AI-Network-Intrusion-Detection
```

Replace the repository URL and directory name with the values for your repository.

### 2. Set up the backend

Create and activate a virtual environment:

```powershell
python -m venv venv311
.\venv311\Scripts\Activate.ps1
```

Install the Python dependencies using the dependency file included in the repository. Obtain or regenerate the required model artifacts before starting the API.

From the project root, start the backend:

```powershell
uvicorn backend.app.main:app --reload
```

Backend API: `http://127.0.0.1:8000`

Interactive API documentation: `http://127.0.0.1:8000/docs`

### 3. Set up the frontend

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, typically `http://localhost:5173`.

If required, configure `VITE_API_URL` to point to the backend API.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Check service and model readiness |
| GET | `/api/stats` | Retrieve dashboard statistics |
| GET | `/api/alerts` | Retrieve saved alerts |
| GET | `/api/live-flows` | Retrieve extracted traffic-flow statistics |
| POST | `/api/predict` | Predict a single compatible feature record |
| POST | `/api/predict/csv` | Run predictions on a compatible CSV file |

Visit `/docs` while the backend is running to inspect request and response schemas.

## Important Limitations

- The current packet-capture extractor produces 12 flow-statistic columns, while the Random Forest expects 78 CICIDS2017 features.
- The captured-flow display is not the same as continuous AI classification of live packets.
- Reliable live classification requires a compatible feature-extraction pipeline that calculates the required features consistently with the training process.
- Isolation Forest anomaly flags and Random Forest predictions are model outputs, not definitive proof of an attack.
- Evaluation results depend on the dataset, preprocessing, and validation method. Results from the same dataset should not be interpreted as proof of generalization to unseen networks.

## Future Improvements

- Integrate a validated live packet-to-flow feature-extraction pipeline.
- Add continuous inference and alert updates.
- Improve evaluation using independent test data.
- Add configurable detection thresholds and more detailed event investigation.
- Harden deployment, configuration, logging, and access control.

## Disclaimer

This project is an educational prototype for network-security monitoring and machine-learning experimentation. It is not a replacement for a production intrusion detection or prevention system.