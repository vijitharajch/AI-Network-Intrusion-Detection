def risk_level(prediction: str, confidence: float, anomaly: bool) -> str:
    normal = prediction.strip().lower() in {"normal", "benign", "benign traffic"}
    if normal and not anomaly:
        return "LOW"
    if anomaly and confidence >= 0.80:
        return "CRITICAL"
    if prediction.lower() in {"dos", "ddos", "bot", "botnet", "infiltration"}:
        return "HIGH"
    if anomaly or confidence < 0.70:
        return "MEDIUM"
    return "HIGH"

def explain(prediction: str, confidence: float, anomaly: bool, risk: str):
    reasons = [f"Classifier prediction: {prediction}", f"Model confidence: {confidence:.1%}"]
    if anomaly:
        reasons.append("Isolation Forest flagged the flow as anomalous")
    else:
        reasons.append("Isolation Forest did not flag the flow as anomalous")
    reasons.append(f"Risk engine assigned {risk} risk")
    return reasons
