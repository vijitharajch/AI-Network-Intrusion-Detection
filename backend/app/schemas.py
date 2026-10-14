from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class PredictionRequest(BaseModel):
    features: Dict[str, Any]
    source_ip: Optional[str] = "unknown"
    destination_ip: Optional[str] = "unknown"

class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    anomaly: bool
    risk: str
    source_ip: str
    destination_ip: str
    explanation: list[str] = Field(default_factory=list)
