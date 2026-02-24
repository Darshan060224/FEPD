import hashlib
import json


class MLBridge:
    """Deterministic, explainable scoring for artifacts."""

    def __init__(self, model_name: str = "stub"):
        self.model_name = model_name

    def score_and_explain(self, artifact_path: str):
        # deterministic pseudo-score from path
        h = hashlib.sha256(artifact_path.encode('utf-8')).hexdigest()
        num = int(h[:8], 16)
        score = (num % 1000) / 1000.0  # 0.0 - 0.999
        reasons = []
        # simple heuristics for explainability
        if ".exe" in artifact_path.lower():
            reasons.append("executable file type")
        if any(x in artifact_path.lower() for x in ["payload", "malware", "susp"]):
            reasons.append("suspicious filename")
        if score > 0.8:
            reasons.append("outlier entropy/behavior model")
        if score < 0.2:
            reasons.append("low risk according to model")
        return {"score": round(score, 3), "reasons": reasons, "model": self.model_name}
