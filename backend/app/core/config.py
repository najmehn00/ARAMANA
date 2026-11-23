import os
from pydantic import BaseModel


class FraudEngineConfig(BaseModel):
    """Configurable thresholds for the hybrid fraud & anomaly detection engine."""
    hhi_threshold: float = float(os.getenv("FRAUD_HHI_THRESHOLD", "0.45"))
    top_share_threshold: float = float(os.getenv("FRAUD_TOP_SHARE_THRESHOLD", "0.55"))
    min_referrals_for_analysis: int = int(os.getenv("FRAUD_MIN_REFERRALS", "5"))

    max_approvals_per_hour: int = int(os.getenv("FRAUD_MAX_APPROVALS_1H", "8"))
    missing_doc_ratio_threshold: float = float(os.getenv("FRAUD_MISSING_DOC_RATIO", "0.30"))
    min_reviews_for_velocity: int = int(os.getenv("FRAUD_MIN_REVIEWS", "5"))

    overlap_base_score: float = float(os.getenv("FRAUD_OVERLAP_BASE_SCORE", "65.0"))
    overlap_penalty_per_pair: float = float(os.getenv("FRAUD_OVERLAP_PENALTY", "10.0"))

    isolation_forest_contamination: float = float(os.getenv("FRAUD_IF_CONTAMINATION", "0.15"))


fraud_config = FraudEngineConfig()
