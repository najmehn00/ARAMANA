from collections import Counter
from typing import Dict
from sqlalchemy.orm import Session

from app.models.models import AnomalyAlert, ProfessionalProfile, SessionRecord, SupervisionReview, User


def compute_dashboard_analytics(db: Session) -> Dict:
    """
    Aggregates non-technical executive KPIs, category/risk distributions,
    and evaluation metrics (Precision, Recall, F1) against synthetic ground truth.
    """
    alerts = db.query(AnomalyAlert).all()
    total_professionals = db.query(ProfessionalProfile).count()
    active_professionals = db.query(ProfessionalProfile).filter(ProfessionalProfile.employment_status == "active").count()
    total_sessions = db.query(SessionRecord).count()
    total_reviews = db.query(SupervisionReview).count()

    by_category = dict(Counter(a.anomaly_category for a in alerts))
    by_risk = dict(Counter(a.risk_level for a in alerts))
    by_status = dict(Counter(a.investigation_status for a in alerts))

    # Ground-truth evaluation over the 4 core required synthetic scenarios
    expected_scenarios = {
        "therapist_overlapping_sessions": "therapist1@aramana.ai",
        "abnormal_referral_network": "counselor1@aramana.ai",
        "unusual_supervisor_approvals": "sup2@aramana.ai",
        "unauthorized_access_attempt": "hr@aramana.ai",
    }

    tp, fp, fn = 0, 0, 0
    per_scenario = []
    for cat, expected_email in expected_scenarios.items():
        user = db.query(User).filter(User.email == expected_email).first()
        matched_alerts = [a for a in alerts if a.anomaly_category == cat]
        if user and any(user.id in (a.related_user_ids or []) for a in matched_alerts):
            tp += 1
            detected = True
        else:
            fn += 1
            detected = False
        # Any alert marked false_positive by a human reviewer counts as FP
        fp_count = sum(1 for a in matched_alerts if a.investigation_status == "false_positive")
        fp += fp_count
        per_scenario.append({
            "scenario": cat,
            "detected": detected,
            "alerts_count": len(matched_alerts),
            "false_positives": fp_count,
        })

    precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 3) if (tp + fn) > 0 else 0.0
    f1 = round(2 * precision * recall / (precision + recall), 3) if (precision + recall) > 0 else 0.0

    return {
        "kpis": {
            "total_alerts": len(alerts),
            "critical_or_high": sum(1 for a in alerts if a.risk_level in ("Critical", "High")),
            "open_investigations": sum(1 for a in alerts if a.investigation_status in ("open", "in_review")),
            "active_professionals": active_professionals,
            "total_professionals": total_professionals,
            "total_sessions": total_sessions,
            "total_reviews": total_reviews,
        },
        "distributions": {
            "by_category": by_category,
            "by_risk_level": by_risk,
            "by_status": by_status,
        },
        "evaluation": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "per_scenario": per_scenario,
        },
    }
