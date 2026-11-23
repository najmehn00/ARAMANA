from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import fraud_config
from app.core.database import get_db
from app.core.security import log_audit, require_roles
from app.models.models import AnomalyAlert, Investigation, User
from app.modules.fraud_engine.detector import run_full_detection_pipeline
from app.modules.fraud_engine.evaluator import compute_dashboard_analytics

router = APIRouter(prefix="/api/fraud", tags=["Module C: AI Fraud & Anomaly Detection"])


class InvestigateAlertRequest(BaseModel):
    findings: str
    resolution: str  # false_positive, escalated, closed, info_requested


@router.post("/scan")
def trigger_anomaly_scan(
    current_user: User = Depends(require_roles(["platform_admin", "compliance_reviewer"], "fraud_engine")),
    db: Session = Depends(get_db),
):
    summary = run_full_detection_pipeline(db)
    log_audit(db, current_user.id, "RUN_ANOMALY_SCAN", "anomaly_alerts", "batch", summary)
    return summary


@router.get("/analytics")
def get_fraud_analytics(
    current_user: User = Depends(require_roles(["platform_admin", "compliance_reviewer", "clinical_supervisor", "hr_admin"], "fraud_analytics")),
    db: Session = Depends(get_db),
):
    data = compute_dashboard_analytics(db)
    data["config"] = fraud_config.model_dump()
    return data


@router.get("/alerts")
def list_alerts(
    status_filter: str = None,
    risk_level: str = None,
    current_user: User = Depends(require_roles(["platform_admin", "compliance_reviewer", "clinical_supervisor"], "fraud_alerts")),
    db: Session = Depends(get_db),
):
    query = db.query(AnomalyAlert)
    if status_filter:
        query = query.filter(AnomalyAlert.investigation_status == status_filter)
    if risk_level:
        query = query.filter(AnomalyAlert.risk_level == risk_level)

    alerts = query.order_by(AnomalyAlert.risk_score.desc()).all()
    return {
        "count": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "alert_uid": a.alert_uid,
                "related_user_ids": a.related_user_ids,
                "anomaly_category": a.anomaly_category,
                "detected_at": a.detected_at.isoformat(),
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "detection_method": a.detection_method,
                "supporting_evidence": a.supporting_evidence,
                "explanation": a.explanation,
                "recommended_action": a.recommended_action,
                "investigation_status": a.investigation_status,
            }
            for a in alerts
        ],
    }


@router.post("/alerts/{alert_id}/investigate")
def investigate_alert(
    alert_id: int,
    payload: InvestigateAlertRequest,
    current_user: User = Depends(require_roles(["platform_admin", "compliance_reviewer", "clinical_supervisor"], "fraud_investigations")),
    db: Session = Depends(get_db),
):
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    valid_resolutions = {"false_positive", "escalated", "closed", "info_requested"}
    if payload.resolution not in valid_resolutions:
        raise HTTPException(status_code=400, detail=f"Resolution must be one of {valid_resolutions}")

    inv = Investigation(
        alert_id=alert.id,
        reviewer_id=current_user.id,
        findings=payload.findings,
        resolution=payload.resolution,
    )
    db.add(inv)
    alert.investigation_status = "in_review" if payload.resolution == "info_requested" else payload.resolution
    db.commit()

    log_audit(
        db,
        current_user.id,
        "INVESTIGATE_ALERT",
        "anomaly_alerts",
        alert.id,
        {"resolution": payload.resolution, "findings": payload.findings},
    )
    return {"message": "Investigation recorded", "alert_id": alert.id, "new_status": alert.investigation_status}
