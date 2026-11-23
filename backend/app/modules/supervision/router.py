from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import log_audit, require_roles
from app.models.models import (
    CorrectiveAction,
    SessionRecord,
    SupervisionAssignment,
    SupervisionReview,
    User,
)

router = APIRouter(prefix="/api/supervision", tags=["Module B: Clinical Supervision & Quality Management"])


class SubmitReviewRequest(BaseModel):
    session_id: int
    has_supporting_docs: bool = True
    decision: str  # approved, needs_revision, escalated
    notes: str
    corrective_action_text: Optional[str] = None


@router.get("/dashboard")
def supervisor_dashboard(
    current_user: User = Depends(require_roles(["clinical_supervisor", "platform_admin", "compliance_reviewer"], "clinical_supervision")),
    db: Session = Depends(get_db),
):
    if current_user.role == "clinical_supervisor":
        assignments = (
            db.query(SupervisionAssignment)
            .filter(SupervisionAssignment.supervisor_id == current_user.id, SupervisionAssignment.is_active == True)
            .all()
        )
        supervisee_ids = [a.supervisee_id for a in assignments]
        reviews = db.query(SupervisionReview).filter(SupervisionReview.supervisor_id == current_user.id).all()
    else:
        assignments = db.query(SupervisionAssignment).filter(SupervisionAssignment.is_active == True).all()
        supervisee_ids = list({a.supervisee_id for a in assignments})
        reviews = db.query(SupervisionReview).all()

    escalated = [r for r in reviews if r.decision == "escalated"]
    needs_revision = [r for r in reviews if r.decision == "needs_revision"]
    open_actions = db.query(CorrectiveAction).filter(CorrectiveAction.status == "open").count()

    supervisees = db.query(User).filter(User.id.in_(supervisee_ids)).all() if supervisee_ids else []

    return {
        "assigned_supervisees_count": len(supervisees),
        "active_supervisees": sum(1 for u in supervisees if u.is_active),
        "total_reviews": len(reviews),
        "escalated_cases": len(escalated),
        "needs_revision_count": len(needs_revision),
        "open_corrective_actions": open_actions,
        "supervisees": [
            {"id": u.id, "full_name": u.full_name, "email": u.email, "is_active": u.is_active}
            for u in supervisees
        ],
        "recent_reviews": [
            {
                "id": r.id,
                "supervisor_id": r.supervisor_id,
                "supervisee_id": r.supervisee_id,
                "session_id": r.session_id,
                "has_supporting_docs": r.has_supporting_docs,
                "decision": r.decision,
                "notes": r.notes,
                "reviewed_at": r.reviewed_at.isoformat(),
            }
            for r in sorted(reviews, key=lambda x: x.reviewed_at, reverse=True)[:15]
        ],
    }


@router.get("/sessions")
def list_permitted_clinical_sessions(
    limit: int = 30,
    current_user: User = Depends(require_roles(["clinical_supervisor", "therapist"], "clinical_records")),
    db: Session = Depends(get_db),
):
    """
    Strictly restricted to clinical roles! HR Admins and Platform Admins without clinical
    scope are blocked and logged in access_events (demonstrating Scenario 4 & RBAC separation).
    """
    query = db.query(SessionRecord)
    if current_user.role == "therapist":
        query = query.filter(SessionRecord.therapist_id == current_user.id)
    elif current_user.role == "clinical_supervisor":
        assigned_ids = [
            a.supervisee_id
            for a in db.query(SupervisionAssignment)
            .filter(SupervisionAssignment.supervisor_id == current_user.id, SupervisionAssignment.is_active == True)
            .all()
        ]
        query = query.filter(SessionRecord.therapist_id.in_(assigned_ids))

    sessions = query.order_by(SessionRecord.scheduled_start.desc()).limit(limit).all()
    return {
        "sessions": [
            {
                "id": s.id,
                "therapist_id": s.therapist_id,
                "client_pseudo_id": s.client_pseudo_id,
                "scheduled_start": s.scheduled_start.isoformat(),
                "scheduled_end": s.scheduled_end.isoformat(),
                "status": s.status,
                "clinical_note_summary": s.clinical_note_summary,
            }
            for s in sessions
        ]
    }


@router.post("/reviews")
def submit_supervision_review(
    payload: SubmitReviewRequest,
    current_user: User = Depends(require_roles(["clinical_supervisor"], "clinical_supervision")),
    db: Session = Depends(get_db),
):
    session = db.query(SessionRecord).filter(SessionRecord.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session record not found")

    review = SupervisionReview(
        supervisor_id=current_user.id,
        supervisee_id=session.therapist_id,
        session_id=session.id,
        has_supporting_docs=payload.has_supporting_docs,
        decision=payload.decision,
        notes=payload.notes,
    )
    db.add(review)
    db.flush()

    if payload.corrective_action_text:
        action = CorrectiveAction(
            review_id=review.id,
            assigned_to=session.therapist_id,
            description=payload.corrective_action_text,
            due_date=datetime.utcnow() + timedelta(days=7),
        )
        db.add(action)

    db.commit()
    log_audit(
        db,
        current_user.id,
        "SUBMIT_SUPERVISION_REVIEW",
        "supervision_reviews",
        review.id,
        {"decision": payload.decision, "session_id": session.id},
    )
    return {"message": "Review recorded", "review_id": review.id}
