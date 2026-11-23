from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import hash_password, log_audit, require_roles
from app.models.models import AuditLog, ProfessionalProfile, SupervisionAssignment, User

router = APIRouter(prefix="/api/hr", tags=["Module A: HR & Platform Administration"])


class CreateProfessionalRequest(BaseModel):
    email: str
    full_name: str
    password: str = "DemoPass123!"
    role: str  # therapist, assistant_counselor, clinical_supervisor
    specialization: str
    license_number: str
    license_expiry: datetime
    contract_type: str = "full_time"


class UpdateStatusRequest(BaseModel):
    employment_status: str  # active, suspended, terminated


class AssignSupervisorRequest(BaseModel):
    supervisor_id: int
    supervisee_id: int


@router.get("/professionals")
def list_professionals(
    current_user: User = Depends(require_roles(["platform_admin", "hr_admin", "compliance_reviewer"], "hr_profiles")),
    db: Session = Depends(get_db),
):
    profiles = db.query(ProfessionalProfile).all()
    result = []
    for p in profiles:
        result.append({
            "user_id": p.user.id,
            "full_name": p.user.full_name,
            "email": p.user.email,
            "role": p.user.role,
            "specialization": p.specialization,
            "license_number": p.license_number,
            "license_expiry": p.license_expiry.isoformat(),
            "employment_status": p.employment_status,
            "contract_type": p.contract_type,
        })
    return {"count": len(result), "professionals": result}


@router.post("/professionals")
def create_professional(
    payload: CreateProfessionalRequest,
    current_user: User = Depends(require_roles(["platform_admin", "hr_admin"], "hr_profiles")),
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.flush()

    profile = ProfessionalProfile(
        user_id=user.id,
        specialization=payload.specialization,
        license_number=payload.license_number,
        license_expiry=payload.license_expiry,
        contract_type=payload.contract_type,
    )
    db.add(profile)
    db.commit()

    log_audit(db, current_user.id, "CREATE_PROFESSIONAL", "professional_profiles", profile.id, {"role": payload.role})
    return {"message": "Professional onboarded", "user_id": user.id}


@router.patch("/professionals/{user_id}/status")
def update_employment_status(
    user_id: int,
    payload: UpdateStatusRequest,
    current_user: User = Depends(require_roles(["platform_admin", "hr_admin"], "hr_profiles")),
    db: Session = Depends(get_db),
):
    profile = db.query(ProfessionalProfile).filter(ProfessionalProfile.user_id == user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Professional profile not found")

    old_status = profile.employment_status
    profile.employment_status = payload.employment_status
    if payload.employment_status in ("suspended", "terminated"):
        profile.user.is_active = False
    elif payload.employment_status == "active":
        profile.user.is_active = True
    db.commit()

    log_audit(
        db,
        current_user.id,
        "UPDATE_EMPLOYMENT_STATUS",
        "professional_profiles",
        profile.id,
        {"old_status": old_status, "new_status": payload.employment_status},
    )
    return {"user_id": user_id, "employment_status": profile.employment_status}


@router.post("/assignments")
def assign_supervisor(
    payload: AssignSupervisorRequest,
    current_user: User = Depends(require_roles(["platform_admin", "hr_admin"], "org_structure")),
    db: Session = Depends(get_db),
):
    existing = (
        db.query(SupervisionAssignment)
        .filter(SupervisionAssignment.supervisee_id == payload.supervisee_id, SupervisionAssignment.is_active == True)
        .all()
    )
    for item in existing:
        item.is_active = False
        item.effective_to = datetime.utcnow()

    assignment = SupervisionAssignment(
        supervisor_id=payload.supervisor_id,
        supervisee_id=payload.supervisee_id,
        is_active=True,
    )
    db.add(assignment)
    db.commit()
    log_audit(
        db,
        current_user.id,
        "ASSIGN_SUPERVISOR",
        "supervision_assignments",
        assignment.id,
        {"supervisor_id": payload.supervisor_id, "supervisee_id": payload.supervisee_id},
    )
    return {"message": "Supervisor assigned", "assignment_id": assignment.id}


@router.get("/audit-logs")
def get_audit_logs(
    limit: int = 50,
    current_user: User = Depends(require_roles(["platform_admin", "compliance_reviewer"], "audit_logs")),
    db: Session = Depends(get_db),
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return {
        "logs": [
            {
                "id": l.id,
                "actor_id": l.actor_id,
                "action": l.action,
                "target_table": l.target_table,
                "target_id": l.target_id,
                "details": l.details,
                "timestamp": l.timestamp.isoformat(),
            }
            for l in logs
        ]
    }
