from datetime import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.core.database import Base


# ==========================================
# CORE & SECURITY MODELS
# ==========================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(120), unique=True, index=True, nullable=False)
    full_name = Column(String(120), nullable=False)
    hashed_password = Column(String(256), nullable=False)
    role = Column(
        String(50),
        nullable=False,
        index=True,
        # Roles: platform_admin, hr_admin, clinical_supervisor, therapist, assistant_counselor, compliance_reviewer
    )
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    profile = relationship("ProfessionalProfile", back_populates="user", uselist=False)


class AccessEvent(Base):
    """Tracks API/resource access attempts (used for RBAC auditing & Scenario 4)."""
    __tablename__ = "access_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    user_role = Column(String(50), nullable=False)
    endpoint = Column(String(200), nullable=False)
    resource_type = Column(String(80), nullable=False)
    action = Column(String(40), nullable=False)
    is_authorized = Column(Boolean, nullable=False, index=True)
    ip_address = Column(String(50), default="127.0.0.1")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class AuditLog(Base):
    """Immutable audit trail for HR, clinical supervision, and investigation actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String(100), nullable=False)
    target_table = Column(String(80), nullable=False)
    target_id = Column(String(80), nullable=False)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


# ==========================================
# MODULE A: HR & ADMINISTRATION
# ==========================================

class ProfessionalProfile(Base):
    __tablename__ = "professional_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    specialization = Column(String(120), nullable=False)
    license_number = Column(String(80), unique=True, nullable=False)
    license_expiry = Column(DateTime, nullable=False)
    employment_status = Column(String(40), default="active")  # active, suspended, terminated
    contract_type = Column(String(50), default="full_time")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="profile")


class SupervisionAssignment(Base):
    __tablename__ = "supervision_assignments"

    id = Column(Integer, primary_key=True, index=True)
    supervisor_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    supervisee_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    effective_from = Column(DateTime, default=datetime.utcnow)
    effective_to = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)


# ==========================================
# MODULE B: CLINICAL SUPERVISION (SEPARATED DATA)
# ==========================================

class SessionRecord(Base):
    """Clinical session metadata. Uses pseudonymous client IDs (no real PII)."""
    __tablename__ = "session_records"

    id = Column(Integer, primary_key=True, index=True)
    therapist_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    client_pseudo_id = Column(String(64), nullable=False, index=True)
    scheduled_start = Column(DateTime, nullable=False)
    scheduled_end = Column(DateTime, nullable=False)
    actual_start = Column(DateTime, nullable=True)
    actual_end = Column(DateTime, nullable=True)
    status = Column(String(40), default="completed")  # scheduled, completed, cancelled, modified
    clinical_note_summary = Column(Text, nullable=True)  # Restricted to clinical roles only
    created_at = Column(DateTime, default=datetime.utcnow)


class ReferralRecord(Base):
    __tablename__ = "referral_records"

    id = Column(Integer, primary_key=True, index=True)
    assistant_counselor_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    therapist_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    client_pseudo_id = Column(String(64), nullable=False)
    referral_reason = Column(String(200), nullable=False)
    is_policy_assigned = Column(Boolean, default=False)  # Distinguishes legitimate policy/specialty routing
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class SupervisionReview(Base):
    __tablename__ = "supervision_reviews"

    id = Column(Integer, primary_key=True, index=True)
    supervisor_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    supervisee_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    session_id = Column(Integer, ForeignKey("session_records.id"), nullable=False)
    has_supporting_docs = Column(Boolean, default=True)
    decision = Column(String(40), nullable=False)  # pending, approved, needs_revision, escalated
    notes = Column(Text, nullable=True)
    reviewed_at = Column(DateTime, default=datetime.utcnow, index=True)


class CorrectiveAction(Base):
    __tablename__ = "corrective_actions"

    id = Column(Integer, primary_key=True, index=True)
    review_id = Column(Integer, ForeignKey("supervision_reviews.id"), nullable=False)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=False)
    description = Column(Text, nullable=False)
    due_date = Column(DateTime, nullable=False)
    status = Column(String(40), default="open")  # open, completed


# ==========================================
# MODULE C: AI FRAUD & ANOMALY DETECTION
# ==========================================

class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_uid = Column(String(40), unique=True, index=True, nullable=False)
    related_user_ids = Column(JSON, nullable=False)  # List of involved user IDs
    anomaly_category = Column(String(100), nullable=False, index=True)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    risk_score = Column(Float, nullable=False)  # 0 to 100
    risk_level = Column(String(20), nullable=False)  # Low, Medium, High, Critical
    detection_method = Column(String(80), nullable=False)  # rule_based, statistical, ml_isolation_forest, graph_analysis
    supporting_evidence = Column(JSON, nullable=False)
    explanation = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    investigation_status = Column(String(40), default="open", index=True)  # open, in_review, false_positive, escalated, closed


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("anomaly_alerts.id"), nullable=False, index=True)
    reviewer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    findings = Column(Text, nullable=False)
    resolution = Column(String(40), nullable=False)  # false_positive, escalated, closed, info_requested
    updated_at = Column(DateTime, default=datetime.utcnow)
