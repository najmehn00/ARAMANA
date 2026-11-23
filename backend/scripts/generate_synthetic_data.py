"""
Synthetic Dataset Generator for ARAMANA Technical Challenge.
Generates normal baseline activity plus all 4 required anomalous scenarios:
  1. Therapist overlapping session intervals
  2. Abnormal referral concentration (vs. legitimate policy-assigned specialization)
  3. Rapid supervisor approvals lacking supporting documentation
  4. Unauthorized administrative access attempts
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Allow running from repo root or backend/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.database import Base, SessionLocal, engine
from app.core.security import hash_password
from app.models.models import (
    AccessEvent,
    AnomalyAlert,
    AuditLog,
    Investigation,
    ProfessionalProfile,
    ReferralRecord,
    SessionRecord,
    SupervisionAssignment,
    SupervisionReview,
    User,
)


def seed_synthetic_data():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    pw = hash_password("DemoPass123!")

    # 1. Create Users across all roles
    users_data = [
        ("compliance@aramana.ai", "Sara Ahmadi", "compliance_reviewer", "Compliance & Risk", "LIC-COMP-001"),
        ("admin@aramana.ai", "Reza Karimi", "platform_admin", "Platform Operations", "LIC-ADM-001"),
        ("hr@aramana.ai", "Mina Moradi", "hr_admin", "HR Governance", "LIC-HR-001"),
        ("sup1@aramana.ai", "Dr. Ali Tehrani", "clinical_supervisor", "Clinical Psychology", "LIC-SUP-101"),
        ("sup2@aramana.ai", "Dr. Neda Rahimi", "clinical_supervisor", "Trauma & CBT", "LIC-SUP-102"),
        ("therapist1@aramana.ai", "Dr. Omid Parsa", "therapist", "CBT", "LIC-TH-201"),
        ("therapist2@aramana.ai", "Dr. Hasti Nouri", "therapist", "Family Therapy", "LIC-TH-202"),
        ("therapist3@aramana.ai", "Dr. Kianosh Zarei", "therapist", "Trauma Specialist", "LIC-TH-203"),
        ("therapist4@aramana.ai", "Dr. Maryam Rad", "therapist", "Anxiety & Mood", "LIC-TH-204"),
        ("counselor1@aramana.ai", "Arman Javadi", "assistant_counselor", "Intake & Triage", "LIC-AC-301"),
        ("counselor2@aramana.ai", "Leila Shariati", "assistant_counselor", "Intake & Triage", "LIC-AC-302"),
    ]

    users = {}
    for email, name, role, spec, lic in users_data:
        u = User(email=email, full_name=name, hashed_password=pw, role=role)
        db.add(u)
        db.flush()
        db.add(ProfessionalProfile(
            user_id=u.id,
            specialization=spec,
            license_number=lic,
            license_expiry=now + timedelta(days=365),
            employment_status="active",
        ))
        users[email] = u

    # Supervision assignments
    db.add(SupervisionAssignment(supervisor_id=users["sup1@aramana.ai"].id, supervisee_id=users["therapist1@aramana.ai"].id))
    db.add(SupervisionAssignment(supervisor_id=users["sup1@aramana.ai"].id, supervisee_id=users["therapist2@aramana.ai"].id))
    db.add(SupervisionAssignment(supervisor_id=users["sup2@aramana.ai"].id, supervisee_id=users["therapist3@aramana.ai"].id))
    db.add(SupervisionAssignment(supervisor_id=users["sup2@aramana.ai"].id, supervisee_id=users["therapist4@aramana.ai"].id))

    # 2. Normal baseline sessions for therapists 2, 3, 4
    normal_sessions = []
    for idx, t_email in enumerate(["therapist2@aramana.ai", "therapist3@aramana.ai", "therapist4@aramana.ai"]):
        for day in range(1, 7):
            start = now - timedelta(days=day, hours=2 + idx)
            s = SessionRecord(
                therapist_id=users[t_email].id,
                client_pseudo_id=f"CL-{1000 + idx * 10 + day}",
                scheduled_start=start,
                scheduled_end=start + timedelta(minutes=50),
                actual_start=start,
                actual_end=start + timedelta(minutes=50),
                status="completed",
                clinical_note_summary="Standard follow-up session.",
            )
            db.add(s)
            normal_sessions.append(s)

    # SCENARIO 1: Therapist 1 has overlapping session intervals
    t1_id = users["therapist1@aramana.ai"].id
    overlap_base = now - timedelta(days=1, hours=4)
    db.add(SessionRecord(
        therapist_id=t1_id,
        client_pseudo_id="CL-9001",
        scheduled_start=overlap_base,
        scheduled_end=overlap_base + timedelta(minutes=60),
        status="completed",
        clinical_note_summary="Session A",
    ))
    db.add(SessionRecord(
        therapist_id=t1_id,
        client_pseudo_id="CL-9002",
        scheduled_start=overlap_base + timedelta(minutes=20),  # 40-min overlap!
        scheduled_end=overlap_base + timedelta(minutes=80),
        status="completed",
        clinical_note_summary="Session B (concurrent overlap)",
    ))
    db.add(SessionRecord(
        therapist_id=t1_id,
        client_pseudo_id="CL-9003",
        scheduled_start=overlap_base + timedelta(minutes=30),  # Another overlap!
        scheduled_end=overlap_base + timedelta(minutes=90),
        status="completed",
        clinical_note_summary="Session C (concurrent overlap)",
    ))

    # SCENARIO 2: Counselor 1 abnormally concentrates non-policy referrals on Therapist 2
    c1_id = users["counselor1@aramana.ai"].id
    for i in range(9):
        db.add(ReferralRecord(
            assistant_counselor_id=c1_id,
            therapist_id=users["therapist2@aramana.ai"].id,
            client_pseudo_id=f"CL-REF-{i}",
            referral_reason="General intake",
            is_policy_assigned=False,
        ))
    db.add(ReferralRecord(
        assistant_counselor_id=c1_id,
        therapist_id=users["therapist4@aramana.ai"].id,
        client_pseudo_id="CL-REF-99",
        referral_reason="General intake",
        is_policy_assigned=False,
    ))
    # Legitimate specialized policy referrals by Counselor 2 (should NOT trigger alert)
    c2_id = users["counselor2@aramana.ai"].id
    for i in range(6):
        db.add(ReferralRecord(
            assistant_counselor_id=c2_id,
            therapist_id=users["therapist3@aramana.ai"].id,
            client_pseudo_id=f"CL-POL-{i}",
            referral_reason="Trauma protocol assignment",
            is_policy_assigned=True,
        ))

    db.flush()

    # SCENARIO 3: Supervisor 2 rapidly approves 10 reviews within 15 minutes, 6 without docs
    sup2_id = users["sup2@aramana.ai"].id
    sample_session_id = normal_sessions[0].id
    for i in range(10):
        db.add(SupervisionReview(
            supervisor_id=sup2_id,
            supervisee_id=users["therapist3@aramana.ai"].id,
            session_id=sample_session_id,
            has_supporting_docs=(i >= 6),  # 6 missing docs!
            decision="approved",
            notes="Batch approved",
            reviewed_at=now - timedelta(minutes=20 - i),
        ))

    # SCENARIO 4: HR Admin attempts unauthorized access to restricted clinical records
    hr_id = users["hr@aramana.ai"].id
    for i in range(3):
        db.add(AccessEvent(
            user_id=hr_id,
            user_role="hr_admin",
            endpoint="/api/supervision/sessions",
            resource_type="clinical_records",
            action="GET",
            is_authorized=False,
            timestamp=now - timedelta(minutes=10 - i),
        ))

    db.commit()
    db.close()
    print("Synthetic dataset seeded successfully (normal + 4 anomalous scenarios).")


if __name__ == "__main__":
    seed_synthetic_data()
