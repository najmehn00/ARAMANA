import uuid
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List

import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.core.config import fraud_config
from app.models.models import (
    AccessEvent,
    AnomalyAlert,
    ReferralRecord,
    SessionRecord,
    SupervisionReview,
)


def score_to_risk_level(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def _alert_exists(db: Session, category: str, primary_user_id: int) -> bool:
    existing = (
        db.query(AnomalyAlert)
        .filter(AnomalyAlert.anomaly_category == category)
        .all()
    )
    for a in existing:
        if primary_user_id in (a.related_user_ids or []):
            return True
    return False


def detect_overlapping_sessions(db: Session) -> List[AnomalyAlert]:
    """
    Scenario 1 (Rule-Based Temporal Interval Overlap):
    Detects therapists with physically impossible overlapping session intervals.
    """
    alerts = []
    sessions = db.query(SessionRecord).filter(SessionRecord.status != "cancelled").all()
    by_therapist: Dict[int, List[SessionRecord]] = defaultdict(list)
    for s in sessions:
        by_therapist[s.therapist_id].append(s)

    for therapist_id, items in by_therapist.items():
        items.sort(key=lambda x: x.scheduled_start)
        overlaps = []
        for i in range(len(items) - 1):
            curr, nxt = items[i], items[i + 1]
            if curr.scheduled_end > nxt.scheduled_start:
                overlap_mins = int((curr.scheduled_end - nxt.scheduled_start).total_seconds() // 60)
                overlaps.append({
                    "session_a_id": curr.id,
                    "session_b_id": nxt.id,
                    "session_a_window": f"{curr.scheduled_start.isoformat()} -> {curr.scheduled_end.isoformat()}",
                    "session_b_window": f"{nxt.scheduled_start.isoformat()} -> {nxt.scheduled_end.isoformat()}",
                    "overlap_minutes": overlap_mins,
                })

        if overlaps and not _alert_exists(db, "therapist_overlapping_sessions", therapist_id):
            risk_score = min(
                98.0,
                fraud_config.overlap_base_score + len(overlaps) * fraud_config.overlap_penalty_per_pair,
            )
            alert = AnomalyAlert(
                alert_uid=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                related_user_ids=[therapist_id],
                anomaly_category="therapist_overlapping_sessions",
                risk_score=risk_score,
                risk_level=score_to_risk_level(risk_score),
                detection_method="rule_based",
                supporting_evidence={"overlap_count": len(overlaps), "overlapping_pairs": overlaps[:5]},
                explanation=(
                    f"Therapist #{therapist_id} has {len(overlaps)} overlapping session interval(s), "
                    f"which is physically impossible for concurrent clinical delivery."
                ),
                recommended_action="Audit affected session logs with Clinical Supervisor and verify client attendance records.",
                investigation_status="open",
            )
            db.add(alert)
            alerts.append(alert)
    return alerts


def detect_abnormal_referrals(db: Session) -> List[AnomalyAlert]:
    """
    Scenario 2 (Statistical HHI + NetworkX Graph Concentration):
    Identifies assistant counselors concentrating non-policy referrals onto a narrow group
    of therapists, while filtering out legitimate policy/specialty assignments.
    """
    alerts = []
    referrals = db.query(ReferralRecord).filter(ReferralRecord.is_policy_assigned == False).all()
    if not referrals:
        return alerts

    G = nx.DiGraph()
    by_counselor: Dict[int, List[int]] = defaultdict(list)
    for r in referrals:
        by_counselor[r.assistant_counselor_id].append(r.therapist_id)
        if G.has_edge(r.assistant_counselor_id, r.therapist_id):
            G[r.assistant_counselor_id][r.therapist_id]["weight"] += 1
        else:
            G.add_edge(r.assistant_counselor_id, r.therapist_id, weight=1)

    for counselor_id, therapist_ids in by_counselor.items():
        total = len(therapist_ids)
        if total < fraud_config.min_referrals_for_analysis:
            continue
        counts = Counter(therapist_ids)
        shares = [c / total for c in counts.values()]
        hhi = sum(s ** 2 for s in shares)
        top_therapist_id, top_count = counts.most_common(1)[0]
        top_share = top_count / total

        if hhi >= fraud_config.hhi_threshold and top_share >= fraud_config.top_share_threshold:
            if not _alert_exists(db, "abnormal_referral_network", counselor_id):
                risk_score = round(min(95.0, 50.0 + hhi * 45.0), 1)
                alert = AnomalyAlert(
                    alert_uid=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    related_user_ids=[counselor_id, top_therapist_id],
                    anomaly_category="abnormal_referral_network",
                    risk_score=risk_score,
                    risk_level=score_to_risk_level(risk_score),
                    detection_method="statistical_and_graph_analysis",
                    supporting_evidence={
                        "total_non_policy_referrals": total,
                        "unique_therapists_referred": len(counts),
                        "hhi_concentration_index": round(hhi, 3),
                        "top_therapist_id": top_therapist_id,
                        "top_therapist_share": round(top_share, 3),
                        "graph_edge_weight": G[counselor_id][top_therapist_id]["weight"],
                    },
                    explanation=(
                        f"Assistant Counselor #{counselor_id} directed {round(top_share * 100, 1)}% "
                        f"({top_count}/{total}) of non-policy referrals to Therapist #{top_therapist_id} "
                        f"(HHI={round(hhi, 2)}), deviating significantly from peer distribution."
                    ),
                    recommended_action="Review referral justification notes and check for undisclosed personal or financial ties.",
                    investigation_status="open",
                )
                db.add(alert)
                alerts.append(alert)
    return alerts


def detect_unusual_supervisor_approvals(db: Session) -> List[AnomalyAlert]:
    """
    Scenario 3 (Statistical Velocity + Missing Documentation Rule):
    Detects supervisors approving an abnormally high volume of reviews in a short window,
    especially when required supporting documentation is missing.
    """
    alerts = []
    reviews = db.query(SupervisionReview).filter(SupervisionReview.decision == "approved").all()
    by_supervisor: Dict[int, List[SupervisionReview]] = defaultdict(list)
    for r in reviews:
        by_supervisor[r.supervisor_id].append(r)

    for sup_id, items in by_supervisor.items():
        if len(items) < fraud_config.min_reviews_for_velocity:
            continue
        items.sort(key=lambda x: x.reviewed_at)
        missing_docs = [r for r in items if not r.has_supporting_docs]
        max_in_hour = 0
        for i, r in enumerate(items):
            window_end = r.reviewed_at + timedelta(minutes=60)
            count = sum(1 for x in items[i:] if x.reviewed_at <= window_end)
            max_in_hour = max(max_in_hour, count)

        missing_ratio = len(missing_docs) / len(items)
        if max_in_hour >= fraud_config.max_approvals_per_hour or (
            len(missing_docs) >= 3 and missing_ratio >= fraud_config.missing_doc_ratio_threshold
        ):
            if not _alert_exists(db, "unusual_supervisor_approvals", sup_id):
                risk_score = round(min(96.0, 55.0 + max_in_hour * 2.0 + missing_ratio * 30.0), 1)
                alert = AnomalyAlert(
                    alert_uid=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    related_user_ids=[sup_id],
                    anomaly_category="unusual_supervisor_approvals",
                    risk_score=risk_score,
                    risk_level=score_to_risk_level(risk_score),
                    detection_method="statistical_velocity_and_rule",
                    supporting_evidence={
                        "total_approvals": len(items),
                        "max_approvals_in_1h": max_in_hour,
                        "approvals_without_docs": len(missing_docs),
                        "missing_docs_ratio": round(missing_ratio, 3),
                        "sample_review_ids": [r.id for r in missing_docs[:5]],
                    },
                    explanation=(
                        f"Supervisor #{sup_id} approved up to {max_in_hour} reviews within 60 minutes, "
                        f"including {len(missing_docs)} record(s) lacking required supporting documentation."
                    ),
                    recommended_action="Re-audit flagged approvals and require missing clinical documentation before sign-off.",
                    investigation_status="open",
                )
                db.add(alert)
                alerts.append(alert)
    return alerts


def detect_unauthorized_admin_activity(db: Session) -> List[AnomalyAlert]:
    """
    Scenario 4 (Security / RBAC Violation Detection):
    Detects administrative or non-clinical accounts attempting to access/modify restricted records.
    """
    alerts = []
    violations = db.query(AccessEvent).filter(AccessEvent.is_authorized == False).all()
    by_user: Dict[int, List[AccessEvent]] = defaultdict(list)
    for v in violations:
        by_user[v.user_id].append(v)

    for user_id, events in by_user.items():
        if not _alert_exists(db, "unauthorized_access_attempt", user_id):
            risk_score = round(min(99.0, 70.0 + len(events) * 6.0), 1)
            endpoints = list({e.endpoint for e in events})
            alert = AnomalyAlert(
                alert_uid=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                related_user_ids=[user_id],
                anomaly_category="unauthorized_access_attempt",
                risk_score=risk_score,
                risk_level=score_to_risk_level(risk_score),
                detection_method="rule_based_security_audit",
                supporting_evidence={
                    "violation_count": len(events),
                    "user_role": events[0].user_role,
                    "attempted_endpoints": endpoints,
                    "latest_attempt": max(e.timestamp for e in events).isoformat(),
                },
                explanation=(
                    f"Account #{user_id} (role: {events[0].user_role}) made {len(events)} unauthorized "
                    f"attempt(s) to access restricted resources ({', '.join(endpoints)})."
                ),
                recommended_action="Escalate to Platform Security & Compliance Reviewer; verify if account credentials are compromised.",
                investigation_status="open",
            )
            db.add(alert)
            alerts.append(alert)
    return alerts


def detect_ml_behavioral_outliers(db: Session) -> List[AnomalyAlert]:
    """
    Unsupervised ML Layer (IsolationForest):
    Computes per-therapist behavioral features (session volume, cancellation rate, avg duration)
    to surface multi-feature outliers not caught by static thresholds alone.
    """
    alerts = []
    sessions = db.query(SessionRecord).all()
    if len(sessions) < 10:
        return alerts

    rows = []
    by_therapist: Dict[int, List[SessionRecord]] = defaultdict(list)
    for s in sessions:
        by_therapist[s.therapist_id].append(s)

    for tid, items in by_therapist.items():
        total = len(items)
        cancelled = sum(1 for x in items if x.status == "cancelled")
        durations = [(x.scheduled_end - x.scheduled_start).total_seconds() / 60.0 for x in items]
        rows.append({
            "therapist_id": tid,
            "session_count": total,
            "cancel_rate": cancelled / total if total else 0.0,
            "avg_duration_mins": float(np.mean(durations)) if durations else 0.0,
        })

    df = pd.DataFrame(rows)
    if len(df) < 4:
        return alerts

    features = df[["session_count", "cancel_rate", "avg_duration_mins"]]
    model = IsolationForest(contamination=fraud_config.isolation_forest_contamination, random_state=42)
    df["pred"] = model.fit_predict(features)
    df["anomaly_score"] = model.decision_function(features)

    for _, row in df[df["pred"] == -1].iterrows():
        tid = int(row["therapist_id"])
        if not _alert_exists(db, "ml_behavioral_outlier", tid):
            risk_score = round(min(85.0, max(45.0, 60.0 - float(row["anomaly_score"]) * 100.0)), 1)
            alert = AnomalyAlert(
                alert_uid=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                related_user_ids=[tid],
                anomaly_category="ml_behavioral_outlier",
                risk_score=risk_score,
                risk_level=score_to_risk_level(risk_score),
                detection_method="ml_isolation_forest",
                supporting_evidence={
                    "session_count": int(row["session_count"]),
                    "cancel_rate": round(float(row["cancel_rate"]), 3),
                    "avg_duration_mins": round(float(row["avg_duration_mins"]), 1),
                    "isolation_forest_score": round(float(row["anomaly_score"]), 4),
                },
                explanation=(
                    f"IsolationForest flagged Therapist #{tid} as a multi-feature behavioral outlier "
                    f"(sessions={int(row['session_count'])}, cancel_rate={round(float(row['cancel_rate'])*100, 1)}%, "
                    f"avg_duration={round(float(row['avg_duration_mins']), 1)}m)."
                ),
                recommended_action="Review longitudinal workload and cancellation patterns during next supervision cycle.",
                investigation_status="open",
            )
            db.add(alert)
            alerts.append(alert)
    return alerts


def run_full_detection_pipeline(db: Session) -> Dict:
    created = []
    created.extend(detect_overlapping_sessions(db))
    created.extend(detect_abnormal_referrals(db))
    created.extend(detect_unusual_supervisor_approvals(db))
    created.extend(detect_unauthorized_admin_activity(db))
    created.extend(detect_ml_behavioral_outliers(db))
    db.commit()
    return {
        "new_alerts_generated": len(created),
        "categories": dict(Counter(a.anomaly_category for a in created)),
    }
