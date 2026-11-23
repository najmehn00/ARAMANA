import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app
from scripts.generate_synthetic_data import seed_synthetic_data

client = TestClient(app)


def _login(email: str) -> str:
    res = client.post("/api/auth/login", json={"email": email, "password": "DemoPass123!"})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_rbac_separates_clinical_records_from_hr():
    seed_synthetic_data()
    hr_token = _login("hr@aramana.ai")
    res = client.get("/api/supervision/sessions", headers={"Authorization": f"Bearer {hr_token}"})
    assert res.status_code == 403


def test_all_four_required_scenarios_and_investigation_workflow():
    seed_synthetic_data()
    comp_token = _login("compliance@aramana.ai")

    scan_res = client.post("/api/fraud/scan", headers={"Authorization": f"Bearer {comp_token}"})
    assert scan_res.status_code == 200
    categories = scan_res.json()["categories"]

    assert "therapist_overlapping_sessions" in categories
    assert "abnormal_referral_network" in categories
    assert "unusual_supervisor_approvals" in categories
    assert "unauthorized_access_attempt" in categories

    # Verify executive analytics & evaluation metrics
    analytics_res = client.get("/api/fraud/analytics", headers={"Authorization": f"Bearer {comp_token}"})
    assert analytics_res.status_code == 200
    eval_data = analytics_res.json()["evaluation"]
    assert eval_data["precision"] == 1.0
    assert eval_data["recall"] == 1.0
    assert eval_data["f1_score"] == 1.0

    alerts_res = client.get("/api/fraud/alerts", headers={"Authorization": f"Bearer {comp_token}"})
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()["alerts"]
    assert len(alerts) >= 4

    # Verify explainable fields and human investigation workflow
    first_alert = alerts[0]
    assert first_alert["explanation"]
    assert first_alert["supporting_evidence"]

    inv_res = client.post(
        f"/api/fraud/alerts/{first_alert['id']}/investigate",
        headers={"Authorization": f"Bearer {comp_token}"},
        json={"findings": "Verified overlap in session logs.", "resolution": "escalated"},
    )
    assert inv_res.status_code == 200
    assert inv_res.json()["new_status"] == "escalated"
