# ARAMANA — Intelligent Workforce Governance, Clinical Supervision & AI Fraud Detection

A modular, explainable governance prototype built with **FastAPI**, **SQLAlchemy**, **scikit-learn**, **NetworkX**, and **Tailwind CSS**.

## Quick Start (Local Python)

1. **Activate your virtual environment and install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Seed the synthetic dataset (normal baseline + 4 anomalous scenarios):**
   ```bash
   cd backend
   python scripts/generate_synthetic_data.py
   ```

3. **Run automated tests (RBAC + all 4 detection scenarios):**
   ```bash
   pytest tests/test_scenarios.py -v
   ```

4. **Start the application:**
   ```bash
   uvicorn app.main:app --reload
   ```
   - **Web Dashboard:** http://127.0.0.1:8000/
   - **Interactive API Docs (Swagger):** http://127.0.0.1:8000/docs

## Demo Accounts (Password: `DemoPass123!`)
- `compliance@aramana.ai` (`compliance_reviewer`) — Full access to Fraud Alerts & Investigations
- `hr@aramana.ai` (`hr_admin`) — HR Profiles only (blocked from clinical records; triggers Scenario 4 if attempted)
- `sup1@aramana.ai` / `sup2@aramana.ai` (`clinical_supervisor`) — Supervision Dashboard & permitted clinical records
- `admin@aramana.ai` (`platform_admin`) — System & HR administration

## Project Structure
- `backend/app/core/`: Database connection, JWT auth, RBAC enforcement, Audit & Access logging
- `backend/app/modules/hr/`: Module A (Workforce & Organizational Structure)
- `backend/app/modules/supervision/`: Module B (Clinical Supervision & Quality)
- `backend/app/modules/fraud_engine/`: Module C (Rule-Based, Statistical HHI/Velocity, NetworkX Graph, IsolationForest)
- `backend/scripts/generate_synthetic_data.py`: Synthetic data & scenario injector
- `frontend/index.html`: Single-page functional web interface
- `docs/architecture.md`: Mermaid diagrams (System Architecture, ERD, RBAC Matrix)
