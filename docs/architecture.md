# ARAMANA Governance — Architecture & Design

## 1. System Architecture Diagram

```mermaid
flowchart TB
    UI["Web Dashboard (Role-Based UI)"] --> API["FastAPI Gateway + RBAC Middleware"]
    API --> Audit["AuditLog & AccessEvent Logger"]
    API --> ModA["Module A: HR & Admin"]
    API --> ModB["Module B: Clinical Supervision"]
    API --> ModC["Module C: AI Fraud & Anomaly Engine"]

    ModC --> Rules["Rule-Based Detector (Overlaps, Missing Docs, RBAC)"]
    ModC --> Stats["Statistical Detector (HHI Concentration, 1h Velocity)"]
    ModC --> Graph["NetworkX Referral Graph"]
    ModC --> ML["Scikit-Learn IsolationForest"]

    ModA --> DB[("Shared Relational DB\n(SQLite / PostgreSQL)")]
    ModB --> DB
    ModC --> DB
    Audit --> DB
```

## 2. Database Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    USERS ||--o| PROFESSIONAL_PROFILES : has
    USERS ||--o{ SUPERVISION_ASSIGNMENTS : supervises
    USERS ||--o{ SESSION_RECORDS : conducts
    USERS ||--o{ REFERRAL_RECORDS : refers
    USERS ||--o{ SUPERVISION_REVIEWS : reviews
    USERS ||--o{ ACCESS_EVENTS : generates
    SESSION_RECORDS ||--o{ SUPERVISION_REVIEWS : evaluated_in
    SUPERVISION_REVIEWS ||--o{ CORRECTIVE_ACTIONS : triggers
    ANOMALY_ALERTS ||--o{ INVESTIGATIONS : reviewed_in
```

## 3. Role & Permission Matrix (RBAC)

| Resource / Endpoint | `platform_admin` | `hr_admin` | `clinical_supervisor` | `therapist` | `compliance_reviewer` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| HR Profiles & Contracts | Read/Write | Read/Write | — | — | Read |
| Org Assignments | Read/Write | Read/Write | — | — | — |
| Clinical Session Notes | **Blocked (Logged)** | **Blocked (Logged)** | Assigned Only | Own Only | — |
| Supervision Reviews | Read | — | Read/Write | — | Read |
| Fraud Alerts & Scan | Read/Scan | — | Read/Investigate | — | Read/Scan/Investigate |
| Audit Logs | Read | — | — | — | Read |
