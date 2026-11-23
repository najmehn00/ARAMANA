from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import Base, engine, get_db
from app.core.security import create_access_token, verify_password
from app.models.models import User
from app.modules.fraud_engine.router import router as fraud_router
from app.modules.hr.router import router as hr_router
from app.modules.supervision.router import router as supervision_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ARAMANA Intelligent Workforce Governance & Fraud Detection API",
    description="Unified prototype for HR Administration, Clinical Supervision, and Explainable AI Anomaly Detection.",
    version="1.0.0",
)

app.include_router(hr_router)
app.include_router(supervision_router)
app.include_router(fraud_router)


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/auth/login", tags=["Authentication"])
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is suspended or terminated")
    token = create_access_token(user.id, user.role, user.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"id": user.id, "full_name": user.full_name, "email": user.email, "role": user.role},
    }


@app.get("/api/auth/demo-accounts", tags=["Authentication"])
def list_demo_accounts(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return {
        "accounts": [
            {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role}
            for u in users
        ]
    }


@app.get("/", include_in_schema=False)
def serve_frontend():
    frontend_path = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
    if frontend_path.exists():
        return FileResponse(frontend_path)
    return {"message": "ARAMANA API is running. Visit /docs for Swagger UI."}
