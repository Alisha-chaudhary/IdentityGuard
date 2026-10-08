from fastapi import FastAPI
from app.auth.routes import router as auth_router
from app.api.users import router as users_router
from app.api.roles import router as roles_router
from app.api.audit import router as audit_router
from app.api.jml import router as jml_router
from app.api.access_requests import router as access_requests_router

app = FastAPI(
    title="IdentityGuard",
    version="0.1.0",
    description=(
        "Identity. Access. Control"
        "IAM/PAM security platform for lifecycle management, governance, and privileged access"
    ),
)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(audit_router)
app.include_router(jml_router)
app.include_router(access_requests_router)

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "identityguard"}