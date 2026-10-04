from fastapi import FastAPI
from app.auth.routes import router as auth_router
from app.api.users import router as users_router
from app.api.roles import router as roles_router
from app.api.audit import router as audit_router

app = FastAPI(
    title="IdentityGuard",
    version="0.1.0",
    description=(
        "Local IAM/PAM/access-governance security lab. "
        "Not a production system; not CyberArk, SailPoint, AD or Entra ID."
    ),
)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(audit_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "identityguard"}