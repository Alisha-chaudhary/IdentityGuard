from fastapi import FastAPI

app = FastAPI(
    title="IdentityGuard",
    version="0.1.0",
    description=(
        "Local IAM/PAM/access-governance security lab. "
        "Not a production system; not CyberArk, SailPoint, AD or Entra ID."
    ),
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "identityguard"}