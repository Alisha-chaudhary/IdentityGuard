import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.access_requests import router as access_requests_router
from app.api.access_reviews import router as access_reviews_router
from app.api.audit import router as audit_router
from app.api.jml import router as jml_router
from app.api.pam import router as pam_router
from app.api.reports import router as reports_router
from app.api.roles import router as roles_router
from app.api.users import router as users_router
from app.auth.routes import router as auth_router
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.pam.service import expire_due_checkouts

logger = logging.getLogger("identityguard")

# How often the background sweeper moves overdue PAM checkouts to EXPIRED.
PAM_EXPIRY_SWEEP_SECONDS = 30


def _sweep_expired_checkouts() -> int:
    with SessionLocal() as db:
        return len(expire_due_checkouts(db))


async def _pam_expiry_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(_sweep_expired_checkouts)
        except Exception:  # never let the sweeper die
            logger.exception("PAM expiry sweep failed")
        await asyncio.sleep(PAM_EXPIRY_SWEEP_SECONDS)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Fresh clone: make sure every table exists so login does not 500.
    # (Creating tables is idempotent. Seeding is a separate, explicit step:
    #  `python -m app.db.seed`.)
    init_db()
    sweeper = asyncio.create_task(_pam_expiry_loop())
    try:
        yield
    finally:
        sweeper.cancel()


app = FastAPI(
    title="IdentityGuard",
    version="0.2.0",
    description=(
        "Identity. Access. Control. "
        "IAM/IGA governance lab with a simulated PAM checkout workflow."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://identity-guard-omega.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(audit_router)
app.include_router(jml_router)
app.include_router(access_requests_router)
app.include_router(access_reviews_router)
app.include_router(pam_router)
app.include_router(reports_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "identityguard"}
