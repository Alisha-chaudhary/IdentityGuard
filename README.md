# IdentityGuard
### IAM / IGA Governance Lab — access requests, SoD, access reviews, simulated PAM checkout, tamper-evident audit

IdentityGuard is a **local learning and portfolio project** (FastAPI · SQLAlchemy/SQLite · React/Vite) that models how access is *requested, approved, provisioned, reviewed and audited* — not just how login works.
It is **not** a commercial IAM/PAM product.

## What is real and what is simulated

| Area | Status | Notes |
|:--|:--|:--|
| Backend-enforced RBAC | **Implemented, tested** | Every non-public route uses `require_permission`; permissions are recomputed from the DB on every request, so role expiry/termination apply immediately. An endpoint matrix test enforces this for every route. |
| Authentication | **Implemented, tested** | Argon2id, generic 401s, dummy-hash timing mitigation, lockout (5 failures / 15 min), 15-min JWT, change-password with policy. |
| Access request → approve → provision | **Implemented, tested** | Requester **and target** cannot approve; privileged roles need `role.assign_privileged`; approver ≠ provisioner for privileged roles (four-eyes). |
| Segregation of duties | **Implemented, tested** | 3 hard-coded rules, enforced at provisioning (SOD_VIOLATION audited) + a report of conflicts that already exist. No policy engine. |
| Access reviews | **Implemented, tested** | Snapshot of assignments, self-review denied, atomic revocation, skipped if the assignment changed. |
| JML | **Implemented** | Joiner (password policy enforced), mover (keeps roles by design — the access review is the compensating control), leaver (expires roles, revokes PAM checkouts, closes open requests; cannot terminate self or the last admin). `user.create` / `user.move` / `user.terminate` are separate permissions. |
| Audit log | **Implemented, tested** | Hash-chained, append-only via SQLite triggers, written in the same transaction as the change. **Tamper-evident, not tamper-proof** (unkeyed SHA-256; someone with DB access can rebuild the chain). |
| **PAM** | **Simulated** | Request → approve → time-limited checkout → expire/revoke/end, all audited. **No credential vault, no password rotation, no session recording.** Expiry is enforced by a background sweeper (30 s) and `POST /pam/checkouts/expire-due`. |
| Frontend | **Partial** | Login, reports and access-review actions only. Everything else is API-only (use `/docs`). |
| Docker / CI | **Config provided** | CI runs tests, a fresh-clone smoke test, a Docker build + health check and the frontend build. Treat them as working only after you have seen a green run. |

## Quick start (fresh clone)

```powershell
git clone https://github.com/Alisha-chaudhary/IdentityGuard.git
cd IdentityGuard
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# 1. Choose secrets (never commit them)
$env:IDENTITYGUARD_JWT_SECRET = "<long random string>"
$env:IDENTITYGUARD_SEED_PASSWORD = "Choose-A-Str0ng-Passw0rd"   # shared by all demo users

# 2. Create tables + demo data (idempotent)
python -m app.db.seed

# 3. Run the API
python -m uvicorn app.main:app --reload      # http://127.0.0.1:8000/docs

# 4. Prove it works (second terminal, same env vars)
python -m scripts.smoke_login                # boots app, logs in as admin
python -m scripts.demo                       # full guided demo (about 2 minutes)
python -m pytest -q                          # 330+ tests
```

Demo logins (all use `IDENTITYGUARD_SEED_PASSWORD`): `identityguard.admin`, `identityguard.admin2` (two IAM administrators, required for four-eyes), `auditor`, `reviewer`, and the business users `priya.nair`, `rahul.mehta`, `meera.iyer` (stale-access case), `lisa`, `kiran.reddy` (PAM operators), `sneha.rao`, `arjun.verma`.
Without seeding, the API starts and creates tables but nobody can log in.

Frontend: `cd frontend; npm ci; npm run dev` (needs the backend on :8000).

Docker: set `IDENTITYGUARD_JWT_SECRET` and `IDENTITYGUARD_SEED_PASSWORD`, then `docker compose up --build`. The image runs as a non-root user and seeds on first start.

See **docs/DEMO.md** for the demo story and what each step proves.

## Configuration

| Variable | Purpose |
|:--|:--|
| `IDENTITYGUARD_DATABASE_URL` | SQLAlchemy URL (default `sqlite:///./identityguard.db`) |
| `IDENTITYGUARD_JWT_SECRET` | Signing secret. **Set it**: otherwise a random per-process secret is used and tokens die on restart (a warning is logged). |
| `IDENTITYGUARD_SEED_PASSWORD` | Password for demo users; a random one is generated and printed if unset. |
| `IDENTITYGUARD_AUTO_SEED` | Docker only: `true` runs the seed before the API starts. |

## Known limitations (be upfront about these)

- Logout is client-side; tokens (15 min) cannot be revoked server-side (no `jti` denylist).
- No rate limiting; a targeted lockout of a known username is possible. Failed logins for unknown usernames and every 403 are audited, so the log can be flooded.
- Audit chain is unkeyed; truncating the tail of the log is not detectable.
- SQLite, no migrations (schema changes need a new database); seed mutates RBAC on existing databases.
- SoD rules are code constants; mover flow does not remove old access automatically.
- No SSO/OIDC/Keycloak integration and no commercial IAM/PAM product experience is claimed.

## Project layout

```text
app/        api/ auth/ authz/ audit/ governance/ iam/ pam/ reports/ db/ core/
frontend/   React + Vite review & report console
tests/      unit/ and api/ (incl. endpoint authorization matrix)
scripts/    smoke_login.py, demo.py, docker-entrypoint.sh
docs/       DEMO.md
```
