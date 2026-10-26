# IdentityGuard

An IAM governance and access-management lab I built to learn how access is requested, approved, reviewed, elevated and audited. Privileged access is **simulated**. This is a portfolio project and not production IAM or PAM software.

**Status** In active development.
**Live demo** [identity-guard-omega.vercel.app](https://identity-guard-omega.vercel.app/) (read-only demo user, synthetic data only, see [docs/DEMO.md](docs/DEMO.md))
**Stack** Python, FastAPI, SQLAlchemy, SQLite, Pytest, React

## Table of contents

1. [What it does](#what-it-does)
2. [Simulated PAM versus real PAM](#simulated-pam-versus-real-pam)
3. [Try the demo](#try-the-demo)
4. [Run it locally](#run-it-locally)
5. [Things I learnt](#things-i-learnt)
6. [Decisions I took](#decisions-i-took)
7. [Security review and known limitations](#security-review-and-known-limitations)
8. [Roadmap](#roadmap)

## What it does

| Area | What is implemented |
|---|---|
| Role-based access control | Roles, permissions and a permission-checked API |
| Joiner, mover, leaver | User lifecycle changes that update access and are written to the audit log |
| Access requests | Request and approval workflow |
| Separation of duties | Rules that block conflicting access |
| Access reviews | Review cycles with decisions, completion and a correction path |
| Simulated privileged access | Time-limited elevation that expires automatically |
| Audit chain | Tamper-evident audit events |
| Reports | Summary and governance reports built from the audit data |

<!-- VERIFY before commit: confirm each row above matches what is on main, especially reports and SoD. Remove any row that is still only on a local branch. -->

## Simulated PAM versus real PAM

| Area | Status |
|---|---|
| Argon2id password hashing | Implemented |
| JWT sessions | Implemented |
| Backend RBAC | Implemented |
| Access request/approval/provisioning | Implemented |
| JML transitions | Implemented |
| SoD checks and violation reports | Implemented |
| Access reviews and summaries | Implemented |
| Audit trail and reports | Implemented |
| Policy engine for privileged assignment | Implemented, feature-flagged, default off; authoritative and fail-closed when enabled |
| PAM lifecycle simulation | Simulated; no real credential vault/session recording |
| Audit integrity | Hash chain; not tamper-proof |
| SSO/OIDC/Keycloak | Not implemented |
| Rate limiting | Implemented on /auth/login (per-IP request window); account lockout is a separate per-account control |
| Database migrations | Not implemented (create_all only; introduce Alembic or add new tables for schema changes) |
| All workflows in frontend | Partial; several workflows are API-first |
| LDAP directory synchronization | Implemented (Phase 4-6): read-only client, dry-run sync, controlled apply mode. No LDAP writes. |
| Vault secret management | Implemented (Phase 7-8): read-only Vault client, KV v2 secrets engine, narrowly scoped policy, IdentityGuard approval workflow mediation. |

---

## LDAP Directory Synchronization (Phase 4-6)

IdentityGuard can synchronize with an OpenLDAP directory in a controlled,
read-first manner:

1. **Read-only discovery** (`app/ldap/client.py`): Connects to LDAP,
   searches users and groups, returns normalized records. Never writes to
   LDAP.
2. **Dry-run synchronization** (`app/ldap/sync.py`): Compares directory
   records against local IdentityGuard records and produces a change
   report. Default mode; no local changes.
3. **Controlled apply** (`DirectorySynchronizer.apply()`): Explicit
   operator action to apply approved changes (create users, assign/remove
   roles, disable accounts). Privileged roles are never auto-assigned.

New database tables (`external_identities`, `directory_group_mappings`,
`directory_sync_runs`, `directory_sync_changes`) track the mapping between
directory and local identities. All changes are audited.

### LDAP environment variables

| Variable | Default | Purpose |
|---|---|---|
| `IDENTITYGUARD_LDAP_ENABLED` | `false` | Master switch for sync |
| `IDENTITYGUARD_LDAP_URI` | `ldap://localhost:389` | LDAP server URI |
| `IDENTITYGUARD_LDAP_BIND_DN` | `` | Read-only bind DN |
| `IDENTITYGUARD_LDAP_BIND_PASSWORD` | `` | Read-only bind password (runtime only) |
| `IDENTITYGUARD_LDAP_BASE_DN` | `dc=example,dc=test` | Search base |
| `IDENTITYGUARD_LDAP_TIMEOUT` | `10` | Connection/operation timeout (seconds) |

---

## Vault Secret Management (Phase 7-8)

HashiCorp Vault manages synthetic test secrets used in the lab:

1. **Vault client** (`app/vault/client.py`): Read-only client using
   Vault's HTTP API with token authentication. Never logs or returns the
   Vault token.
2. **Vault integration** (`app/vault/integration.py`): Connects
   IdentityGuard's access request/approval workflow with Vault's own
   policy enforcement. IdentityGuard verifies an active approval grant;
   Vault independently enforces its policy. Secret values are never
   stored in IdentityGuard's database, logs, or audit reasons.
3. **API endpoints** (`app/api/vault.py`): `GET /vault/health`,
   `GET /vault/grant`, `GET /vault/secret/{path}`.

### Vault environment variables

| Variable | Default | Purpose |
|---|---|---|
| `IDENTITYGUARD_VAULT_ADDR` | `http://127.0.0.1:8200` | Vault server address |
| `IDENTITYGUARD_VAULT_TOKEN` | `` | Vault token (runtime only, never committed) |
| `IDENTITYGUARD_VAULT_SECRET_PATH` | `identityguard-lab/data/synthetic/test-secret` | Secret path |
| `IDENTITYGUARD_VAULT_TIMEOUT` | `10` | Request timeout (seconds) |
>>> feature/phase-9-documentation


| Capability | IdentityGuard | Enterprise PAM platform |
|---|---|---|
| Time-limited privilege elevation | Simulated with expiry | Yes |
| Approval before elevation | Yes | Yes |
| Audit trail of who had access and when | Yes | Yes |
| Credential vaulting | Not built | Yes |
| Automatic password rotation | Not built | Yes |
| Session isolation and recording | Not built | Yes |
| Directory integration (LDAP or AD) | Not built | Yes |

IdentityGuard teaches the governance and lifecycle side. It does not store or rotate real credentials and it does not broker sessions.

## Try the demo

The hosted demo signs in as a zero-privilege user on synthetic data, so nothing real can be changed. The backend sleeps when idle and can take up to a minute to wake. A guided walkthrough is in [docs/DEMO.md](docs/DEMO.md).

## Run it locally

```bash
git clone https://github.com/Alisha-chaudhary/IdentityGuard.git
cd IdentityGuard
python -m venv .venv
source .venv/bin/activate        # on Windows use .venv\Scripts\activate
pip install -r requirements.txt
pytest
uvicorn app.main:app --reload

```

## Things I learnt

1. **Authorization has to live on the server.** Hiding a button in the UI does not stop a request. The API checks a permission on every route, and the demo user is safe because the server refuses writes, not because the interface hides them.
2. **An audit log is only useful if it cannot be quietly edited.** Events are chained so tampering is detectable. When a review decision had the wrong reason, I added a correction event instead of changing the original record.
3. **Access reviews expose design conflicts.** My own admin account could not review its own IAM Administrator role without reviewing itself. Fixing that meant adding a separate reviewer role instead of making an exception.
4. **Simulating PAM taught me where the real product starts.** Expiring elevation and approvals cover the lifecycle. Vaulting, rotation and session recording are separate problems that I have not built.
5. **Reviewing my own code found real gaps.** A static scan and manual review turned up missing login rate limiting, no server-side token revocation and silent exception handling. Writing them up taught me to threat model the authentication path first.
6. **A status summary is not a test run.** I stopped trusting a reported pass count and started rerunning the suite before saying anything about it.
7. **Public demos need their own threat model.** Free hosting, cold starts and an open login endpoint are all things a visitor can reach, so the demo account has to be least privilege by design.

## Decisions I took

| Decision | Why | Trade-off |
|---|---|---|
| Simulate PAM instead of building a vault | Keeps scope honest and lets me focus on governance and lifecycle | No real credential handling |
| Permission-based authorization on the API | Roles can change without touching route code | More permissions to manage |
| Audit events are never edited or deleted | Keeps the chain trustworthy | Mistakes need correction events |
| Separate `access_review.correct` permission for IAM Administrators only | Corrections are powerful and should be rare | Extra permission to explain |
| Non-privileged Access Reviewer role (view and decide) | Removes the admin self-review conflict | One more role to seed and test |
| Zero-privilege demo user on synthetic data | Recruiters can explore with no risk | Visitors cannot try approvals themselves |
| SQLite and SQLAlchemy | Simple to run locally for a lab | No migration framework yet |
| Feature branches merged with `--no-ff`, small verified changes | Easy to see what changed and why | Slower than committing straight to main |
| Treat the first review cycle as a test cycle and use a clean second cycle for demos | Keeps demo data tidy without altering audit history | Two cycles to maintain |
| Call PAM simulated everywhere it appears | Avoids overclaiming | Less impressive wording |

## Security review and known limitations

I reviewed this project myself with Bandit and a manual read. The write-up is in [Secure-coding-review](https://github.com/Alisha-chaudhary/Secure-coding-review). I track each finding here.

| Finding | CWE | Status |
|---|---|---|
| No rate limiting on login | CWE-307 | Fixed |
| No server-side token revocation | CWE-613 | Open |
| Silent exception handling in the access-expiry sweeper | CWE-703 | Fixed |
| Broad exception fallback in access requests | CWE-703 | Fixed |
| No password history check | CWE-521 | Open |
| SQLite without migrations | CWE-1036 | Open |
| Detailed user information on the current-user endpoint | CWE-200 | Open |

- **Simulated PAM:** no real credential vault, password rotation, or session recording.
- **Audit integrity:** hash chaining helps detect changes but is not tamper-proof.
- **Session handling:** logout is client-side; no server-side token denylist.
- **Abuse protection:** rate limiting is implemented on `/auth/login` (per-IP request window). Account lockout (per account, five failures / fifteen minutes) is a separate control.
- **Token revocation:** short-lived JWTs are issued with no server-side denylist; logout and compromise revocation are client-side/time-bound only.
- **Policy engine:** used only for privileged role assignment, behind `IDENTITYGUARD_POLICY_AUTHZ` (default off). When enabled, policy decisions are authoritative and fail-closed; the legacy permission path runs only when policy is disabled or `target_user` is absent.
- **Storage and schema changes:** SQLite without a migration framework. `create_all()` creates missing tables but does not add columns to existing tables; use Alembic or add new tables for LDAP/integration schema changes.
- **LDAP synchronization:** read-only against LDAP (no account creation, password changes, or group modifications). Dry-run by default; apply mode requires explicit operator action. Identity matching uses LDAP entryUUID; username matching is a candidate link only, never auto-merged. Disabled directory accounts result in local user being set to DISABLED, not deleted. Missing directory entries are never interpreted as deletion.
- **Vault integration:** Vault enforces its own policies independently; IdentityGuard approval does not substitute for Vault authorization. Vault tokens are never stored in IdentityGuard's database, logs, or audit reasons. Dev-mode Vault is used for the lab; not production-grade authentication.

Other limits are listed in [Simulated PAM versus real PAM](#simulated-pam-versus-real-pam).

## Roadmap

- Hardening items from the security review
- GitHub Actions running the test suite
- Docker setup
- Frontend polish
- A tagged v1.0 release
