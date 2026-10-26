# IdentityGuard

**An IAM Governance Lab I Built to Explore How Access Should Be Managed**

IdentityGuard is a portfolio-grade **identity governance and access-management lab**. It models how access is requested, approved, provisioned, reviewed, revoked, and recorded for audit across users, roles, and entitlements.

The project combines a **Python/FastAPI backend**, **SQLAlchemy + SQLite**, and a **React/Vite console**. The priority is not just authentication; it is **authorization and governance behavior**—especially the awkward cases that matter in real environments: self-approval attempts, privileged roles needing extra checks, segregation-of-duties (SoD) conflicts, JML transitions, access reviews that must survive in-flight changes, and externalized policy decisions.

> **Scope note:** IdentityGuard is a learning and portfolio project, not a commercial IAM/PAM product. Privileged access is simulated; there is no real credential vault, password rotation, or session recording. This repository is used to practise and discuss IAM concepts, not to claim production IAM/PAM operations experience.

---

## What IdentityGuard demonstrates

### Identity and authentication
- Argon2id password hashing.
- Generic login errors to avoid user enumeration.
- Login lockout and password-policy enforcement.
- Short-lived JWT sessions.

### Authorization and access governance
- Backend-enforced role-based access control.
- Permissions evaluated against current database state on protected requests.
- Access request -> approval -> provision workflow.
- Self-approval restrictions.
- Approver/provisioner separation for privileged roles.
- Joiner / mover / leaver (JML) handling.
- Segregation-of-duties (SoD) checks and violation reporting.
- Access reviews with assignment snapshots and self-review prevention.
- Tamper-evident, hash-chained audit trail.
- Access-control and governance reporting.

### Authorization as code
- Externalized role-assignment policy in `app/policies/identityguard_policy.json`.
- A small PBAC/ABAC policy engine in `app/authz/policy_engine.py`.
- Feature-flagged policy authorization in `app/iam/access_requests.py` (`IDENTITYGUARD_POLICY_AUTHZ`).
- Policy decisions recorded into the existing audit trail as `POLICY_DECISION`.
- Legacy permission checks remain the default path and run when the policy
  feature is disabled or no target user is present.

### Privileged access, simulated
- Privileged-access request flow.
- Approval and provisioning separation.
- Time-limited checkout concepts, expiry, and revocation.
- PAM activity reporting.
- Explicit documentation that no real credential vault exists.

### Delivery and engineering
- FastAPI application structure.
- SQLAlchemy models and sessions.
- Seed/demo scripts.
- Unit and API tests.
- React/Vite console for selected workflows.
- Docker configuration and CI workflow files.
- Environment-based configuration.

## Enterprise IAM concept mapping

| IdentityGuard capability | Enterprise IAM concept |
|---|---|
| RBAC + current-state permission checks | Role-Based Access Control and least privilege |
| Request/approve/provision | Entitlement request lifecycle |
| SoD conflict checks | Segregation of duties and control enforcement |
| JML transitions | Joiner/mover/leaver access lifecycle |
| Access reviews with snapshots | Periodic access certification / attestation |
| Reports and audit trail | Identity inventory, entitlement reporting, audit evidence |
| Simulated checkout/expiry/revocation | Privileged access management lifecycle concepts |
| Policy engine + JSON policy | Policy-Based Access Control as code |

## Implemented vs. simulated

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


## Run locally

```powershell
git clone https://github.com/Alisha-chaudhary/IdentityGuard.git
cd IdentityGuard
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Set local development secrets:

```powershell
$env:IDENTITYGUARD_JWT_SECRET = "<your-long-random-local-secret>"
$env:IDENTITYGUARD_SEED_PASSWORD = "<your-strong-local-demo-password>"
```

Initialize and start the API:

```powershell
python -m app.db.seed
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

Run workflows and tests:

```powershell
python -m scripts.smoke_login
python -m scripts.demo
python -m pytest -q
```

Enable the policy path only when testing it:

```powershell
$env:IDENTITYGUARD_POLICY_AUTHZ="true"
python -m pytest -q
```

## Frontend

```powershell
cd frontend
npm ci
npm run dev
```

## Docker

```powershell
docker compose up --build
```

## Repository map

```text
app/        API, authentication, authorization, audit, governance, IAM, PAM, policy engine, reports, database, core
frontend/   React + Vite review and reporting console
tests/      automated unit and API tests
scripts/    smoke-login and guided-demo utilities
docs/       demo walkthrough, deployment reference, and supporting documentation
deploy/     optional multi-stage Docker, compose, Kubernetes, and Jenkins reference assets
```

## Deployment Reference (Optional)

Optional non-production deployment assets are provided under deploy/ alongside the original Dockerfile and compose.yaml.

Included:
- deploy/docker/Dockerfile.multistage for a multi-stage FastAPI image
- deploy/docker/docker-compose.reference.yml for the reference image
- deploy/kubernetes/deployment.yaml and service.yaml as deployment reference manifests
- deploy/jenkins/Jenkinsfile as a simple pipeline reference
- docs/deployment-reference.md for build, health-check, compose, and Kubernetes notes

These assets are reference-only. They are not a claim of production cluster operation or enterprise deployment ownership.

## Current limitations

- **Simulated PAM:** no real credential vault, password rotation, or session recording.
- **Audit integrity:** hash chaining helps detect changes but is not tamper-proof.
- **Session handling:** logout is client-side; no server-side token denylist.
- **Abuse protection:** rate limiting is implemented on /auth/login (per-IP request window). Account lockout (per account, five failures / fifteen minutes) is a separate control.
- **Token revocation:** short-lived JWTs are issued with no server-side denylist; logout and compromise revocation are client-side/time-bound only.
- **Policy engine:** used only for privileged role assignment, behind `IDENTITYGUARD_POLICY_AUTHZ` (default off). When enabled, policy decisions are authoritative and fail-closed; the legacy permission path runs only when policy is disabled or `target_user` is absent.
- **Storage and schema changes:** SQLite without a migration framework. `create_all()` creates missing tables but does not add columns to existing tables; use Alembic or add new tables for LDAP/integration schema changes.
- **LDAP synchronization:** read-only against LDAP (no account creation, password changes, or group modifications). Dry-run by default; apply mode requires explicit operator action. Identity matching uses LDAP entryUUID; username matching is a candidate link only, never auto-merged. Disabled directory accounts result in local user being set to DISABLED, not deleted. Missing directory entries are never interpreted as deletion.
- **Vault integration:** Vault enforces its own policies independently; IdentityGuard approval does not substitute for Vault authorization. Vault tokens are never stored in IdentityGuard's database, logs, or audit reasons. Dev-mode Vault is used for the lab; not production-grade authentication.

## Why I am building it

I wanted a project that connects security principles to actual application behavior rather than just listing IAM terms. IdentityGuard lets me practise least privilege, approval separation, joiner-mover-leaver controls, segregation of duties, access reviews, privileged-access lifecycle concepts, policy-as-code, and auditability in one place.

I use it as a learning lab and a basis for technical discussion. It is **not** a claim of production IAM/PAM operations experience, and it does not claim CyberArk integration. The goal is to keep extending the project while being clear about what is implemented, what is simulated, and what still needs work.