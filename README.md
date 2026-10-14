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
- Legacy permission checks remain the default and fallback path.

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
| Policy engine for privileged assignment | Implemented, feature-flagged, default off |
| PAM lifecycle simulation | Simulated; no real credential vault/session recording |
| Audit integrity | Hash chain; not tamper-proof |
| SSO/OIDC/Keycloak | Not implemented |
| Rate limiting | Not implemented |
| Database migrations | Not implemented |
| All workflows in frontend | Partial; several workflows are API-first |

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
- **Abuse protection:** rate limiting is not implemented yet.
- **Storage and schema changes:** SQLite without a migration framework.
- **Governance rules:** SoD rules are defined in application code; mover workflow retains roles by design, with access review as compensating control.
- **Integrations and UI:** no SSO/OIDC or Keycloak integration; frontend does not expose every workflow.
- **Policy engine:** currently used only for privileged role assignment, behind a feature flag with legacy fallback.

## Why I am building it

I wanted a project that connects security principles to actual application behavior rather than just listing IAM terms. IdentityGuard lets me practise least privilege, approval separation, joiner-mover-leaver controls, segregation of duties, access reviews, privileged-access lifecycle concepts, policy-as-code, and auditability in one place.

I use it as a learning lab and a basis for technical discussion. It is **not** a claim of production IAM/PAM operations experience, and it does not claim CyberArk integration. The goal is to keep extending the project while being clear about what is implemented, what is simulated, and what still needs work.