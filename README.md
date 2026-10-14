# IdentityGuard

**An IAM Governance Lab I Built to Explore How Access Should Be Managed**

IdentityGuard is a portfolio-grade **identity governance and access-management lab**. It models how access is requested, approved, provisioned, reviewed, revoked, and recorded for audit across users, roles, and entitlements.

The project combines a **Python/FastAPI backend**, **SQLAlchemy + SQLite**, and a **React/Vite console**. The priority is not just authentication, it is **authorization and governance behavior**—especially the awkward cases that matter in real environments: self-approval attempts, privileged roles needing extra checks, segregation-of-duties (SoD) conflicts, JML transitions, and access reviews that must survive in-flight changes.

> **Scope note:** IdentityGuard is a learning and portfolio project, not a commercial IAM/PAM product. Privileged access is simulated; there is no real credential vault, password rotation, or session recording. This repository is used to practise and discuss IAM concepts, not to claim production IAM/PAM operations experience.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What it demonstrates](#what-it-demonstrates)
- [Enterprise IAM concept mapping](#enterprise-iam-concept-mapping)
- [Implemented vs. simulated](#implemented-vs-simulated)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Run locally](#run-locally)
- [Testing and validation](#testing-and-validation)
- [Current limitations](#current-limitations)
- [Repository map](#repository-map)
- [Roadmap](#roadmap)

---

## Why this exists

Many IAM discussions stay at the level of terms: RBAC, access review, least privilege, JML. IdentityGuard exists to make those terms **behavioral and testable**:

- A permission is not assumed because a role name looks right. It is checked against current database state.
- A person cannot approve their own request.
- Privileged assignments require separation between approver and provisioner.
- Moving or terminating a user has predictable consequences for their access.
- A review remains stable even when an underlying assignment changes mid-review.
- Every important change leaves an audit trail.

---

## What it demonstrates

### Identity and authentication
- Argon2id password hashing.
- Generic login errors to avoid user enumeration.
- Login lockout and password-policy enforcement.
- Short-lived JWT sessions.
- Configurable local development secrets.

### Authorization (RBAC)
- Backend-enforced role-based access control.
- Permissions evaluated against current database state on protected requests.
- Route/endpoint matrix testing.
- Authorization checks separated from business logic where practical.

### Access request and approval lifecycle
- Request → approval → provision workflow.
- Self-approval restrictions.
- Separation of approver and provisioner for privileged-role assignments.
- Pending request closure during user changes.
- Request history and audit traceability.

### Joiner / Mover / Leaver (JML)
- User creation.
- Role changes and role-retention behavior.
- Termination handling.
- Access expiry.
- Closure of open requests.
- Revocation of active simulated PAM checkouts.

### Segregation of duties (SoD)
- Provisioning-time conflict checks.
- Audit events for violations.
- Reporting of existing conflicts.
- Clear documentation of SoD rules and compensating controls.

### Access governance
- Assignment snapshots for access reviews.
- Prevention of self-review.
- Revocation decisions.
- Safeguards for assignments that change during a review.
- Access-review summaries and reports.
- Identity inventory and role-assignment reporting.

### Privileged access (simulated PAM)
- Privileged-access request flow.
- Approval and provisioning separation.
- Time-limited checkout concept.
- Expiry handling.
- Revocation handling.
- PAM activity reporting.
- Explicit documentation that no real credential vault exists.

### Auditability
- Hash-chained audit records written alongside changes.
- Audit trail reporting.
- Clear statement that the chain is detectability-oriented, not tamper-proof.

### Delivery and engineering
- FastAPI application structure.
- SQLAlchemy models and sessions.
- Seed/demo scripts.
- Unit and API tests.
- React/Vite console for selected workflows.
- Docker configuration and CI workflow files.
- Configuration via environment variables.

---

## Enterprise IAM concept mapping

| IdentityGuard capability | Enterprise IAM concept |
|---|---|
| RBAC + current-state permission checks | Role-Based Access Control and least privilege |
| Request/approve/provision | Entitlement request lifecycle |
| SoD conflict checks at provisioning | Segregation of duties and control enforcement |
| JML transitions | Joiner/mover/leaver access lifecycle |
| Access reviews with snapshots | Periodic access certification / attestation |
| Reports and audit trail | Identity inventory, entitlement reporting, audit evidence |
| Simulated checkout/expiry/revocation | Privileged access management (PAM) lifecycle concepts |
| Backend-enforced checks | Authorization decision enforcement (PEP-style application enforcement) |

This repository does **not** currently implement Policy-Based Access Control (PBAC), Attribute-Based Access Control (ABAC), Open Policy Agent/Rego, Cedar, external policy decision points, or enterprise IAM platform integrations.

---

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
| PAM lifecycle simulation | Simulated; no real credential vault/session recording |
| Audit integrity | Hash chain; not tamper-proof |
| SSO/OIDC/Keycloak | Not implemented |
| Rate limiting | Not implemented |
| Database migrations | Not implemented |
| All workflows in the frontend | Partial; several workflows are API-first |

---

## Architecture

```
┌─────────────┐       ┌──────────────────────┐
│ React/Vite  │──────▶│ FastAPI route layer │
│ console     │       │ app/api/*           │
└─────────────┘       └──────────┬───────────┘
                                 │
                    ┌────────────┴────────────┐
                    │ Authorization (RBAC)    │
                    │ app/authz/service.py    │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
       IAM services         PAM services       Governance
       app/iam/*            app/pam/*          app/governance/*
              │                  │                  │
              └──────────┬───────┴────────┬─────────┘
                         │                │
                    SQLAlchemy models   Audit events
                    app/db/models.py   app/audit/*
                         │
                      SQLite (local dev)
```

The authorization layer is intentionally placed in the request path so that permissions are evaluated against current state rather than trusted from stale client/session data.

---

## Tech stack

**Backend**
- Python
- FastAPI
- SQLAlchemy
- SQLite (local development)
- Pydantic
- JWT
- Argon2id

**Frontend**
- React
- Vite

**Testing and delivery**
- pytest
- Docker
- GitHub Actions workflow files
- Environment-based configuration

---

## Run locally

I develop IdentityGuard as a local project. To try it on Windows, install Python 3.12 and Git, then run these commands in PowerShell:

```powershell
git clone https://github.com/Alisha-chaudhary/IdentityGuard.git
cd IdentityGuard
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

### Set local development secrets

Choose your own values in the same PowerShell session. These are placeholders, not working credentials.

```powershell
$env:IDENTITYGUARD_JWT_SECRET = "<your-long-random-local-secret>"
$env:IDENTITYGUARD_SEED_PASSWORD = "<your-strong-local-demo-password>"
```

### Initialize and start the API

```powershell
python -m app.db.seed
python -m uvicorn app.main:app --reload
```

Open the interactive API documentation at `http://127.0.0.1:8000/docs`.

### Exercise workflows and run tests

In a second terminal, activate the virtual environment and set the same local environment variables, then run:

```powershell
python -m scripts.smoke_login
python -m scripts.demo
python -m pytest -q
```

### Frontend

With the API running:

```powershell
cd frontend
npm ci
npm run dev
```

The frontend currently covers selected login, report, and access-review tasks; use `/docs` to explore the other API workflows.

### Docker

After setting `IDENTITYGUARD_JWT_SECRET` and `IDENTITYGUARD_SEED_PASSWORD` in your local environment:

```powershell
docker compose up --build
```

Docker and CI checks are treated as verified only when there is a successful build or green run to point to.

---

## Testing and validation

- Unit and API tests under `tests/`.
- Authorization route/endpoint matrix tests.
- SoD, JML, PAM, access review, and report tests.
- Smoke-login and guided demo scripts.
- Automated suite is run with pytest.

The repository intentionally reports the actual test result rather than assuming a fixed test count. Before citing a number in a resume or interview, run the suite locally and use the exact passing count.

---

## Current limitations

These limitations are intentional to call out:

- **Simulated PAM:** the project demonstrates a privileged-access lifecycle, not CyberArk administration. There is no real credential vault, password rotation, or session recording.
- **Audit integrity:** hash chaining helps make certain changes detectable, but the current unkeyed chain is not tamper-proof against someone who can modify the database.
- **Session handling:** logout is client-side; there is no server-side token denylist.
- **Abuse protection:** rate limiting is not implemented yet.
- **Storage and schema changes:** the project uses SQLite and does not currently include a migration framework.
- **Governance rules:** SoD rules are defined in application code. The mover workflow retains existing roles by design, with access review as the compensating control.
- **Integrations and UI:** there is no SSO/OIDC/Keycloak integration, and the frontend does not expose every workflow.

---

## Repository map

```
app/        API, authentication, authorization, audit, governance, IAM, PAM, reports, database, core
frontend/   React + Vite review and reporting console
tests/      automated unit and API tests
scripts/    smoke-login and guided-demo utilities
docs/       demo walkthrough and supporting documentation
```

---

## Roadmap

- Add policy-as-code or externalized authorization evaluation (OPA/Rego or Cedar) for selected decisions.
- Add attribute-aware ABAC/PBAC examples without duplicating existing RBAC checks.
- Add SSO/OIDC integration in a separate branch/experiment.
- Add server-side revocation or token denylist.
- Add rate limiting and security hardening tests.
- Add a migration strategy if moving beyond SQLite.
- Expand frontend coverage for admin/governance workflows.

---

## Why I am building it

I wanted a project that connects security principles to actual application behavior rather than just listing IAM terms. IdentityGuard lets me practise least privilege, approval separation, joiner-mover-leaver controls, segregation of duties, access reviews, privileged-access lifecycle concepts, and auditability in one place.

I use it as a learning lab and a basis for technical discussion. It is **not** a claim of production IAM/PAM operations experience, and it does not claim CyberArk integration. The goal is to keep extending the project while being clear about what is implemented, what is simulated, and what still needs work.
