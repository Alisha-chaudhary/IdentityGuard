# IdentityGuard
### An IAM Governance Lab I Built to Explore How Access Should Be Managed

I built **IdentityGuard** to make identity governance more concrete than a login screen. The project lets me explore how access is requested, approved, provisioned, reviewed, revoked, and recorded for audit.

It brings together a Python/FastAPI backend, SQLAlchemy with SQLite, and a React/Vite console. The focus is on access-control decisions and governance workflows, including the awkward cases that matter: someone trying to approve their own request, a privileged role needing extra checks, or a user's access changing while a review is in progress.

**A clear scope note:** IdentityGuard is a learning and portfolio project, not a commercial IAM/PAM product. Its privileged-access workflow is simulated and does not connect to CyberArk or store real privileged credentials.

## What I implemented and what I am still simulating

| Area | What you can explore in IdentityGuard |
|---|---|
| Authentication | Argon2id password hashing, generic login errors, login lockout, short-lived JWTs, and password-policy enforcement. |
| Authorization | Backend-enforced role-based access control (RBAC), with permissions checked against current database state on protected requests. |
| Access requests and approvals | A request-to-approval-to-provision workflow, restrictions on self-approval, and separation of approver and provisioner for privileged-role assignments. |
| Joiner, mover, leaver (JML) | User creation, role changes, termination, access expiry, closure of open requests, and revocation of active simulated PAM checkouts. |
| Segregation of duties (SoD) | Provisioning-time checks against defined conflict rules, audit events for violations, and a report of existing conflicts. |
| Access reviews | Assignment snapshots, prevention of self-review, revocation decisions, and safeguards for assignments that change during a review. |
| Audit trail | Hash-chained audit records written alongside changes. The chain is intended to make tampering detectable. It is not tamper-proof. |
| Privileged-access concepts | Simulated request, approval, time-limited checkout, expiry, revocation, and audit tracking. There is no real credential vault, password rotation, or session recording. |
| Interface and reports | A partial React console for login, reports, and access-review actions. Other workflows are currently API-first. |

## Tools and technologies

**Python · FastAPI · SQLAlchemy · SQLite · Pydantic · JWT · Argon2id · React · Vite · pytest · Docker**

## Run it locally

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

Open the interactive API documentation at http://127.0.0.1:8000/docs.

### Exercise the workflows and run the tests

In a second PowerShell terminal, activate the virtual environment and set the same local environment variables, then run:

```powershell
python -m scripts.smoke_login
python -m scripts.demo
python -m pytest -q
```

The smoke script exercises the login flow, the guided demo walks through key project scenarios, and pytest runs the automated suite. I report the test result from the actual run rather than assuming a fixed test count.

The seed script creates local demo accounts. Use only the local demo password you chose above, and never reuse it for a real account.

## Frontend

With the API running, open another terminal:

```powershell
cd frontend
npm ci
npm run dev
```

The frontend currently covers selected login, report, and access-review tasks; use `/docs` to explore the other API workflows.

## Docker

The repository includes Docker configuration. After setting `IDENTITYGUARD_JWT_SECRET` and `IDENTITYGUARD_SEED_PASSWORD` in your local environment, you can try:

```powershell
docker compose up --build
```

I treat Docker and CI checks as verified only when I have a successful build or green run to point to.

## Configuration

| Variable | Purpose |
|---|---|
| `IDENTITYGUARD_DATABASE_URL` | SQLAlchemy database URL; defaults to a local SQLite database. |
| `IDENTITYGUARD_JWT_SECRET` | Secret used to sign JWTs. Set a stable, random local value for development. |
| `IDENTITYGUARD_SEED_PASSWORD` | Password assigned to seeded demo users. Choose a unique local-only value. |
| `IDENTITYGUARD_AUTO_SEED` | Optional Docker startup setting to seed the database when enabled. |

## Current boundaries and next improvements

I want the project to be useful without overstating what it proves, so these limitations are intentional to call out:

- **Simulated PAM:** the project demonstrates a privileged-access lifecycle, not CyberArk administration. It has no real credential vault, password rotation, or session recording.
- **Audit integrity:** hash chaining helps make certain changes detectable, but the current unkeyed chain is not tamper-proof against someone who can modify the database.
- **Session handling:** logout is client-side; there is no server-side token denylist.
- **Abuse protection:** rate limiting is not implemented yet.
- **Storage and schema changes:** the project uses SQLite and does not currently include a migration framework.
- **Governance rules:** SoD rules are defined in application code. The mover workflow retains existing roles by design, with access review as the compensating control.
- **Integrations and UI:** there is no SSO/OIDC or Keycloak integration, and the frontend does not yet expose every workflow.

## Repository map

```text
app/        API, authentication, authorization, audit, governance, IAM, PAM, reports, database, core
frontend/   React + Vite review and reporting console
tests/      automated unit and API tests
scripts/    smoke-login and guided-demo utilities
docs/       demo walkthrough and supporting documentation
```

## Why I am building it

I wanted a project that connects security principles to actual application behavior, not just a list of IAM terms. IdentityGuard gives me a way to practise least privilege, approval separation, joiner-mover-leaver controls, segregation of duties, access reviews, privileged-access lifecycle concepts, and auditability in one place.

I use it as a learning lab and a basis for technical discussion. It is **not** a claim of production IAM/PAM operations experience, and it does not claim CyberArk integration. My goal is to keep extending the project while being clear about what is implemented, what is simulated, and what still needs work.

