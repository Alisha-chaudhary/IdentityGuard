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

<!-- VERIFY before commit: confirm the uvicorn entry point, how the database is seeded, and where the frontend lives, then add the frontend start commands. -->

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

<!-- VERIFY before commit: confirm the review cycle decision was carried out, and that access_review.correct and the Access Reviewer role are on main. -->

## Security review and known limitations

I reviewed this project myself with Bandit and a manual read. The write-up is in [Secure-coding-review](https://github.com/Alisha-chaudhary/Secure-coding-review). I track each finding here.

| Finding | CWE | Status |
|---|---|---|
| No rate limiting on login | CWE-307 | Open |
| No server-side token revocation | CWE-613 | Open |
| Silent exception handling in the access-expiry sweeper | CWE-703 | Open |
| Broad exception fallback in access requests | CWE-703 | Open |
| No password history check | CWE-521 | Open |
| SQLite without migrations | CWE-1036 | Open |
| Detailed user information on the current-user endpoint | CWE-200 | Open |

<!-- VERIFY before commit: change Status to Fixed (with the PR number) for any finding you have already remediated. Leave Open only if it is still true. -->

Other limits are listed in [Simulated PAM versus real PAM](#simulated-pam-versus-real-pam).

## Roadmap

- Hardening items from the security review
- GitHub Actions running the test suite
- Docker setup
- Frontend polish
- A tagged v1.0 release
