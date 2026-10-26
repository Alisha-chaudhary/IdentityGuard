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
