# IdentityGuard demo (about 6 minutes, synthetic identities)

Run it automatically against a freshly seeded database:

```powershell
python -m app.db.seed
python -m uvicorn app.main:app          # terminal 1
python -m scripts.demo                  # terminal 2 (same env vars)
```

Or follow the steps by hand in `http://127.0.0.1:8000/docs` (Authorize with the token from `/auth/login`).

| # | What you do | What it proves |
|:--|:--|:--|
| 1 | Log in as `auditor`, call `POST /jml/users` directly → **403**, then show the `ACCESS_DENIED` event in `GET /audit/events`. | Authorization is enforced by the backend, not the UI, and denials are audited. |
| 2 | `identityguard.admin2` requests **Payment Approver** for `rahul.mehta` (who holds Payment Initiator); `identityguard.admin` approves; provisioning → **409**, `SOD_VIOLATION` recorded. | SoD is enforced where access is actually granted, and approval/provisioning are separate steps. |
| 3 | Request **Database Administrator** (privileged) for `arjun.verma`; admin approves; admin tries to provision → **403** (four-eyes); `identityguard.admin2` provisions → 200. | Privileged roles need `role.assign_privileged` and two different people. |
| 4 | Create an access review. `reviewer` revokes `meera.iyer`'s stale **Finance Analyst** role; show self-review is denied; complete the cycle. | Reviews snapshot assignments, block self-review and revoke atomically. |
| 5 | `lisa` requests a 1-minute PAM checkout, admin approves, lisa checks out; after it lapses it is `EXPIRED` and `PRIVILEGE_EXPIRED` is audited. | Time-bound access is actually enforced (simulated PAM: no vault). |
| 6 | Terminate `kiran.reddy` → his token is rejected (401); admin cannot terminate themselves (409). | Leaver flow: roles expired, PAM revoked, requests closed, self/last-admin guards. |
| 7 | `GET /reports/audit-trail` → `integrity.ok: true`; `GET /reports/sod-violations`. | Tamper-evident audit chain and governance reporting. |

## 30-second interview version

"I built a governance application to understand how access is requested, approved, reviewed and audited, not just how login works. The strongest parts are backend-enforced permissions, SoD at provisioning, access reviews that revoke access, and a tamper-evident audit log. PAM is a simulation — request, approval, time-limited checkout and expiry — with no credential vault."
