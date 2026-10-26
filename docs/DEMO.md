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

---

## Vault Secret Access Demo (Phase 7-8)

Prerequisites: Vault running in WSL (see `docs/ldap-sync-design.md` for setup), `IDENTITYGUARD_VAULT_*` env vars set.

| # | What you do | What it proves |
|:--|:--|:--|
| 8 | `GET /vault/health` → confirms Vault is reachable. | Vault service is operational. |
| 9 | Provision **Vault Secret Access** role to a user via access request/approval. `GET /vault/grant` → `has_grant: true`. | IdentityGuard approval workflow grants access eligibility. |
| 10 | `GET /vault/secret/identityguard-lab/data/synthetic/test-secret` → returns `access_granted: true` with secret keys (not values). | Approved user can read secret through Vault policy enforcement. |
| 11 | Revoke the **Vault Secret Access** role; `GET /vault/grant` → `has_grant: false`; secret read → **403**. | Revoking IdentityGuard grant blocks access. Vault policy independently enforced. |
| 12 | Try secret read with a Vault token lacking the reader policy → **403** from Vault. | Vault enforces its own policy; IdentityGuard approval is not sufficient by itself. |

---

## LDAP Synchronization Demo (Phase 4-6)

Prerequisites: OpenLDAP running in WSL (see `docs/ldap-sync-design.md` for setup), `IDENTITYGUARD_LDAP_*` env vars set.

| # | What you do | What it proves |
|:--|:--|:--|
| 13 | Run dry-run sync: `GET /ldap/sync` (dry-run default) → shows proposed changes (new identities, group mappings, attribute changes). | Read-only directory discovery produces a change report without modifying anything. |
| 14 | Review the report; confirm no local users were created/modified. | Dry-run mode makes no local changes. |
| 15 | Run apply mode explicitly → local users created, roles assigned from mapped LDAP groups. Audit events recorded. | Controlled apply with explicit operator action. |
| 16 | Disable a directory account in LDAP; run sync → local user set to DISABLED, roles removed. | Disabled directory account propagates to local access revocation. |

## 30-second interview version

"I built a governance application to understand how access is requested, approved, reviewed and audited, not just how login works. The strongest parts are backend-enforced permissions, SoD at provisioning, access reviews that revoke access, and a tamper-evident audit log. I extended it with controlled LDAP synchronization (read-only discovery, dry-run by default, explicit apply) and HashiCorp Vault integration for real synthetic secret management, where Vault enforces its own policies independently of IdentityGuard approvals. PAM is a simulation — request, approval, time-limited checkout and expiry — with no credential vault."
