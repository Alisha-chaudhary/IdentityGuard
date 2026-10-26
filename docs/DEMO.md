# IdentityGuard demo guide

The hosted demo is for looking, not changing. You sign in as a zero-privilege viewer on synthetic data. Nothing you do can modify records.

**Live demo** https://identity-guard-omega.vercel.app/

| Credentials are available on request through my [portfolio](https://alishachaudhary.vercel.app/).

The backend sleeps when idle, so the first request can take up to a minute.

## Five minute walkthrough

| Step | What to open | What it shows |
|---|---|---|
| 1 | Sign in as the demo user | Authentication and a least-privilege account |
| 2 | Users and roles | Role-based access control and who holds which role |
| 3 | An access request and its approval trail | Request and approval workflow |
| 4 | Separation of duties view | Conflicting access being blocked |
| 5 | Access review cycle | Pending items, decisions and corrections |
| 6 | Simulated privileged access | Time-limited elevation and expiry (simulated, not a vault) |
| 7 | Audit log | Chained events showing who did what and when |
| 8 | Try a restricted action | The server refuses it, which proves the UI is not the only control |

## What the demo user cannot do

The demo user has view permissions only. Create, approve, decide, correct, elevate and delete actions must return an authorization error. If any write succeeds, treat it as a bug and tell me.

## checklist i need to work on before sharing the link

- [ ] Sign in as the demo user in a private window and confirm every write returns 403
- [ ] Add a test that fails if the demo role ever gains a write permission
- [ ] Confirm the database holds synthetic data only and can be reseeded
- [ ] Check that the hosted API docs page is disabled or exposes nothing sensitive
- [ ] Restrict allowed origins to the demo frontend
- [ ] Confirm login rate limiting is in place on the hosted backend (open finding in the security review)
- [ ] Confirm no secrets are in the repository or the frontend bundle
- [ ] Share credentials only on request

## Failure scenarios

| Scenario | Symptom | Evidence (log or audit event) | Likely cause | Steps taken | Resolution | Verification |
|---|---|---|---|---|---|---|---|---|
| A user requests access they are not authorized to receive | | | | | | | |
| Elevated access has expired when the user tries to use it | | | | | | | |
| A user loses the role needed for an action | | | | | | | |
| A reviewer tries to review their own privileged role | | | | | | | |
| The audit chain fails verification | | | | | | | |

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
