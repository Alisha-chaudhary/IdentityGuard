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
|---|---|---|---|---|---|---|
| A user requests access they are not authorized to receive | | | | | | |
| Elevated access has expired when the user tries to use it | | | | | | |
| A user loses the role needed for an action | | | | | | |
| A reviewer tries to review their own privileged role | | | | | | |
| The audit chain fails verification | | | | | | |
