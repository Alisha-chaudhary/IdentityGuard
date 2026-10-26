# IdentityGuard — Phase 2: LDAP Synchronization Design

**Status:** Design for review (not implemented)  
**Phase:** Phase 2 of the IdentityGuard implementation plan  
**Branch:** to be created from `main` before implementation

---

## 1. Purpose

Add a controlled, read-first LDAP synchronization layer to IdentityGuard so that
directory users and groups from OpenLDAP can be reconciled against IdentityGuard's
local application identity records **without** LDAP becoming an alternative route
around application authorization.

The first implementation is **read-only against LDAP** (no LDAP account creation,
no password changes, no group modifications) and **dry-run by default** (no local
changes are applied unless an operator explicitly requests apply mode).

---

## 2. Scope (in and out)

### In scope
- A small Python LDAP client module (read-only, timeouts, safe error handling).
- A synchronization service that compares directory records against local records
  and produces a change report (dry-run) or applies approved changes (apply mode).
- Dedicated integration tables (no columns added to existing `User`).
- Audit events for every sync outcome (proposed, applied, skipped, failed).
- Unit tests (normalization, mapping, change detection, idempotency, error handling)
  and integration tests against a real local OpenLDAP service.

### Out of scope (explicitly deferred)
- LDAP authentication (bind as login) — not part of this phase.
- LDAP write operations (create/change passwords/modify groups).
- Automatic assignment of privileged roles from directory data.
- Vault integration (Phase 7+).
- Alembic migrations (deferred; new tables only, no existing-table changes).

---

## 3. Current identity model (inspected from source)

### `users` table (`app/db/models.py:36`)
| Column | Type | Notes |
|--------|------|-------|
| `id` | int PK | Local surrogate key |
| `employee_id` | String(20), unique | Business identifier |
| `username` | String(50), unique | Login identity |
| `full_name` | String(150) | |
| `email` | String(255), unique | |
| `password_hash` | String(255), nullable | Local Argon2 hash |
| `status` | String(20) | ACTIVE / DISABLED / LOCKED / TERMINATED |
| `failed_attempts`, `locked_until` | | Lockout state |
| `department_id` | FK departments | |
| `manager_id` | FK users (self) | |
| `created_at`, `terminated_at` | | |

There are **no LDAP-related columns** on `User`. Per the brief, we must not add
columns to existing tables and assume the local DB updates (SQLite `create_all`
does not add columns to existing tables; no Alembic yet).

### `roles` table (`app/db/models.py:111`)
| Column | Notes |
|--------|-------|
| `id` | PK |
| `name` | unique (e.g. "Finance Analyst", "Database Administrator") |
| `is_privileged` | bool |

### `user_roles` table (`app/db/models.py:185`)
Composite PK (`user_id`, `role_id`), plus `assigned_at` and `expires_at`.

### Seed roles (from `app/db/seed.py:80`)
**Privileged roles** (must never be auto-assigned from LDAP):
- `IAM Administrator`
- `Database Administrator`
- `System Administrator`

**Non-privileged roles** (candidates for LDAP group mapping):
- `Finance Analyst`
- `Finance Manager`
- `HR Analyst`
- `SOC Analyst`
- `Payment Initiator`
- `Payment Approver`

The exact mapped role must be chosen from the real seeded environment during
implementation and recorded in `DirectoryGroupMapping`.

### Uniqueness of existing users
Users are uniquely identified locally by `id` (surrogate), `employee_id`, and
`username`, each unique. No column currently stores an immutable directory
identifier.

---

## 4. Identity matching rules

### Immutable external identifier
- Use the LDAP **entryUUID** (operational attribute `entryUUID`) as the immutable
  directory identifier. It survives renames and attribute changes.
- Fallback (only if entryUUID is unavailable in the chosen OpenLDAP build): a
  deterministic, stable attribute such as `uid` / `entryDN`, documented as a
  weaker fallback with a clearly stated collision risk.

### Matching order
1. Match by `ExternalIdentity.external_id` = LDAP `entryUUID` (strongest).
2. If no external identity exists, match by `User.username` == LDAP `uid`
   (candidate link, flagged for review — usernames can change).
3. Never auto-merge on display name, email, or similar usernames alone.

### Ambiguity / conflicts
- Two directory entries mapping to the same local user → **conflict**, propose
  skip, record in audit, require operator review.
- One directory entry matching multiple local users → **conflict**, propose skip.
- No match → directory identity with no local match (provisioning candidate).

---

## 5. Proposed database tables (new tables only)

No existing table is altered. All new tables are created via `Base.metadata.create_all()`
in `init_db()` (already called on app startup). This is safe on SQLite without
Alembic because nothing already exists with these names.

### 5.1 `external_identities`
Links a directory identity to a local IdentityGuard user.

| Column | Type | Notes |
|--------|------|-------|
| `id` | int PK | |
| `provider` | String(50) | e.g. "ldap" |
| `external_id` | String(255), **unique** | LDAP entryUUID |
| `local_user_id` | int FK → users.id | |
| `dn` | String(500) | Directory entry DN (non-secret, for diagnostics) |
| `username` | String(100) | Directory `uid` at last sync |
| `last_seen_at` | DateTime | Last successful sync observation |
| `sync_status` | String(20) | matched / unmatched / conflict / disabled |
| `created_at`, `updated_at` | DateTime | |

Unique constraint: `(provider, external_id)`.

### 5.2 `directory_group_mappings`
Explicit, configurable mapping from an LDAP group to a local role.

| Column | Type | Notes |
|--------|------|-------|
| `id` | int PK | |
| `provider` | String(50) | "ldap" |
| `group_dn` | String(500) | LDAP group DN (immutable anchor) |
| `group_name` | String(100) | e.g. `cn=finance-analysts,ou=groups,...` |
| `role_id` | int FK → roles.id | Must be non-privileged |
| `is_active` | bool | default true |
| `approved_by` | String(100) | Operator who approved the mapping |
| `approved_at` | DateTime | |
| `created_at`, `updated_at` | DateTime | |

Constraint: `role_id` must reference a role where `is_privileged = false` (enforced
in application logic, documented). Unknown/unmapped groups grant nothing.

### 5.3 `directory_sync_runs`
One row per sync execution.

| Column | Type | Notes |
|--------|------|-------|
| `id` | int PK | |
| `run_id` | String(64), unique | Correlation id for the run |
| `mode` | String(10) | "dry-run" or "apply" |
| `started_at` | DateTime | |
| `completed_at` | DateTime | nullable |
| `outcome` | String(20) | completed / partial / failed |
| `summary` | JSON / Text | counts: proposed, applied, skipped, failed |
| `error` | Text | nullable, failure reason if any |

### 5.4 `directory_sync_changes`
One row per proposed or applied change.

| Column | Type | Notes |
|--------|------|-------|
| `id` | int PK | |
| `run_id` | String(64) FK → directory_sync_runs.run_id | |
| `change_type` | String(30) | create_user / assign_role / remove_role / disable_access / skip_noop / skip_conflict / skip_disabled / skip_missing |
| `external_id` | String(255) | LDAP entryUUID |
| `local_user_id` | int FK → users.id | nullable |
| `target_role_id` | int FK → roles.id | nullable |
| `previous_state` | JSON / Text | |
| `proposed_state` | JSON / Text | |
| `outcome` | String(20) | proposed / applied / skipped / failed |
| `reason` | Text | human-readable why |
| `created_at` | DateTime | |

---

## 6. Group-to-role mapping

- Unknown LDAP groups grant nothing.
- Unmapped users receive no additional roles.
- LDAP group membership never directly grants an administrative or privileged role.
- `directory_group_mappings.role_id` must reference a non-privileged role.
- Privileged role assignments continue through IdentityGuard's existing
  authorization and governance controls (request → approval → provision, SoD,
  four-eyes).
- Separation of duties, approval requirements, and audit logging are never
  bypassed.

The initial mapping must be chosen from real seeded roles. Example (to be
confirmed against the actual seed):
- LDAP group `cn=finance-analysts,ou=groups,dc=example,dc=test` → role
  `Finance Analyst` (non-privileged).

---

## 7. Behavior for directory edge cases

| Situation | Behavior |
|-----------|----------|
| LDAP user explicitly disabled/inactive | Propose removal of mapped local access (disable or role removal), **not** automatic deletion of the local user or audit history. Record as `skip_disabled` or `remove_role` in dry-run; apply only on explicit operator action. |
| User removed from a mapped LDAP group | Propose role removal (`remove_role`). Audit as proposed change. |
| User missing from directory search results | **Do not** interpret as deletion. Propose no change; record `skip_missing`. |
| LDAP server unavailable | Sync fails fast with `outcome=failed`. **Never** generate a mass deprovisioning plan from a failed/incomplete query. |
| Partial or failed LDAP search | Treat as `outcome=partial`, record which entries were read vs. failed. No mass changes. |
| Ambiguous identity match | `skip_conflict`, require operator review, audit recorded. |
| LDAP outage during apply | Revalidate preconditions before applying; fail safely, roll back partial transaction. |

### Safety rule
A failed or incomplete directory query must never produce a mass deprovisioning
plan. Idempotency: running sync twice against unchanged directory data must not
create duplicate users, assignments, or noisy duplicate events.

---

## 8. Workflows

### Dry-run (default)
1. Connect to LDAP (read-only, timeout-bounded).
2. Read users + groups + memberships.
3. Normalize into internal structures.
4. Compare against local users, `external_identities`, `directory_group_mappings`.
5. Produce a proposed change report: new identities, attribute changes, group
   changes, unknown groups, disabled accounts, conflicts, missing entries,
   completeness flag.
6. Record a `directory_sync_run` with `mode=dry-run`, `outcome=completed`, and
   `directory_sync_change` rows with `outcome=proposed`.
7. No local users or roles are modified.

### Apply (explicit operator action)
1. Require an explicit operator flag (`--apply` or equivalent API/action).
2. Revalidate preconditions (LDAP reachable, mappings valid, no privileged role
   auto-assignment).
3. Apply only changes explicitly approved in the report.
4. Every applied change gets an audit event and a `directory_sync_change` row
   with `outcome=applied`.
5. Skipped/failed changes recorded with `outcome=skipped`/`failed` and a reason.
6. Repeatable: unchanged data → no duplicate assignments or events.

---

## 9. Audit events

New event types (to be added to `app/audit/events.py` `EventType`):

- `DIRECTORY_SYNC_STARTED`
- `DIRECTORY_SYNC_COMPLETED`
- `DIRECTORY_SYNC_FAILED`
- `DIRECTORY_CHANGE_PROPOSED`
- `DIRECTORY_CHANGE_APPLIED`
- `DIRECTORY_CHANGE_SKIPPED`
- `DIRECTORY_CHANGE_FAILED`
- `IDENTITY_MAPPED`
- `IDENTITY_MATCH_CONFLICT`
- `IDENTITY_DISABLED_IN_DIRECTORY`

All use valid `result` values: `SUCCESS`, `DENIED`, `FAILURE`. No LDAP passwords,
bind secrets, Vault secrets, or secret values are ever written to `reason`, logs,
or responses.

---

## 10. Configuration (environment variables, no committed secrets)

| Variable | Default | Purpose |
|----------|---------|---------|
| `IDENTITYGUARD_LDAP_ENABLED` | `false` | Master switch for sync |
| `IDENTITYGUARD_LDAP_URI` | `ldap://localhost:389` | LDAP server URI |
| `IDENTITYGUARD_LDAP_BIND_DN` | `` | Read-only bind DN |
| `IDENTITYGUARD_LDAP_BIND_PASSWORD` | `` | Read-only bind password (runtime only, never committed) |
| `IDENTITYGUARD_LDAP_BASE_DN` | `dc=example,dc=test` | Search base |
| `IDENTITYGUARD_LDAP_USER_FILTER` | `(objectClass=inetOrgPerson)` | User search filter |
| `IDENTITYGUARD_LDAP_GROUP_FILTER` | `(objectClass=groupOfNames)` | Group search filter |
| `IDENTITYGUARD_LDAP_TIMEOUT` | `10` | Connection/operation timeout seconds |
| `IDENTITYGUARD_SYNC_MODE` | `dry-run` | `dry-run` or `apply` |

A safe `.env.example` with placeholders only will be provided. `.env` is already
gitignored.

---

## 11. Files expected to change

**New files:**
- `app/ldap/client.py` — read-only LDAP client
- `app/ldap/sync.py` — synchronization service
- `app/ldap/models.py` — normalized directory structures
- `app/db/models.py` — add the four new integration table classes (no changes to
  existing tables)
- `tests/unit/test_ldap_client.py`
- `tests/unit/test_ldap_sync.py`
- `tests/integration/test_ldap_sync_integration.py` (against real OpenLDAP)
- `docs/ldap-sync-design.md` (this document)
- `.env.example`

**Modified files:**
- `app/audit/events.py` — add sync event types
- `app/db/init_db.py` — already imports all models via `app.db.models`; confirm
  new models are imported
- `app/main.py` — optional startup health/logging for LDAP sync availability
- `README.md` — document LDAP sync status and limitations

---

## 12. Risks

| Risk | Mitigation |
|------|------------|
| SQLite `create_all` won't add columns to existing tables | Use new tables only; no `User` changes |
| No Alembic yet | Documented limitation; new tables are additive |
| In-memory rate limiter not shared across instances | Single-process lab; documented |
| LDAP outage mistaken for empty directory | Fail fast, `outcome=failed/partial`, no mass deprovision |
| Policy path bug (found in Phase 1) | Fixed `POLICY_PATH` to `app/policies/...` |
| `entryUUID` not available in some OpenLDAP builds | Document fallback + collision risk |
| Privileged role auto-assignment | Application-level enforcement: mapped roles must be non-privileged |

---

## 13. Tests and acceptance criteria

### Unit tests
- LDAP record normalization (entryUUID, uid, group membership, disabled flag).
- Identity matching order (entryUUID → username → conflict).
- Change detection (new, changed, removed, unchanged → idempotent).
- Dry-run produces no local mutations.
- Unknown groups grant nothing; privileged roles never auto-assigned.
- Failed LDAP query → no mass deprovisioning.

### Integration tests
- Against real local OpenLDAP: bind, search users/groups, read `entryUUID`.
- Sync against seeded IdentityGuard DB; verify report and (optionally) apply.
- Idempotency: second run against unchanged data → no new changes/events.
- LDAP unavailable → error, not empty directory.

### Security tests
- No secrets in logs/audit/reasons.
- Disabled directory user does not delete local user or audit history.
- Privileged role cannot be granted through directory mapping alone.

---

## 14. Definition of done (Phase 2)

1. Design reviewed and approved.
2. Code implemented (new tables, client, sync service).
3. Unit tests pass; integration tests pass against real OpenLDAP.
4. Relevant existing regression tests pass (full suite green).
5. LDAP can be started and stopped without affecting IdentityGuard.
6. Configuration and reset instructions documented.
7. Limitations recorded accurately.
8. Committed on the intended working branch (if authorized).

---

## 15. Open questions for review

1. **Mapping choice:** Which non-privileged seeded role should the initial LDAP
   group map to (e.g. `Finance Analyst`)? Confirm against the real seed data.
2. **entryUUID availability:** Confirm the chosen OpenLDAP build returns
   `entryUUID`; if not, approve the `uid`/`entryDN` fallback with documented risk.
3. **Apply trigger:** CLI flag only, or also an API endpoint? Recommend CLI-first
   for the lab (explicit operator action, easier to audit).
4. **Disabled-user behavior:** Propose role removal vs. mark local user
   `DISABLED`? Recommend role removal / access revocation only, never deleting
   local users or audit history.

---

**Next step after approval:** Create the working branch, implement Phase 3
(start a local OpenLDAP service and verify read access), then Phase 4 (read-only
LDAP client).
