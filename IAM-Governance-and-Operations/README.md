# IAM Governance and Operations

**Identity and Access Management governance and operations documentation pack**
**Entry-level IAM / Access Management / SailPoint Provisioning Operations portfolio**

---

## Purpose

This documentation pack supports five practical IAM operations scenarios that are executed and documented separately (Joiner/Mover/Leaver, Access Requests and Provisioning, Provisioning Exceptions and SLA, Access Certification and SoD, Reconciliation and Audit).

It provides a connected set of professional IAM governance and operational documents for the fictional organisation **Asteron Financial Services**, grounded in the actual implementation of the **IdentityGuard** IAM governance application.

---

## Fictional organisation (training data only)

**Asteron Financial Services** is a fictional organisation created exclusively for training and portfolio demonstration.

- Its policies are **not** real corporate policies.
- It is **not** associated with EY or any other organisation.
- No signatures, approvals, certifications or corporate authorisation are fabricated.
- All documents carry `Status: Training Reference` and `Organisation: Asteron Financial Services (Fictional)`.

### Business environment (fictional)
- Wealth Management
- Investment Operations
- Compliance
- Human Resources
- IT

### Fictional business applications (proposed training data)
- Customer Relationship Management (CRM)
- Portfolio Management System (PMS)
- Trade Operations Portal
- Compliance Case Management (CCM)
- HR Management System (HRMS)

These applications and their entitlements are **proposed Asteron training data** and are labelled as such throughout the pack. They are **not** IdentityGuard records.

### Main scenario subject (fictional)
- **Maya Rao**, Employee ID **EMP-1001**, Hyderabad, Full-time
- Initial department: Wealth Management — Relationship Manager
- Manager: Neha Kapoor — Join date: 17 November 2026
- Mover date: 1 February 2027 — Investment Operations Analyst, Investment Operations
- Leaver date: 30 June 2027

Maya's Joiner / Mover / Leaver access is logically consistent across all documents.

---

## Source repository

**IdentityGuard:** https://github.com/Alisha-chaudhary/IdentityGuard  
A Python/FastAPI IAM governance lab (SQLAlchemy, SQLite, Pytest, React). Status: in active development. The repository was inspected in full (source code, database models, seed data, policy files, LDAP/PAM/Vault integrations, tests, and documentation) before this pack was written.

**Important:** No application code was modified, no new APIs/scripts/modules were introduced, and the existing database was not changed, reset, seeded or deleted.

### Repository findings report
`00-Repository-Assessment/IdentityGuard-Repository-Findings.md`

This report is the evidence base for the pack. It documents the verified repository contents (schema, seed users/roles/permissions, workflows, SoD rules, access reviews, audit, LDAP, Vault, implemented vs. designed-only features, gaps) with source file paths for every major conclusion.

---

## Actual vs. proposed functionality

A central requirement of this pack is to distinguish:

| Category | Meaning |
|----------|---------|
| **Implemented (IdentityGuard)** | Capability verified in the IdentityGuard source code and tests. Technical names (roles, permissions, resources, event types) are retained verbatim. |
| **Designed-only / planned / unimplemented** | Features described in IdentityGuard documentation or roadmap but not implemented; not presented as operational. |
| **Proposed — Asteron training data** | Fictional business applications, roles and entitlements created for the five training scenarios. Clearly labelled; not IdentityGuard records. |
| **Manual / simulated** | Organisational procedures operated in ServiceNow PDI, Excel or Word/PDF because IdentityGuard does not implement them. |

**No planned or unimplemented feature is described as an operational IdentityGuard capability.**

Key IdentityGuard limitations observed and reflected in this pack:
- PAM is **simulated** (request / approve / time-limited checkout / expiry); no credential vault, password rotation or session recording.
- LDAP integration is **OpenLDAP only, read-only, dry-run by default, controlled apply**. **Active Directory is NOT implemented** and is not described as Active Directory.
- IdentityGuard supports a **single approver per access request**; multi-stage chains are operated manually or in ServiceNow PDI.
- Access reviews are created **on demand**; there is no scheduled recurring review.
- No ServiceNow integration exists in the repository; none is claimed or fabricated.
- No migration framework (Alembic); SQLite `create_all()` only.
- No server-side token revocation; logout is client-side.

---

## Document pack structure

```
IAM-Operations-Portfolio/
├── 00-Repository-Assessment/
│   └── IdentityGuard-Repository-Findings.md     # Evidence base (repository investigation)
├── 00-Governance-Framework/
│   ├── 01-Access-Control-Policy.docx            # Formal Access Control Policy
│   ├── 02-RBAC-Matrix.xlsx                      # Role-Based Access Control matrix
│   ├── 03-Entitlement-Catalogue.xlsx            # Entitlement inventory
│   ├── 04-Approval-Matrix.xlsx                  # Approval matrix for access requests
│   ├── 05-SoD-Policy-and-Rules-Register.docx    # SoD policy and rules register
│   ├── 06-Provisioning-and-Deprovisioning-SOP.docx   # Provisioning SOP (intake to closure)
│   └── 07-Exception-Management-SOP.docx         # Exception Management SOP
└── README.md                                     # This file
```

### Document conventions
- **DOCX** for formal policies and SOPs (each includes Document ID, Version, Status: Training Reference, Organisation, Purpose, Scope, Definitions, Roles and responsibilities, review/approval placeholders, references).
- **XLSX** for matrices, catalogues and registers (filtered tables, frozen header rows, data validation, implementation-status legend, separate Read Me and Reference Data sheets).
- **Markdown** for the repository findings report and this README.

Each XLSX workbook contains:
- `Read Me & Legend` — purpose, implementation-status legend, notes
- `Reference Data` — shared reference data used across all documents (departments, fictional applications, Maya Rao scenario)
- The main worksheet (RBAC Matrix / Entitlement Catalogue / Approval Matrix)

---

## Alignment with the five practical scenarios

All scenarios use the same organisation, business roles, applications, policies and reference data (including Maya Rao, EMP-1001).

| Scenario | Focus | Supporting documents |
|----------|-------|----------------------|
| 1. Joiner, Mover and Leaver | Onboarding, initial access, role change, access add/remove, termination, revocation, verification and evidence | 01 (lifecycle sections), 02 (RBAC), 03 (Entitlement Catalogue), 06 (JML procedures) |
| 2. Access Requests and Provisioning | Intake, justification, entitlement validation, approval, work item, fulfilment, verification, closure | 04 (Approval Matrix), 06 (standard procedure), 03 (Entitlement Catalogue) |
| 3. Provisioning Exceptions and SLA | Failed requests, pending approvals, incorrect access, provisioning failures, SLA tracking, escalation | 07 (Exception Management SOP), 06 |
| 4. Access Certification and SoD | Manager review, retain/revoke, excessive access, incompatible permissions, revocation, certification evidence | 01 (access review), 05 (SoD Policy & Rules Register), 03, 06 |
| 5. Reconciliation and Audit | Compare identities and entitlements, unmatched accounts, discrepancies, exceptions, corrective action, audit report | 01 (audit logging), 03, 06, 07 |

### Where activities are performed
| Activity | IdentityGuard | LDAP (OpenLDAP) | ServiceNow PDI | Excel | Word/PDF |
|----------|---------------|-----------------|----------------|-------|----------|
| Request intake & tracking | Access request API | No | Ticket / work item | Register | No |
| Approval | Single approver (access.approve) | No | Additional/manual approvals | Approval log | No |
| Provisioning (roles) | provision_access_request / UserRole | Group-mapped roles (non-privileged only) | No | Entitlement log | No |
| JML (joiner/mover/leaver) | create_user / move_user / terminate_user | Sync can create/disable local users | Ticket | JML tracker | SOP |
| Privileged access | Simulated PAM checkout (max 60 min) | No | Ticket | PAM log | No |
| Access review / certification | Review cycles, RETAIN/REVOKE | No | Ticket | Review evidence | Report |
| Audit & reconciliation | Hash-chained audit events + reports | Sync runs/changes | Ticket audit | Reconciliation register | Audit report |

---

## How to use this pack

1. Read `00-Repository-Assessment/IdentityGuard-Repository-Findings.md` first — it establishes what IdentityGuard actually implements.
2. Use `01-Access-Control-Policy.docx` as the governing policy (marks each requirement as organisational `[Policy requirement]` or IdentityGuard `[IG-implemented]`).
3. Use `02-RBAC-Matrix.xlsx`, `03-Entitlement-Catalogue.xlsx` and `04-Approval-Matrix.xlsx` as the reference data for access requests and reviews.
4. Use `05-SoD-Policy-and-Rules-Register.docx` for SoD rules (implemented IdentityGuard rules plus labelled training rules).
5. Execute `06-Provisioning-and-Deprovisioning-SOP.docx` and `07-Exception-Management-SOP.docx` as operating procedures during the practical exercises.

---

## Repository findings summary

IdentityGuard implements (verified in source and tests): RBAC with roles/permissions and a permission-checked API; access request/approval/provisioning; Joiner/Mover/Leaver lifecycle; SoD rules enforced at provisioning (Payment Initiator + Payment Approver; System Administrator + SOC Analyst; Database Administrator + Security Auditor) plus a violations report; access review cycles with RETAIN/REVOKE decisions and correction; hash-chained append-only audit logging; simulated PAM (time-limited checkout); read-only OpenLDAP synchronisation (dry-run default, controlled apply); read-only Vault integration (Vault enforces its own policy); a feature-flagged policy engine for privileged assignment.

Not implemented: Active Directory integration, SSO/OIDC, real PAM vaulting/rotation/session recording, server-side token revocation, database migrations, scheduled recurring reviews, multi-stage approval chains, ServiceNow integration, LDAP writes, LDAP authentication.

Full details: `00-Repository-Assessment/IdentityGuard-Repository-Findings.md`.

---

## Generated files

| # | File | Type |
|---|------|------|
| 0 | `00-Repository-Assessment/IdentityGuard-Repository-Findings.md` | Markdown findings report |
| 1 | `00-Governance-Framework/01-Access-Control-Policy.docx` | Access Control Policy |
| 2 | `00-Governance-Framework/02-RBAC-Matrix.xlsx` | RBAC Matrix |
| 3 | `00-Governance-Framework/03-Entitlement-Catalogue.xlsx` | Entitlement Catalogue |
| 4 | `00-Governance-Framework/04-Approval-Matrix.xlsx` | Approval Matrix |
| 5 | `00-Governance-Framework/05-SoD-Policy-and-Rules-Register.docx` | SoD Policy and Rules Register |
| 6 | `00-Governance-Framework/06-Provisioning-and-Deprovisioning-SOP.docx` | Provisioning & Deprovisioning SOP |
| 7 | `00-Governance-Framework/07-Exception-Management-SOP.docx` | Exception Management SOP |
| — | `README.md` | Pack overview (this file) |

---

## Unresolved assumptions / items for review

- The actual data in any running/deployed IdentityGuard database instance was not inspected (the local SQLite file was not opened or modified); seed data in code is used as the evidence base.
- Whether an OpenLDAP or Vault server is running in any target environment is not confirmed (integrations are environment-variable configured).
- Training SLA targets in `07-Exception-Management-SOP.docx` are labelled training targets, not regulatory commitments; replace with organisational SLAs for real use.
- The IdentityGuard frontend exposes several workflows as API-first (per the repository README); practical exercises may need to use the API directly.

