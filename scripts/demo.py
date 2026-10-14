"""Runs the IdentityGuard demo story against a RUNNING server.

    1) python -m app.db.seed                       (note the password it prints)
    2) python -m uvicorn app.main:app              (second terminal)
    3) IDENTITYGUARD_SEED_PASSWORD=... python -m scripts.demo

Idempotency: run it against a freshly seeded database. It prints PASS/FAIL per
step and exits non-zero if any expectation is not met.
Needs `httpx` (pip install -r requirements-dev.txt).
"""
import os
import sys
import time

import httpx

BASE = os.environ.get("IDENTITYGUARD_URL", "http://127.0.0.1:8000")
PASSWORD = os.environ.get("IDENTITYGUARD_SEED_PASSWORD")
failures = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global failures
    print(f"  [{'PASS' if condition else 'FAIL'}] {label} {detail}")
    failures += 0 if condition else 1


def login(client: httpx.Client, username: str) -> dict:
    r = client.post("/auth/login", json={"username": username, "password": PASSWORD})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def main() -> int:
    if not PASSWORD:
        print("Set IDENTITYGUARD_SEED_PASSWORD (the password printed by the seed).")
        return 2

    with httpx.Client(base_url=BASE, timeout=30) as c:
        admin, admin2 = login(c, "identityguard.admin"), login(c, "identityguard.admin2")
        auditor, reviewer = login(c, "auditor"), login(c, "reviewer")
        users = {u["username"]: u["id"] for u in c.get("/users", headers=admin).json()}
        roles = {r["name"]: r["id"] for r in c.get("/roles", headers=admin).json()}

        print("\n1. The UI is not the control: the Auditor calls the JML API directly")
        r = c.post("/jml/users", headers=auditor, json={
            "employee_id": "DEMO1", "username": "demo.user", "full_name": "Demo User",
            "email": "demo.user@example.test", "department_id": 1,
            "password": "Demo-Passw0rd-2026"})
        check("Auditor is denied (403)", r.status_code == 403, f"-> {r.status_code}")
        events = c.get("/audit/events?limit=20", headers=auditor).json()
        check("Denial is in the audit log",
              any(e["event_type"] == "ACCESS_DENIED" and e["actor"] == "auditor" for e in events))

        print("\n2. Segregation of duties blocks a conflicting grant at provisioning")
        r = c.post("/access-requests", headers=admin2, json={
            "target_user_id": users["rahul.mehta"], "role_id": roles["Payment Approver"],
            "justification": "Cover for manager"})
        rid = r.json()["id"]
        check("Request filed", r.status_code == 201)
        r = c.post(f"/access-requests/{rid}/approve", headers=admin, json={"reason": "Manager approved"})
        check("Approved by a different admin", r.status_code == 200)
        r = c.post(f"/access-requests/{rid}/provision", headers=admin2)
        check("Provisioning blocked by SoD (409)", r.status_code == 409, r.json().get("detail", ""))
        events = c.get("/audit/events?limit=20", headers=auditor).json()
        check("SOD_VIOLATION recorded", any(e["event_type"] == "SOD_VIOLATION" for e in events))

        print("\n3. Privileged roles need four-eyes (approver != provisioner)")
        r = c.post("/access-requests", headers=admin2, json={
            "target_user_id": users["arjun.verma"], "role_id": roles["Database Administrator"],
            "justification": "Incident support"})
        rid = r.json()["id"]
        c.post(f"/access-requests/{rid}/approve", headers=admin, json={"reason": "Approved"})
        r = c.post(f"/access-requests/{rid}/provision", headers=admin)
        check("Approver cannot also provision (403)", r.status_code == 403, r.json().get("detail", ""))
        r = c.post(f"/access-requests/{rid}/provision", headers=admin2)
        check("A second administrator can provision (200)", r.status_code == 200)

        print("\n4. Access review revokes stale access (Meera moved Finance -> HR)")
        cycle = c.post("/access-reviews", headers=admin, json={"name": "Demo review"}).json()
        items = c.get(f"/access-reviews/{cycle['id']}", headers=reviewer).json()["items"]
        stale = [i for i in items if i["user_id"] == users["meera.iyer"]
                 and i["role_id"] == roles["Finance Analyst"]]
        check("Stale Finance role is in the review", len(stale) == 1)
        own = [i for i in items if i["user_id"] == users["reviewer"]]
        r = c.post(f"/access-reviews/{cycle['id']}/decisions", headers=reviewer, json={
            "item_id": own[0]["id"], "decision": "RETAIN", "reason": "my own access"})
        check("Self-review is denied", r.status_code in (403, 409), r.json().get("detail", ""))
        for item in items:
            decision = "REVOKE" if item in stale else "RETAIN"
            # Nobody reviews their own access: an admin covers the reviewer's items.
            reviewer_headers = admin if item in own else reviewer
            r = c.post(f"/access-reviews/{cycle['id']}/decisions", headers=reviewer_headers, json={
                "item_id": item["id"], "decision": decision, "reason": "Demo review decision"})
            if r.status_code != 200:
                check(f"decision on item {item['id']}", False, r.text)
        r = c.post(f"/access-reviews/{cycle['id']}/complete", headers=admin)
        check("Cycle completed", r.status_code == 200, f"-> {r.status_code}")
        r = c.post(f"/access-reviews/{cycle['id']}/decisions", headers=admin, json={
            "item_id": items[0]["id"], "decision": "RETAIN", "reason": "late"})
        check("Decisions on a completed cycle are refused", r.status_code >= 400)

        print("\n5. PAM (simulated): request -> approval -> checkout -> expiry")
        r = c.post("/pam/requests", headers=login(c, "lisa"), json={
            "account_id": 1, "justification": "Patch window", "duration_minutes": 1})
        check("Lisa requests privileged access", r.status_code == 201, r.text[:80])
        pid = r.json()["id"]
        r = c.post(f"/pam/requests/{pid}/decision", headers=admin, json={
            "decision": "APPROVED", "reason": "CHG-1234"})
        check("Admin approves", r.status_code == 200)
        r = c.post(f"/pam/requests/{pid}/checkout", headers=login(c, "lisa"))
        check("Lisa checks out (time-limited)", r.status_code == 201)
        cid = r.json()["id"]
        print("     waiting ~65s for the 1-minute checkout to lapse ...")
        time.sleep(65)
        r = c.post("/pam/checkouts/expire-due", headers=admin)
        expired = [x for x in r.json() if x["id"] == cid]
        events = c.get("/audit/events?limit=50", headers=auditor).json()
        check("Checkout expired (by sweeper or on demand)",
              bool(expired) or any(e["event_type"] == "PRIVILEGE_EXPIRED" for e in events))

        print("\n6. Leaver: existing token stops working, roles are expired")
        kiran_headers = login(c, "kiran.reddy")
        r = c.post(f"/jml/users/{users['kiran.reddy']}/terminate", headers=admin)
        check("Kiran terminated", r.status_code == 200)
        r = c.get("/auth/me", headers=kiran_headers)
        check("His old token is rejected (401)", r.status_code == 401)
        r = c.post(f"/jml/users/{users['identityguard.admin']}/terminate", headers=admin)
        check("An admin cannot terminate themselves (409)", r.status_code == 409)

        print("\n7. Audit chain integrity")
        r = c.get("/reports/audit-trail?limit=1", headers=auditor).json()
        print("    integrity block:", r.get("integrity"))
        check("Chain verifies", bool(r.get("integrity", {}).get("ok")))

        print("\n8. Existing SoD conflicts report")
        r = c.get("/reports/sod-violations", headers=auditor)
        check("Report available to the auditor", r.status_code == 200, f"-> {r.json()['total_count']} conflict(s)")

    print("\nRESULT:", "ALL STEPS PASSED" if not failures else f"{failures} STEP(S) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
