from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.init_db import init_db
from app.db.models import (
    Department,
    Permission,
    Resource,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.db.session import SessionLocal


DEPARTMENTS = ["Finance", "HR", "IT", "Security"]


# (name, type, description)
RESOURCES = [
    ("finance-ledger", "application", "General ledger"),
    ("payments-system", "application", "Payment initiation and approval"),
    ("hr-records", "application", "Employee records"),
    ("siem-console", "application", "Security monitoring console"),
    ("PROD-LINUX-01", "server", "Production Linux server"),
    ("PROD-WIN-01", "server", "Production Windows server"),
    ("PROD-DB-01", "database", "Production database server"),
]


# (resource, action)
PERMISSIONS = [
    ("finance-ledger", "read"),
    ("payments-system", "initiate"),
    ("payments-system", "approve"),
    ("hr-records", "read"),
    ("hr-records", "update"),
    ("siem-console", "read"),
    ("siem-console", "triage"),
    ("PROD-LINUX-01", "admin"),
    ("PROD-WIN-01", "admin"),
    ("PROD-DB-01", "admin"),
]


# name -> (description, is_privileged, [(resource, action), ...])
ROLES = {
    "SOC Analyst": (
        "Monitors and triages security alerts",
        False,
        [("siem-console", "read"), ("siem-console", "triage")],
    ),
    "Finance Analyst": (
        "Reads the general ledger",
        False,
        [("finance-ledger", "read")],
    ),
    "Finance Manager": (
        "Finance oversight and reporting",
        False,
        [("finance-ledger", "read")],
    ),
    "HR Analyst": (
        "Maintains employee records",
        False,
        [("hr-records", "read"), ("hr-records", "update")],
    ),
    "System Administrator": (
        "Administers production servers",
        True,
        [("PROD-LINUX-01", "admin"), ("PROD-WIN-01", "admin")],
    ),
    "Database Administrator": (
        "Administers production databases",
        True,
        [("PROD-DB-01", "admin")],
    ),
    "Payment Initiator": (
        "Can create payments",
        False,
        [("payments-system", "initiate")],
    ),
    "Payment Approver": (
        "Can approve payments",
        False,
        [("payments-system", "approve")],
    ),
}


# (employee_id, username, full_name, department, manager_username, [roles])
USERS = [
    (
        "EMP001",
        "priya.nair",
        "Priya Nair",
        "Finance",
        None,
        ["Finance Manager", "Payment Approver"],
    ),
    (
        "EMP002",
        "rahul.mehta",
        "Rahul Mehta",
        "Finance",
        "priya.nair",
        ["Finance Analyst", "Payment Initiator"],
    ),
    (
        "EMP003",
        "sneha.rao",
        "Sneha Rao",
        "HR",
        None,
        ["HR Analyst"],
    ),
    # Stale-access case: moved Finance -> HR, still holds a Finance role.
    (
        "EMP004",
        "meera.iyer",
        "Meera Iyer",
        "HR",
        "sneha.rao",
        ["HR Analyst", "Finance Analyst"],
    ),
    (
        "EMP005",
        "arjun.verma",
        "Arjun Verma",
        "IT",
        None,
        ["System Administrator"],
    ),
    (
        "EMP006",
        "kiran.reddy",
        "Kiran Reddy",
        "IT",
        "arjun.verma",
        ["Database Administrator"],
    ),
    (
        "EMP007",
        "alisha.c",
        "Alisha C",
        "Security",
        None,
        ["SOC Analyst"],
    ),
]


def seed(db: Session) -> None:
    """Idempotent: does nothing if data already exists."""

    if db.scalar(select(func.count()).select_from(Department)):
        return

    departments = {
        name: Department(name=name)
        for name in DEPARTMENTS
    }

    resources = {
        name: Resource(
            name=name,
            resource_type=rtype,
            description=desc,
        )
        for name, rtype, desc in RESOURCES
    }

    db.add_all([
        *departments.values(),
        *resources.values(),
    ])

    db.flush()

    permissions = {
        (res, action): Permission(
            resource_id=resources[res].id,
            action=action,
        )
        for res, action in PERMISSIONS
    }

    db.add_all(permissions.values())

    roles = {}

    for name, (desc, privileged, perms) in ROLES.items():
        role = Role(
            name=name,
            description=desc,
            is_privileged=privileged,
        )
        roles[name] = role

    db.add_all(roles.values())
    db.flush()

    for name, (_, _, perms) in ROLES.items():
        for key in perms:
            db.add(
                RolePermission(
                    role_id=roles[name].id,
                    permission_id=permissions[key].id,
                )
            )

    users = {}

    for emp_id, username, full_name, dept, _, _ in USERS:
        users[username] = User(
            employee_id=emp_id,
            username=username,
            full_name=full_name,
            email=f"{username}@example.test",
            department_id=departments[dept].id,
        )

    db.add_all(users.values())
    db.flush()

    for _, username, _, _, manager, role_names in USERS:
        if manager:
            users[username].manager_id = users[manager].id

        for role_name in role_names:
            db.add(
                UserRole(
                    user_id=users[username].id,
                    role_id=roles[role_name].id,
                )
            )

    db.commit()


if __name__ == "__main__":
    init_db()

    with SessionLocal() as session:
        seed(session)

        print("Seed complete.")
        print(
            "users:",
            session.scalar(select(func.count()).select_from(User)),
        )
        print(
            "roles:",
            session.scalar(select(func.count()).select_from(Role)),
        )
        print(
            "permissions:",
            session.scalar(
                select(func.count()).select_from(Permission)
            ),
        )