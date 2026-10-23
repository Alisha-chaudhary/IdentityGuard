import os
import secrets

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import check_password_strength, hash_password
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
    (
        "IdentityGuard",
        "platform",
        "IdentityGuard platform administration",
    ),
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

    # IdentityGuard platform permissions
    ("IdentityGuard", "user.create"),
    ("IdentityGuard", "user.move"),
    ("IdentityGuard", "user.terminate"),
    ("IdentityGuard", "user.read"),
    ("IdentityGuard", "role.assign"),
    ("IdentityGuard", "role.assign_privileged"),
    ("IdentityGuard", "role.remove"),
    ("IdentityGuard", "audit.read"),
    ("IdentityGuard", "access.request"),
    ("IdentityGuard", "access.approve"),
    ("IdentityGuard", "access.provision"),
    ("IdentityGuard", "access_review.create"),
    ("IdentityGuard", "access_review.view"),
    ("IdentityGuard", "access_review.decide"),
    ("IdentityGuard", "access_review.correct"),
    ("IdentityGuard", "access_review.complete"),
    ("IdentityGuard", "pam.request"),
    ("IdentityGuard", "pam.approve"),
    ("IdentityGuard", "pam.checkout"),
    ("IdentityGuard", "pam.revoke"),
    ("IdentityGuard", "reports.read"),
]


# name -> (description, is_privileged, [(resource, action), ...])
ROLES = {
    "SOC Analyst": (
        "Monitors and triages security alerts",
        False,
        [
            ("siem-console", "read"),
            ("siem-console", "triage"),
        ],
    ),
    "Finance Analyst": (
        "Reads the general ledger",
        False,
        [
            ("finance-ledger", "read"),
        ],
    ),
    "Finance Manager": (
        "Finance oversight and reporting",
        False,
        [
            ("finance-ledger", "read"),
        ],
    ),
    "HR Analyst": (
        "Maintains employee records",
        False,
        [
            ("hr-records", "read"),
            ("hr-records", "update"),
        ],
    ),
    "System Administrator": (
        "Administers production servers",
        True,
        [
            ("PROD-LINUX-01", "admin"),
            ("PROD-WIN-01", "admin"),
        ],
    ),
    "Database Administrator": (
        "Administers production databases",
        True,
        [
            ("PROD-DB-01", "admin"),
        ],
    ),
    "Payment Initiator": (
        "Can create payments",
        False,
        [
            ("payments-system", "initiate"),
        ],
    ),
    "Payment Approver": (
        "Can approve payments",
        False,
        [
            ("payments-system", "approve"),
        ],
    ),

    # IdentityGuard platform roles
    "IAM Administrator": (
        "Administrates IdentityGuard users, roles, and access",
        True,
        [
            ("IdentityGuard", "user.create"),
            ("IdentityGuard", "user.move"),
            ("IdentityGuard", "user.terminate"),
            ("IdentityGuard", "user.read"),
            ("IdentityGuard", "role.assign"),
            ("IdentityGuard", "role.assign_privileged"),
            ("IdentityGuard", "role.remove"),
            ("IdentityGuard", "audit.read"),
            ("IdentityGuard", "access.request"),
            ("IdentityGuard", "access.approve"),
            ("IdentityGuard", "access.provision"),
            ("IdentityGuard", "access_review.create"),
            ("IdentityGuard", "access_review.view"),
            ("IdentityGuard", "access_review.decide"),
            ("IdentityGuard", "access_review.complete"),
            ("IdentityGuard", "access_review.correct"),
            ("IdentityGuard", "pam.request"),
            ("IdentityGuard", "pam.approve"),
            ("IdentityGuard", "pam.checkout"),
            ("IdentityGuard", "pam.revoke"),
            ("IdentityGuard", "reports.read"),
        ],
    ),
    "Security Auditor": (
        "Reviews IdentityGuard audit information",
        False,
        [
            ("IdentityGuard", "user.read"),
            ("IdentityGuard", "audit.read"),
            ("IdentityGuard", "access_review.view"),
            ("IdentityGuard", "reports.read"),
        ],
    ),
    "Help Desk": (
        "Performs approved user and role support operations",
        False,
        [],
    ),
        "Access Reviewer": (
        "Reviews and decides access review items",
        False,
        [
            ("IdentityGuard", "access_review.view"),
            ("IdentityGuard", "access_review.decide"),
        ],
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
        "lisa",
        "Lisa C",
        "IT",
        None,
        ["System Administrator"],
    ),
    (
        "EMP006",
        "kiran.reddy",
        "Kiran Reddy",
        "IT",
        "lisa",
        ["Database Administrator"],
    ),
    (
        "EMP007",
        "arjun.verma",
        "Arjun Verma",
        "Security",
        None,
        ["SOC Analyst"],
    ),
]


def _get_seed_password() -> tuple[str, bool]:
    """
    Get the development seed password.

    Prefer IDENTITYGUARD_SEED_PASSWORD from the environment.
    Otherwise generate a one-time development password.
    """
    password = os.environ.get("IDENTITYGUARD_SEED_PASSWORD")

    if password:
        check_password_strength(password)
        return password, False

    password = secrets.token_urlsafe(12) + "A1!"
    check_password_strength(password)
    return password, True


def _seed_platform_rbac(db: Session) -> None:
    """
    Add the IdentityGuard platform resource, permissions,
    roles, and role-permission mappings.

    This is idempotent and works with an existing database.
    """

    # ---------------------------------------------------------
    # Platform resource
    # ---------------------------------------------------------
    resource = db.scalar(
        select(Resource).where(Resource.name == "IdentityGuard")
    )

    if resource is None:
        resource = Resource(
            name="IdentityGuard",
            resource_type="platform",
            description="IdentityGuard platform administration",
        )
        db.add(resource)
        db.flush()

    # ---------------------------------------------------------
    # Platform permissions
    # ---------------------------------------------------------
    platform_permissions = {
        "user.create": "Create new users",
        "user.move": "Move users between departments or managers",
        "user.terminate": "Terminate users (JML leaver)",
        "user.read": "Read user information",
        "role.assign": "Assign non-privileged roles",
        "role.assign_privileged": "Assign privileged roles",
        "role.remove": "Remove user roles",
        "audit.read": "Read audit events",
        "access.request": "Submit access requests",
        "access.approve": "Approve or reject access requests",
        "access.provision": "Provision approved access",
        "access_review.create": "Create access review cycles",
        "access_review.view": "View access review cycles",
        "access_review.decide": "Record access review decisions",
        "access_review.correct": "Correct decision reasons in open access review cycles",
        "access_review.complete": "Complete access review cycles",
        "pam.request": "Submit privileged access requests",
        "pam.approve": "Approve or reject privileged access requests",
        "pam.checkout": "Check out approved privileged access",
        "pam.revoke": "Revoke active privileged access checkouts",
        "reports.read": "Read identity and governance reports",

    }

    permissions = {}

    for action, description in platform_permissions.items():
        permission = db.scalar(
            select(Permission).where(
                Permission.resource_id == resource.id,
                Permission.action == action,
            )
        )

        if permission is None:
            permission = Permission(
                resource_id=resource.id,
                action=action,
            )
            db.add(permission)
            db.flush()

        permissions[action] = permission

    # ---------------------------------------------------------
    # Platform roles
    # ---------------------------------------------------------
    platform_roles = {
        "IAM Administrator": (
            "Administrates IdentityGuard users, roles, and access",
            True,
            [
                "user.create",
                "user.move",
                "user.terminate",
                "user.read",
                "role.assign",
                "role.assign_privileged",
                "role.remove",
                "audit.read",
                "access.request",
                "access.approve",
                "access.provision",
                "access_review.create",
                "access_review.view",
                "access_review.decide",
                "access_review.correct",
                "access_review.complete",
                "pam.request",
                "pam.approve",
                "pam.checkout",
                "pam.revoke",
                "reports.read",
            ],
        ),
        "Security Auditor": (
            "Reviews IdentityGuard audit information",
            False,
            [
                "user.read",
                "audit.read",
                "access_review.view",
                "reports.read",
            ],
        ),

        "Help Desk": (
            "Performs approved user and role support operations",
            False,
            [],
        ),

            "Access Reviewer": (
            "Reviews and decides access review items",
            False,
            [
                "access_review.view",
                "access_review.decide",
            ],
        ),
    }

    for role_name, (description, privileged, permission_names) in (
        platform_roles.items()
    ):
        role = db.scalar(
            select(Role).where(Role.name == role_name)
        )

        if role is None:
            role = Role(
                name=role_name,
                description=description,
                is_privileged=privileged,
            )
            db.add(role)
            db.flush()

        for permission_name in permission_names:
            permission = permissions[permission_name]

            existing_mapping = db.scalar(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission.id,
                )
            )

            if existing_mapping is None:
                db.add(
                    RolePermission(
                        role_id=role.id,
                        permission_id=permission.id,
                    )
                )

    # Revoke all IdentityGuard platform permissions from Help Desk,
    # including mappings left by earlier seed versions.
    help_desk = db.scalar(
        select(Role).where(Role.name == "Help Desk")
    )
    if help_desk is not None:
        for permission in permissions.values():
            existing_mapping = db.scalar(
                select(RolePermission).where(
                    RolePermission.role_id == help_desk.id,
                    RolePermission.permission_id == permission.id,
                )
            )
            if existing_mapping is not None:
                db.delete(existing_mapping)

    # Remove the obsolete decision permission from Security Auditor
    # in databases seeded by older versions.
    security_auditor = db.scalar(
        select(Role).where(Role.name == "Security Auditor")
    )
    decide_permission = permissions["access_review.decide"]

    if security_auditor is not None:
        obsolete_mapping = db.scalar(
            select(RolePermission).where(
                RolePermission.role_id == security_auditor.id,
                RolePermission.permission_id == decide_permission.id,
            )
        )

        if obsolete_mapping is not None:
            db.delete(obsolete_mapping)


    db.commit()


# ---------------------------------------------------------------------
# Demo platform identities (needed so a fresh clone can actually log in)
# ---------------------------------------------------------------------

# (employee_id, username, full_name, department, [roles])
DEMO_PLATFORM_USERS = [
    ("ADM001", "identityguard.admin", "IdentityGuard Admin", "Security", ["IAM Administrator"]),
    ("ADM002", "identityguard.admin2", "IdentityGuard Admin Two", "Security", ["IAM Administrator"]),
    ("AUD001", "auditor", "Security Auditor", "Security", ["Security Auditor"]),
    ("REV001", "reviewer", "Access Reviewer", "Security", ["Access Reviewer"]),
]

# Users who may request/check out privileged access (approval is done by an admin).
PAM_OPERATOR_ROLE = "PAM Operator"
PAM_OPERATOR_PERMISSIONS = ["pam.request", "pam.checkout"]
PAM_OPERATOR_USERNAMES = ["lisa", "kiran.reddy"]

# (safe name, [(account name, system, type)])
DEMO_PAM_SAFES = [
    (
        "Production Servers",
        [
            ("root-PROD-LINUX-01", "PROD-LINUX-01", "SYSTEM_ADMIN"),
            ("administrator-PROD-WIN-01", "PROD-WIN-01", "SYSTEM_ADMIN"),
        ],
    ),
    (
        "Production Databases",
        [("dba-PROD-DB-01", "PROD-DB-01", "DATABASE_ADMIN")],
    ),
]


def seed_demo_platform(db: Session, password: str) -> None:
    """Idempotently add the identities and PAM data the demo needs.

    - two IAM administrators (needed for four-eyes: approver != provisioner),
      an auditor and an access reviewer, all with platform permissions;
    - a 'PAM Operator' role (pam.request + pam.checkout) for lisa/kiran;
    - two PAM safes with accounts. No credentials are stored: PAM here is a
      simulated request / approve / checkout / expire workflow.
    Run after seed(); safe to run repeatedly.
    """
    from app.pam.models import PamAccount, PamSafe

    check_password_strength(password)
    resource = db.scalar(select(Resource).where(Resource.name == "IdentityGuard"))
    if resource is None:
        raise RuntimeError("Run seed(db) before seed_demo_platform(db).")

    # Opt-in, one-time password reset for the demo administrator only.
    # Set IDENTITYGUARD_RESET_DEMO_ADMIN_PASSWORD=true in the Render UI,
    # trigger a deployment that runs seeding, then unset it immediately.
    reset_admin_password = (
        os.environ.get("IDENTITYGUARD_RESET_DEMO_ADMIN_PASSWORD", "")
        .strip()
        .lower()
        in {"1", "true", "yes"}
    )

    for emp_id, username, full_name, dept_name, role_names in DEMO_PLATFORM_USERS:
        existing_user = db.scalar(select(User).where(User.username == username))
        if existing_user:
            # Only the demo administrator may have its password reset, and only
            # when the explicit opt-in switch is enabled.
            if reset_admin_password and username == "identityguard.admin":
                existing_user.password_hash = hash_password(password)
                existing_user.failed_attempts = 0
                existing_user.locked_until = None
                # Do not reactivate disabled or terminated accounts.
                if existing_user.status not in {"DISABLED", "TERMINATED"}:
                    existing_user.status = "ACTIVE"
            continue
        department = db.scalar(select(Department).where(Department.name == dept_name))
        user = User(
            employee_id=emp_id,
            username=username,
            full_name=full_name,
            email=f"{username}@example.test",
            department_id=department.id,
            password_hash=hash_password(password),
            status="ACTIVE",
            failed_attempts=0,
        )
        db.add(user)
        db.flush()
        for role_name in role_names:
            role = db.scalar(select(Role).where(Role.name == role_name))
            db.add(UserRole(user_id=user.id, role_id=role.id))

    operator = db.scalar(select(Role).where(Role.name == PAM_OPERATOR_ROLE))
    if operator is None:
        operator = Role(
            name=PAM_OPERATOR_ROLE,
            description="Can request and check out approved privileged access",
            is_privileged=False,
        )
        db.add(operator)
        db.flush()
    for action in PAM_OPERATOR_PERMISSIONS:
        permission = db.scalar(
            select(Permission).where(
                Permission.resource_id == resource.id,
                Permission.action == action,
            )
        )
        if db.scalar(
            select(RolePermission).where(
                RolePermission.role_id == operator.id,
                RolePermission.permission_id == permission.id,
            )
        ) is None:
            db.add(RolePermission(role_id=operator.id, permission_id=permission.id))

    for username in PAM_OPERATOR_USERNAMES:
        user = db.scalar(select(User).where(User.username == username))
        if user is not None and db.scalar(
            select(UserRole).where(
                UserRole.user_id == user.id, UserRole.role_id == operator.id
            )
        ) is None:
            db.add(UserRole(user_id=user.id, role_id=operator.id))

    for safe_name, accounts in DEMO_PAM_SAFES:
        safe = db.scalar(select(PamSafe).where(PamSafe.name == safe_name))
        if safe is None:
            safe = PamSafe(name=safe_name, description="Demo safe", status="ACTIVE")
            db.add(safe)
            db.flush()
        for name, system, account_type in accounts:
            if db.scalar(
                select(PamAccount).where(
                    PamAccount.safe_id == safe.id, PamAccount.name == name
                )
            ) is None:
                db.add(
                    PamAccount(
                        safe_id=safe.id,
                        name=name,
                        system_name=system,
                        account_type=account_type,
                        description="Demo privileged account (no stored credential)",
                        status="ACTIVE",
                    )
                )

    db.commit()


def seed(db: Session) -> None:
    """
    Idempotent seed.

    Fresh database:
        Creates the complete Phase 1 + Phase 3 + Phase 4 +
        Phase 6 seed.

    Existing database:
        Preserves existing IAM data, backfills missing password
        hashes, and adds missing platform RBAC data.
    """

    existing_users = db.scalars(select(User)).all()

    # ---------------------------------------------------------
    # Existing database
    # ---------------------------------------------------------
    if existing_users:
        users_missing_passwords = [
            user
            for user in existing_users
            if not user.password_hash
        ]

        if users_missing_passwords:
            password, generated_password = _get_seed_password()

            for user in users_missing_passwords:
                user.password_hash = hash_password(password)

            db.commit()

            if generated_password:
                print("Development seed password:", password)

        # Add or backfill platform RBAC.
        _seed_platform_rbac(db)

        return

    # ---------------------------------------------------------
    # Fresh database
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------
    permissions = {
        (res, action): Permission(
            resource_id=resources[res].id,
            action=action,
        )
        for res, action in PERMISSIONS
    }

    db.add_all(permissions.values())
    db.flush()

    # ---------------------------------------------------------
    # Roles
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # Role -> Permission mappings
    # ---------------------------------------------------------
    for name, (_, _, perms) in ROLES.items():
        for key in perms:
            db.add(
                RolePermission(
                    role_id=roles[name].id,
                    permission_id=permissions[key].id,
                )
            )

    # ---------------------------------------------------------
    # Users
    # ---------------------------------------------------------
    password, generated_password = _get_seed_password()

    users = {}

    for emp_id, username, full_name, dept, _, _ in USERS:
        users[username] = User(
            employee_id=emp_id,
            username=username,
            full_name=full_name,
            email=f"{username}@example.test",
            department_id=departments[dept].id,
            password_hash=hash_password(password),
            status="ACTIVE",
            failed_attempts=0,
            locked_until=None,
        )

    db.add_all(users.values())
    db.flush()

    # ---------------------------------------------------------
    # User -> Role mappings
    # ---------------------------------------------------------
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

    if generated_password:
        print("Development seed password:", password)


if __name__ == "__main__":
    init_db()

    # One password for every demo identity. Use IDENTITYGUARD_SEED_PASSWORD
    # to choose it, otherwise a random one is generated and printed once.
    _password, _generated = _get_seed_password()
    os.environ["IDENTITYGUARD_SEED_PASSWORD"] = _password

    with SessionLocal() as session:
        seed(session)
        seed_demo_platform(session, _password)

        print("Seed complete.")
        print("Demo logins: identityguard.admin, identityguard.admin2, "
              "auditor, reviewer, priya.nair, rahul.mehta, lisa, kiran.reddy ...")
        if _generated:
            print("Shared development password:", _password)
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