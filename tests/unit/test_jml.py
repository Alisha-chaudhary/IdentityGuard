from app.audit.events import EventType
from app.audit.service import list_events
from app.db.models import Department, Role, User, UserRole
from app.iam.jml import (
    DepartmentNotFoundError,
    InvalidManagerError,
    ManagerNotFoundError,
    UserAlreadyExistsError,
    UserNotFoundError,
    create_user,
    move_user,
    terminate_user,
)


def create_department(db, name="IT"):
    department = Department(name=name)
    db.add(department)
    db.flush()
    return department


def test_create_user_creates_active_joiner(db):
    department = create_department(db)

    user = create_user(
        db,
        employee_id="EMP100",
        username="new.joiner",
        full_name="New Joiner",
        email="new.joiner@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    assert user.id is not None
    assert user.employee_id == "EMP100"
    assert user.username == "new.joiner"
    assert user.status == "ACTIVE"
    assert user.password_hash is not None
    assert user.password_hash != "StrongPassword123!"

    events = list_events(db)

    assert any(
        event.event_type == EventType.USER_CREATED.value
        and event.target == "new.joiner"
        and event.result == "SUCCESS"
        for event in events
    )


def test_create_user_supports_manager(db):
    department = create_department(db)

    manager = User(
        employee_id="EMP101",
        username="manager.user",
        full_name="Manager User",
        email="manager@example.com",
        password_hash="existing-hash",
        status="ACTIVE",
        department_id=department.id,
    )

    db.add(manager)
    db.flush()

    user = create_user(
        db,
        employee_id="EMP102",
        username="report.user",
        full_name="Report User",
        email="report@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        manager_id=manager.id,
        actor="admin",
    )

    assert user.manager_id == manager.id


def test_create_user_rejects_duplicate_identity(db):
    department = create_department(db)

    create_user(
        db,
        employee_id="EMP103",
        username="duplicate.user",
        full_name="Duplicate User",
        email="duplicate@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    try:
        create_user(
            db,
            employee_id="EMP103",
            username="another.username",
            full_name="Another User",
            email="another@example.com",
            department_id=department.id,
            password="StrongPassword123!",
            actor="admin",
        )
        assert False, "Expected UserAlreadyExistsError"
    except UserAlreadyExistsError:
        pass


def test_create_user_rejects_unknown_department(db):
    try:
        create_user(
            db,
            employee_id="EMP104",
            username="unknown.department",
            full_name="Unknown Department",
            email="unknown.department@example.com",
            department_id=99999,
            password="StrongPassword123!",
            actor="admin",
        )
        assert False, "Expected DepartmentNotFoundError"
    except DepartmentNotFoundError:
        pass


def test_create_user_rejects_unknown_manager(db):
    department = create_department(db)

    try:
        create_user(
            db,
            employee_id="EMP105",
            username="unknown.manager",
            full_name="Unknown Manager",
            email="unknown.manager@example.com",
            department_id=department.id,
            password="StrongPassword123!",
            manager_id=99999,
            actor="admin",
        )
        assert False, "Expected ManagerNotFoundError"
    except ManagerNotFoundError:
        pass


def test_move_user_changes_department(db):
    old_department = create_department(db, "IT")
    new_department = create_department(db, "Finance")

    user = create_user(
        db,
        employee_id="EMP109",
        username="department.mover",
        full_name="Department Mover",
        email="department.mover@example.com",
        department_id=old_department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    moved_user = move_user(
        db,
        user_id=user.id,
        department_id=new_department.id,
        actor="admin",
    )

    assert moved_user.department_id == new_department.id


def test_move_user_changes_manager(db):
    department = create_department(db)

    old_manager = User(
        employee_id="EMP110",
        username="old.manager",
        full_name="Old Manager",
        email="old.manager@example.com",
        password_hash="existing-hash",
        status="ACTIVE",
        department_id=department.id,
    )

    new_manager = User(
        employee_id="EMP111",
        username="new.manager",
        full_name="New Manager",
        email="new.manager@example.com",
        password_hash="existing-hash",
        status="ACTIVE",
        department_id=department.id,
    )

    db.add_all([old_manager, new_manager])
    db.flush()

    user = create_user(
        db,
        employee_id="EMP112",
        username="manager.mover",
        full_name="Manager Mover",
        email="manager.mover@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        manager_id=old_manager.id,
        actor="admin",
    )

    moved_user = move_user(
        db,
        user_id=user.id,
        manager_id=new_manager.id,
        actor="admin",
    )

    assert moved_user.manager_id == new_manager.id


def test_move_user_records_audit_event(db):
    old_department = create_department(db, "IT")
    new_department = create_department(db, "Finance")

    user = create_user(
        db,
        employee_id="EMP113",
        username="audit.mover",
        full_name="Audit Mover",
        email="audit.mover@example.com",
        department_id=old_department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    move_user(
        db,
        user_id=user.id,
        department_id=new_department.id,
        actor="admin",
    )

    events = list_events(db)

    assert any(
        event.event_type == EventType.USER_MOVED.value
        and event.target == "audit.mover"
        and event.result == "SUCCESS"
        for event in events
    )


def test_move_user_rejects_unknown_user(db):
    department = create_department(db, "Finance")

    try:
        move_user(
            db,
            user_id=99999,
            department_id=department.id,
            actor="admin",
        )
        assert False, "Expected UserNotFoundError"
    except UserNotFoundError:
        pass


def test_move_user_rejects_unknown_department(db):
    department = create_department(db)

    user = create_user(
        db,
        employee_id="EMP114",
        username="bad.department.move",
        full_name="Bad Department Move",
        email="bad.department@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    try:
        move_user(
            db,
            user_id=user.id,
            department_id=99999,
            actor="admin",
        )
        assert False, "Expected DepartmentNotFoundError"
    except DepartmentNotFoundError:
        pass


def test_move_user_rejects_unknown_manager(db):
    department = create_department(db)

    user = create_user(
        db,
        employee_id="EMP115",
        username="bad.manager.move",
        full_name="Bad Manager Move",
        email="bad.manager@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    try:
        move_user(
            db,
            user_id=user.id,
            manager_id=99999,
            actor="admin",
        )
        assert False, "Expected ManagerNotFoundError"
    except ManagerNotFoundError:
        pass


def test_move_user_rejects_self_as_manager(db):
    department = create_department(db)

    user = create_user(
        db,
        employee_id="EMP116",
        username="self.manager",
        full_name="Self Manager",
        email="self.manager@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    try:
        move_user(
            db,
            user_id=user.id,
            manager_id=user.id,
            actor="admin",
        )
        assert False, "Expected InvalidManagerError"
    except InvalidManagerError:
        pass


def test_terminate_user_marks_user_terminated(db):
    department = create_department(db)

    user = create_user(
        db,
        employee_id="EMP106",
        username="leaver.user",
        full_name="Leaver User",
        email="leaver@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    terminated_user = terminate_user(
        db,
        user_id=user.id,
        actor="admin",
    )

    assert terminated_user.status == "TERMINATED"
    assert terminated_user.terminated_at is not None


def test_terminate_user_expires_active_roles(db):
    department = create_department(db)

    user = create_user(
        db,
        employee_id="EMP107",
        username="role.leaver",
        full_name="Role Leaver",
        email="role.leaver@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    role = Role(
        name="Temporary Role",
        description="Role used for JML leaver testing",
        is_privileged=False,
    )

    db.add(role)
    db.flush()

    assignment = UserRole(
        user_id=user.id,
        role_id=role.id,
    )

    db.add(assignment)
    db.flush()

    assert assignment.expires_at is None

    terminated_user = terminate_user(
        db,
        user_id=user.id,
        actor="admin",
    )

    assert terminated_user.status == "TERMINATED"
    assert terminated_user.terminated_at is not None

    db.refresh(assignment)

    assert assignment.expires_at is not None
    assert assignment.expires_at == terminated_user.terminated_at


def test_terminate_user_records_audit_event(db):
    department = create_department(db)

    user = create_user(
        db,
        employee_id="EMP108",
        username="audit.leaver",
        full_name="Audit Leaver",
        email="audit.leaver@example.com",
        department_id=department.id,
        password="StrongPassword123!",
        actor="admin",
    )

    terminate_user(
        db,
        user_id=user.id,
        actor="admin",
    )

    events = list_events(db)

    assert any(
        event.event_type == EventType.USER_TERMINATED.value
        and event.target == "audit.leaver"
        and event.result == "SUCCESS"
        for event in events
    )


def test_terminate_user_rejects_unknown_user(db):
    try:
        terminate_user(
            db,
            user_id=99999,
            actor="admin",
        )
        assert False, "Expected UserNotFoundError"
    except UserNotFoundError:
        pass