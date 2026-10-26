"""Authorization matrix: every route is probed with
  (a) no token, (b) a valid token but WITHOUT the route's permission.

The permission guarding each route is discovered from the route's dependency
tree (require_permission tags its dependency with `required_permission`), so
a newly added route that forgets its guard fails `test_every_route_is_guarded`.
"""

import re

import pytest
from fastapi.routing import APIRoute
from sqlalchemy import select

from app.main import app
from app.db.models import Permission, Resource, Role, RolePermission, User, UserRole
from tests.api.conftest import SEED_PASSWORD  # noqa: F401  (fixtures imported via conftest)

# Routes that are intentionally reachable without a platform permission.
PUBLIC = {("GET", "/health"), ("GET", "/vault/health"), ("GET", "/ldap/health"), ("POST", "/auth/login")}
# Authenticated-only (any valid token), no permission.
AUTHENTICATED_ONLY = {
    ("GET", "/auth/me"),
    ("POST", "/auth/change-password"),
    ("GET", "/vault/grant"),
}


def _permission_of(route: APIRoute) -> str | None:
    def walk(dependant):
        for sub in dependant.dependencies:
            perm = getattr(sub.call, "required_permission", None)
            if perm:
                return perm
            found = walk(sub)
            if found:
                return found
        return None

    return walk(route.dependant)


ROUTER_MODULES = [
    "app.auth.routes", "app.api.users", "app.api.roles", "app.api.audit",
    "app.api.jml", "app.api.access_requests", "app.api.access_reviews",
    "app.api.pam", "app.api.reports", "app.api.vault", "app.api.ldap",
]


def _routes():
    # Walk each APIRouter directly: stable across FastAPI versions (newer
    # versions wrap included routers, so app.routes is not flat).
    import importlib

    for name in ROUTER_MODULES:
        for route in importlib.import_module(name).router.routes:
            if not isinstance(route, APIRoute):
                continue
            for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                yield method, route


def test_router_list_covers_the_app():
    """Fail if main.py mounts a router this matrix does not know about."""
    import app.main as main

    mounted = {
        mod.__name__ for mod in map(__import__("importlib").import_module, ROUTER_MODULES)
    }
    source = open(main.__file__).read()
    for module in mounted:
        assert f"from {module} import" in source
    assert source.count("include_router(") == len(ROUTER_MODULES)


ROUTES = list(_routes())
GUARDED = [
    (m, r) for m, r in ROUTES
    if (m, r.path) not in PUBLIC | AUTHENTICATED_ONLY
]


def _url(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


def test_every_route_is_guarded():
    unguarded = [
        f"{m} {r.path}" for m, r in GUARDED if _permission_of(r) is None
    ]
    assert unguarded == [], f"Routes without require_permission: {unguarded}"


@pytest.mark.parametrize(
    "method,route", GUARDED, ids=[f"{m} {r.path}" for m, r in GUARDED]
)
def test_no_token_is_rejected(api, method, route):
    response = api.request(method, _url(route.path), json={})
    assert response.status_code in (401, 403)


@pytest.mark.parametrize(
    "method,route", GUARDED, ids=[f"{m} {r.path}" for m, r in GUARDED]
)
def test_valid_token_without_permission_is_403(api, seeded, method, route):
    needed = _permission_of(route)

    # A user holding every IdentityGuard permission EXCEPT the one this route needs.
    resource = seeded.scalar(select(Resource).where(Resource.name == "IdentityGuard"))
    role = Role(name=f"All-but-{route.path}-{method}"[:90], description="matrix", is_privileged=False)
    seeded.add(role)
    seeded.flush()
    for permission in seeded.scalars(
        select(Permission).where(Permission.resource_id == resource.id)
    ):
        if f"IdentityGuard:{permission.action}" != needed:
            seeded.add(RolePermission(role_id=role.id, permission_id=permission.id))
    user = seeded.scalar(select(User).where(User.username == "auditor"))
    seeded.add(UserRole(user_id=user.id, role_id=role.id))
    seeded.commit()

    # Strip the auditor's own seeded role so only the "all but one" role counts.
    auditor_role = seeded.scalar(select(Role).where(Role.name == "Security Auditor"))
    for assignment in seeded.scalars(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == auditor_role.id)
    ):
        seeded.delete(assignment)
    seeded.commit()

    headers = api.login("auditor")
    response = api.request(method, _url(route.path), headers=headers, json={})
    assert response.status_code == 403, f"{method} {route.path} -> {response.status_code}"


def test_authenticated_only_routes_still_need_a_token(api):
    assert api.get("/auth/me").status_code in (401, 403)
    assert api.post("/auth/change-password", json={}).status_code in (401, 403)
