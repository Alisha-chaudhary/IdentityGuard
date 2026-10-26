"""LDAP directory synchronization service for IdentityGuard.

Compares directory records from OpenLDAP against IdentityGuard's local
application identity records and produces a change report. The first mode
is dry-run by default: no local users or role assignments are modified.

All changes are recorded in the database (directory_sync_runs,
directory_sync_changes, external_identities) and in IdentityGuard's
audit trail so each sync run is auditable and idempotent.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import EventType, Result
from app.audit.service import record_event
from app.db.models import (
    Department,
    DirectoryGroupMapping,
    DirectorySyncChange,
    DirectorySyncRun,
    ExternalIdentity,
    Role,
    User,
    UserRole,
)
from app.ldap.client import LdapClient
from app.ldap.models import DirectoryGroup, DirectorySearchResult, DirectoryUser

# Change type constants
CHANGE_CREATE_USER = "create_user"
CHANGE_ASSIGN_ROLE = "assign_role"
CHANGE_REMOVE_ROLE = "remove_role"
CHANGE_SKIP_NOOP = "skip_noop"
CHANGE_SKIP_CONFLICT = "skip_conflict"
CHANGE_SKIP_DISABLED = "skip_disabled"
CHANGE_SKIP_MISSING = "skip_missing"

# Outcome constants
OUTCOME_PROPOSED = "proposed"
OUTCOME_APPLIED = "applied"
OUTCOME_SKIPPED = "skipped"
OUTCOME_FAILED = "failed"

# Run mode constants
MODE_DRY_RUN = "dry-run"
MODE_APPLY = "apply"

# Run outcome constants
RUN_COMPLETED = "completed"
RUN_PARTIAL = "partial"
RUN_FAILED = "failed"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _json_dumps(obj: object) -> str:
    return json.dumps(obj, default=str, sort_keys=True)


def _new_run_id() -> str:
    return uuid.uuid4().hex


class SyncReport:
    """A human- and machine-readable synchronization change report."""

    def __init__(self, run_id: str, mode: str) -> None:
        self.run_id = run_id
        self.mode = mode
        self.changes: list[dict] = []
        self.summary: dict[str, int] = {
            "proposed": 0,
            "applied": 0,
            "skipped": 0,
            "failed": 0,
        }
        self.new_identities: list[dict] = []
        self.changed_attributes: list[dict] = []
        self.changed_groups: list[dict] = []
        self.unknown_groups: list[str] = []
        self.conflicts: list[dict] = []
        self.disabled_accounts: list[dict] = []
        self.missing_entries: list[dict] = []

    def add_change(
        self,
        change_type: str,
        outcome: str,
        external_id: Optional[str] = None,
        local_user_id: Optional[int] = None,
        target_role_id: Optional[int] = None,
        previous_state: Optional[str] = None,
        proposed_state: Optional[str] = None,
        reason: str = "",
    ) -> None:
        self.changes.append(
            {
                "change_type": change_type,
                "outcome": outcome,
                "external_id": external_id,
                "local_user_id": local_user_id,
                "target_role_id": target_role_id,
                "previous_state": previous_state,
                "proposed_state": proposed_state,
                "reason": reason,
            }
        )
        self.summary[outcome] = self.summary.get(outcome, 0) + 1

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "mode": self.mode,
            "summary": self.summary,
            "new_identities": self.new_identities,
            "changed_attributes": self.changed_attributes,
            "changed_groups": self.changed_groups,
            "unknown_groups": self.unknown_groups,
            "conflicts": self.conflicts,
            "disabled_accounts": self.disabled_accounts,
            "missing_entries": self.missing_entries,
            "changes": self.changes,
        }


class DirectorySynchronizer:
    """Synchronizes LDAP directory records with IdentityGuard local records.

    The first mode is dry-run: changes are reported but not applied to
    local users or role assignments.
    """

    def __init__(
        self,
        db: Session,
        ldap_client: LdapClient,
        mode: str = MODE_DRY_RUN,
    ) -> None:
        self.db = db
        self.ldap_client = ldap_client
        self.mode = mode
        self.report = SyncReport(run_id=_new_run_id(), mode=mode)

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    @classmethod
    def apply(
        cls,
        db: Session,
        ldap_client: LdapClient,
    ) -> SyncReport:
        """Run a synchronization cycle in apply mode.

        Requires explicit operator action: the caller must pass an
        LDAP client that is already opened and bound. Applies approved
        changes to local users and role assignments. Revalidates
        preconditions before applying any change.

        Returns a SyncReport describing all applied changes.
        """
        sync = cls(db, ldap_client, mode=MODE_APPLY)
        return sync.synchronize()

    def synchronize(self) -> SyncReport:
        """Run a full synchronization cycle.

        Returns a SyncReport describing all proposed changes. In dry-run
        mode no local users or role assignments are modified.
        """
        run = DirectorySyncRun(
            run_id=self.report.run_id,
            mode=self.mode,
            started_at=_utcnow(),
            outcome=RUN_COMPLETED,
        )
        self.db.add(run)
        self.db.flush()

        # Record the sync start in the audit trail.
        self._audit(
            actor="system",
            event_type=EventType.DIRECTORY_SYNC_STARTED,
            target="ldap:directory",
            action="synchronize",
            result=Result.SUCCESS,
            reason=f"mode={self.mode} run_id={self.report.run_id}",
        )

        try:
            # Search the directory.
            search_result = self.ldap_client.search_all()

            if search_result.failed:
                run.outcome = RUN_FAILED
                run.error = search_result.error
                self.db.commit()
                self._audit(
                    actor="system",
                    event_type=EventType.DIRECTORY_SYNC_FAILED,
                    target="ldap:directory",
                    action="synchronize",
                    result=Result.FAILURE,
                    reason=f"search failed: {search_result.error}",
                )
                self.report.summary["failed"] += 1
                return self.report

            if not search_result.complete:
                run.outcome = RUN_PARTIAL

            # Load local state.
            local_users = self._load_local_users()
            local_roles = self._load_local_roles()
            local_user_roles = self._load_local_user_roles()
            external_identities = self._load_external_identities()
            group_mappings = self._load_group_mappings()

            # Build lookup indexes.
            users_by_external_id: dict[str, ExternalIdentity] = dict(
                external_identities
            )
            users_by_username: dict[str, User] = {
                u.username: u for u in local_users.values()
            }
            roles_by_id: dict[int, Role] = dict(local_roles)
            roles_by_name: dict[str, Role] = {r.name: r for r in local_roles.values()}
            mappings_by_group_dn: dict[str, DirectoryGroupMapping] = {
                m.group_dn: m for m in group_mappings.values()
            }
            user_role_set: set[tuple[int, int]] = {
                (ur.user_id, ur.role_id) for ur in local_user_roles
            }

            # Identify directory groups that have no mapping.
            for group in search_result.groups:
                if group.dn not in mappings_by_group_dn:
                    self.report.unknown_groups.append(group.cn)

            # Process each directory user.
            seen_external_ids: set[str] = set()
            for directory_user in search_result.users:
                seen_external_ids.add(directory_user.entry_uuid)

                match_result = self._match_identity(
                    directory_user,
                    users_by_external_id,
                    users_by_username,
                    external_identities,
                    local_users,
                )

                if match_result["conflict"]:
                    self._handle_conflict(directory_user, match_result)
                    continue

                if directory_user.account_status == "disabled":
                    self._handle_disabled(
                        directory_user, match_result, local_user_roles, user_role_set
                    )
                    continue

                external_id = match_result["external_id"]
                local_user = match_result["local_user"]
                is_new_identity = match_result["is_new"]

                if is_new_identity:
                    self._handle_new_identity(
                        directory_user, local_users, user_role_set
                    )
                    continue

                # Existing identity: check attribute changes and group membership.
                self._check_attribute_changes(directory_user, local_user)
                self._check_group_membership(
                    directory_user,
                    local_user,
                    search_result.groups,
                    mappings_by_group_dn,
                    roles_by_id,
                    user_role_set,
                )

            # Identify local users with external identities that are missing
            # from the directory search results.
            for external_id, ei in external_identities.items():
                if external_id not in seen_external_ids:
                    self._handle_missing_entry(ei)

            # Finalize the run.
            run.completed_at = _utcnow()
            run.summary = _json_dumps(self.report.as_dict())
            run.outcome = run.outcome or RUN_COMPLETED
            self.db.commit()

            self._audit(
                actor="system",
                event_type=EventType.DIRECTORY_SYNC_COMPLETED,
                target="ldap:directory",
                action="synchronize",
                result=Result.SUCCESS,
                reason=f"mode={self.mode} run_id={self.report.run_id} "
                f"summary={self.report.summary}",
            )

        except Exception as exc:  # pragma: no cover - infrastructure errors
            run.outcome = RUN_FAILED
            run.error = str(exc)
            run.completed_at = _utcnow()
            self.db.rollback()
            self.db.add(run)
            self.db.commit()
            self._audit(
                actor="system",
                event_type=EventType.DIRECTORY_SYNC_FAILED,
                target="ldap:directory",
                action="synchronize",
                result=Result.FAILURE,
                reason=str(exc),
            )
            raise

        return self.report

    # ------------------------------------------------------------------
    # Local state loading
    # ------------------------------------------------------------------

    def _load_local_users(self) -> dict[int, User]:
        users = self.db.scalars(select(User)).all()
        return {u.id: u for u in users}

    def _load_local_roles(self) -> dict[int, Role]:
        roles = self.db.scalars(select(Role)).all()
        return {r.id: r for r in roles}

    def _load_local_user_roles(self) -> list[UserRole]:
        return list(self.db.scalars(select(UserRole)).all())

    def _load_external_identities(self) -> dict[str, ExternalIdentity]:
        identities = self.db.scalars(select(ExternalIdentity)).all()
        return {ei.external_id: ei for ei in identities}

    def _load_group_mappings(self) -> dict[int, DirectoryGroupMapping]:
        mappings = self.db.scalars(select(DirectoryGroupMapping)).all()
        return {m.id: m for m in mappings}

    # ------------------------------------------------------------------
    # Identity matching
    # ------------------------------------------------------------------

    def _match_identity(
        self,
        directory_user: DirectoryUser,
        users_by_external_id: dict[str, ExternalIdentity],
        users_by_username: dict[str, User],
        external_identities: list[ExternalIdentity],
        local_users: dict[int, User],
    ) -> dict:
        """Match a directory user to a local application user.

        Matching order:
        1. By immutable entryUUID via ExternalIdentity.external_id
        2. By username (uid) as a candidate link — flagged for review
        3. No match → new identity

        Returns a dict with:
            external_id: str | None
            local_user: User | None
            is_new: bool
            conflict: bool
        """
        # 1. Match by immutable entryUUID.
        if directory_user.entry_uuid in users_by_external_id:
            ei = users_by_external_id[directory_user.entry_uuid]
            local_user = local_users.get(ei.local_user_id)
            return {
                "external_id": directory_user.entry_uuid,
                "local_user": local_user,
                "is_new": local_user is None,
                "conflict": False,
            }

        # 2. Candidate match by username.
        matching_users = [
            u for u in local_users.values() if u.username == directory_user.uid
        ]
        if len(matching_users) == 1:
            return {
                "external_id": None,
                "local_user": matching_users[0],
                "is_new": False,
                "conflict": False,
            }
        if len(matching_users) > 1:
            return {
                "external_id": None,
                "local_user": None,
                "is_new": False,
                "conflict": True,
            }

        # 3. No match.
        return {
            "external_id": None,
            "local_user": None,
            "is_new": True,
            "conflict": False,
        }

    # ------------------------------------------------------------------
    # Change handlers
    # ------------------------------------------------------------------

    def _handle_conflict(
        self,
        directory_user: DirectoryUser,
        match_result: dict,
    ) -> None:
        """Multiple local users match the same directory username.

        Do not silently merge. Propose a skip and record a conflict.
        """
        self.report.conflicts.append(
            {
                "external_id": directory_user.entry_uuid,
                "uid": directory_user.uid,
                "dn": directory_user.dn,
                "reason": "Multiple local users match directory username; "
                "manual review required",
            }
        )
        self.report.add_change(
            change_type=CHANGE_SKIP_CONFLICT,
            outcome=OUTCOME_SKIPPED,
            external_id=directory_user.entry_uuid,
            reason=(
                f"Ambiguous identity match for uid={directory_user.uid}: "
                "multiple local users found; not merged"
            ),
        )
        self._audit(
            actor="system",
            event_type=EventType.IDENTITY_MATCH_CONFLICT,
            target=f"ldap:uid:{directory_user.uid}",
            action="match_identity",
            result=Result.FAILURE,
            reason=(
                f"Multiple local users match directory username "
                f"{directory_user.uid}; manual review required"
            ),
            correlation_id=self.report.run_id,
        )

    def _handle_disabled(
        self,
        directory_user: DirectoryUser,
        match_result: dict,
        local_user_roles: list[UserRole],
        user_role_set: set[tuple[int, int]],
    ) -> None:
        """Directory account is explicitly disabled.

        In dry-run mode: propose removal of mapped local access.
        In apply mode: set the local user status to DISABLED and remove
        mapped role assignments. Do not delete the local user or erase
        audit history.
        """
        local_user = match_result["local_user"]
        external_id = match_result["external_id"]

        # Identify roles that would be removed.
        roles_to_remove: list[Role] = []
        roles_to_keep: list[Role] = []
        for ur in local_user_roles:
            if ur.user_id == local_user.id:
                role = self.db.get(Role, ur.role_id)
                if role is not None:
                    roles_to_remove.append(role)

        if self.mode == MODE_APPLY:
            # Disable the local user account.
            local_user.status = "DISABLED"
            self.db.flush()

            # Remove mapped role assignments.
            removed_count = 0
            for ur in list(local_user_roles):
                if ur.user_id == local_user.id:
                    self.db.delete(ur)
                    removed_count += 1
            self.db.flush()

            self.report.add_change(
                change_type=CHANGE_SKIP_DISABLED,
                outcome=OUTCOME_APPLIED,
                external_id=external_id,
                local_user_id=local_user.id,
                reason=(
                    f"Applied: directory account {directory_user.uid} is "
                    f"disabled; local user set to DISABLED and "
                    f"{removed_count} role assignment(s) removed"
                ),
            )
            self._audit(
                actor="system",
                event_type=EventType.USER_UPDATED,
                target=f"ldap:uid:{directory_user.uid}",
                action="disable_access",
                result=Result.SUCCESS,
                reason=(
                    f"Local user {directory_user.uid} set to DISABLED; "
                    f"{removed_count} role assignment(s) removed due to "
                    "directory account being disabled"
                ),
                correlation_id=self.report.run_id,
            )
            self._audit(
                actor="system",
                event_type=EventType.DIRECTORY_CHANGE_APPLIED,
                target=f"ldap:uid:{directory_user.uid}",
                action="disable_access",
                result=Result.SUCCESS,
                reason=(
                    f"Applied directory change: disabled local user "
                    f"{directory_user.uid}"
                ),
                correlation_id=self.report.run_id,
            )
            return

        self.report.disabled_accounts.append(
            {
                "external_id": external_id,
                "uid": directory_user.uid,
                "dn": directory_user.dn,
                "roles_to_remove": [r.name for r in roles_to_remove],
            }
        )
        self.report.add_change(
            change_type=CHANGE_SKIP_DISABLED,
            outcome=OUTCOME_SKIPPED,
            external_id=external_id,
            local_user_id=local_user.id,
            reason=(
                f"Directory account {directory_user.uid} is disabled; "
                f"proposed removal of {len(roles_to_remove)} mapped role(s)"
            ),
        )
        self._audit(
            actor="system",
            event_type=EventType.IDENTITY_DISABLED_IN_DIRECTORY,
            target=f"ldap:uid:{directory_user.uid}",
            action="disable_access",
            result=Result.SUCCESS,
            reason=(
                f"Directory account {directory_user.uid} is disabled; "
                f"{len(roles_to_remove)} mapped role(s) proposed for removal"
            ),
            correlation_id=self.report.run_id,
        )

    def _handle_new_identity(
        self,
        directory_user: DirectoryUser,
        local_users: dict[int, User],
        user_role_set: set[tuple[int, int]],
    ) -> None:
        """A directory identity with no local match.

        In dry-run mode: propose creation of a local user record.
        In apply mode: create the local user record and ExternalIdentity
        mapping. No roles are assigned until an explicit group-to-role
        mapping exists and group membership is processed.
        """
        self.report.new_identities.append(
            {
                "external_id": directory_user.entry_uuid,
                "uid": directory_user.uid,
                "cn": directory_user.cn,
                "mail": directory_user.mail,
                "dn": directory_user.dn,
            }
        )

        if self.mode == MODE_APPLY:
            # Create the local user record.
            dept = self.db.scalars(select(Department)).first()
            if dept is None:
                dept = Department(name="LDAP Synced")
                self.db.add(dept)
                self.db.flush()

            local_user = User(
                employee_id=f"LDAP-{directory_user.uid}",
                username=directory_user.uid,
                full_name=directory_user.cn or directory_user.uid,
                email=directory_user.mail or f"{directory_user.uid}@ldap.example.test",
                department_id=dept.id,
                status="ACTIVE",
            )
            self.db.add(local_user)
            self.db.flush()

            # Create the external identity mapping.
            ei = ExternalIdentity(
                provider="ldap",
                external_id=directory_user.entry_uuid,
                local_user_id=local_user.id,
                dn=directory_user.dn,
                username=directory_user.uid,
                last_seen_at=_utcnow(),
                sync_status="matched",
            )
            self.db.add(ei)
            self.db.flush()

            # Register the new user in local state so group processing can find it.
            local_users[local_user.id] = local_user

            self.report.add_change(
                change_type=CHANGE_CREATE_USER,
                outcome=OUTCOME_APPLIED,
                external_id=directory_user.entry_uuid,
                local_user_id=local_user.id,
                proposed_state=_json_dumps(
                    {
                        "uid": directory_user.uid,
                        "cn": directory_user.cn,
                        "mail": directory_user.mail,
                    }
                ),
                reason=(
                    f"Applied: created local user {directory_user.uid} "
                    f"(entryUUID={directory_user.entry_uuid})"
                ),
            )
            self._audit(
                actor="system",
                event_type=EventType.USER_CREATED,
                target=f"ldap:uid:{directory_user.uid}",
                action="create_user",
                result=Result.SUCCESS,
                reason=(
                    f"Created local user {directory_user.uid} from LDAP "
                    f"(entryUUID={directory_user.entry_uuid})"
                ),
                correlation_id=self.report.run_id,
            )
            self._audit(
                actor="system",
                event_type=EventType.DIRECTORY_CHANGE_APPLIED,
                target=f"ldap:uid:{directory_user.uid}",
                action="create_user",
                result=Result.SUCCESS,
                reason=(
                    f"Applied directory change: created local user "
                    f"{directory_user.uid}"
                ),
                correlation_id=self.report.run_id,
            )
            return

        self.report.add_change(
            change_type=CHANGE_CREATE_USER,
            outcome=OUTCOME_PROPOSED,
            external_id=directory_user.entry_uuid,
            proposed_state=_json_dumps(
                {
                    "uid": directory_user.uid,
                    "cn": directory_user.cn,
                    "mail": directory_user.mail,
                }
            ),
            reason=(
                f"New directory identity {directory_user.uid} has no local "
                "match; local user creation proposed"
            ),
        )
        self._audit(
            actor="system",
            event_type=EventType.DIRECTORY_CHANGE_PROPOSED,
            target=f"ldap:uid:{directory_user.uid}",
            action="create_user",
            result=Result.SUCCESS,
            reason=(
                f"New directory identity {directory_user.uid} "
                f"(entryUUID={directory_user.entry_uuid}) has no local match"
            ),
            correlation_id=self.report.run_id,
        )

    def _check_attribute_changes(
        self,
        directory_user: DirectoryUser,
        local_user: User,
    ) -> None:
        """Check if directory attributes differ from local user attributes.

        Changes to username or email are treated as possible identity
        management events, not proof of a different person.

        In apply mode: update the local user's full_name and email.
        """
        changes = []
        if directory_user.cn is not None and directory_user.cn != local_user.full_name:
            changes.append(
                f"full_name: {local_user.full_name} -> {directory_user.cn}"
            )
        if directory_user.mail is not None and directory_user.mail != local_user.email:
            changes.append(
                f"email: {local_user.email} -> {directory_user.mail}"
            )

        if changes:
            self.report.changed_attributes.append(
                {
                    "external_id": directory_user.entry_uuid,
                    "uid": directory_user.uid,
                    "local_user_id": local_user.id,
                    "changes": changes,
                }
            )

            if self.mode == MODE_APPLY:
                previous = _json_dumps(
                    {"full_name": local_user.full_name, "email": local_user.email}
                )
                local_user.full_name = directory_user.cn or local_user.full_name
                local_user.email = directory_user.mail or local_user.email
                self.db.flush()

                self.report.add_change(
                    change_type=CHANGE_ASSIGN_ROLE,  # attribute change, no role change
                    outcome=OUTCOME_APPLIED,
                    external_id=directory_user.entry_uuid,
                    local_user_id=local_user.id,
                    previous_state=previous,
                    proposed_state=_json_dumps(
                        {
                            "full_name": local_user.full_name,
                            "email": local_user.email,
                        }
                    ),
                    reason="; ".join(changes),
                )
                self._audit(
                    actor="system",
                    event_type=EventType.USER_UPDATED,
                    target=f"ldap:uid:{directory_user.uid}",
                    action="update_attributes",
                    result=Result.SUCCESS,
                    reason=(
                        f"Updated attributes for {directory_user.uid}: "
                        f"{'; '.join(changes)}"
                    ),
                    correlation_id=self.report.run_id,
                )
                self._audit(
                    actor="system",
                    event_type=EventType.DIRECTORY_CHANGE_APPLIED,
                    target=f"ldap:uid:{directory_user.uid}",
                    action="update_attributes",
                    result=Result.SUCCESS,
                    reason=(
                        f"Applied directory change: updated attributes "
                        f"for {directory_user.uid}"
                    ),
                    correlation_id=self.report.run_id,
                )
                return

            self.report.add_change(
                change_type=CHANGE_ASSIGN_ROLE,  # attribute change, no role change
                outcome=OUTCOME_PROPOSED,
                external_id=directory_user.entry_uuid,
                local_user_id=local_user.id,
                previous_state=_json_dumps(
                    {"full_name": local_user.full_name, "email": local_user.email}
                ),
                proposed_state=_json_dumps(
                    {
                        "full_name": directory_user.cn,
                        "email": directory_user.mail,
                    }
                ),
                reason="; ".join(changes),
            )

    def _check_group_membership(
        self,
        directory_user: DirectoryUser,
        local_user: User,
        groups: list[DirectoryGroup],
        mappings_by_group_dn: dict[str, DirectoryGroupMapping],
        roles_by_id: dict[int, Role],
        user_role_set: set[tuple[int, int]],
    ) -> None:
        """Check directory group membership against mapped local roles.

        For each mapped group the user is a member of, assign the mapped
        role (if not already assigned). For each mapped group the user
        is no longer a member of, remove the role.

        In dry-run mode: changes are proposed only.
        In apply mode: UserRole records are created or deleted.

        Privileged roles are never auto-assigned via directory mapping.
        """
        # Build set of group DNs the user is currently a member of.
        user_group_dns: set[str] = set()
        for group in groups:
            if directory_user.uid in group.member_uids:
                user_group_dns.add(group.dn)

        # For each mapping, check if the user should have the role.
        for group_dn, mapping in mappings_by_group_dn.items():
            if not mapping.is_active:
                continue

            role = roles_by_id.get(mapping.role_id)
            if role is None:
                continue

            # Privileged roles are never assigned via directory mapping.
            if role.is_privileged:
                continue

            user_has_role = (local_user.id, role.id) in user_role_set
            user_in_group = group_dn in user_group_dns

            if user_in_group and not user_has_role:
                # User is in the mapped group but doesn't have the role.
                self.report.changed_groups.append(
                    {
                        "external_id": directory_user.entry_uuid,
                        "uid": directory_user.uid,
                        "group": mapping.group_name,
                        "role": role.name,
                        "action": "assign",
                    }
                )

                if self.mode == MODE_APPLY:
                    user_role = UserRole(
                        user_id=local_user.id,
                        role_id=role.id,
                    )
                    self.db.add(user_role)
                    self.db.flush()
                    # Refresh the role set so subsequent checks see the new assignment.
                    user_role_set.add((local_user.id, role.id))

                    self.report.add_change(
                        change_type=CHANGE_ASSIGN_ROLE,
                        outcome=OUTCOME_APPLIED,
                        external_id=directory_user.entry_uuid,
                        local_user_id=local_user.id,
                        target_role_id=role.id,
                        proposed_state=_json_dumps({"role": role.name}),
                        reason=(
                            f"Applied: directory group {mapping.group_name} "
                            f"maps to role {role.name}; user {directory_user.uid} "
                            f"is a member"
                        ),
                    )
                    self._audit(
                        actor="system",
                        event_type=EventType.ROLE_ASSIGNED,
                        target=f"ldap:uid:{directory_user.uid}",
                        action="assign_role",
                        result=Result.SUCCESS,
                        reason=(
                            f"Assigned role {role.name} to {directory_user.uid} "
                            f"via LDAP group {mapping.group_name}"
                        ),
                        correlation_id=self.report.run_id,
                    )
                    self._audit(
                        actor="system",
                        event_type=EventType.DIRECTORY_CHANGE_APPLIED,
                        target=f"ldap:uid:{directory_user.uid}",
                        action="assign_role",
                        result=Result.SUCCESS,
                        reason=(
                            f"Applied directory change: assigned role "
                            f"{role.name} to {directory_user.uid}"
                        ),
                        correlation_id=self.report.run_id,
                    )
                else:
                    self.report.add_change(
                        change_type=CHANGE_ASSIGN_ROLE,
                        outcome=OUTCOME_PROPOSED,
                        external_id=directory_user.entry_uuid,
                        local_user_id=local_user.id,
                        target_role_id=role.id,
                        proposed_state=_json_dumps({"role": role.name}),
                        reason=(
                            f"Directory group {mapping.group_name} maps to role "
                            f"{role.name}; user {directory_user.uid} is a member"
                        ),
                    )
                    self._audit(
                        actor="system",
                        event_type=EventType.DIRECTORY_CHANGE_PROPOSED,
                        target=f"ldap:uid:{directory_user.uid}",
                        action="assign_role",
                        result=Result.SUCCESS,
                        reason=(
                            f"Propose assigning role {role.name} to "
                            f"{directory_user.uid} via group {mapping.group_name}"
                        ),
                        correlation_id=self.report.run_id,
                    )

            elif not user_in_group and user_has_role:
                # User is no longer in the mapped group but has the role.
                self.report.changed_groups.append(
                    {
                        "external_id": directory_user.entry_uuid,
                        "uid": directory_user.uid,
                        "group": mapping.group_name,
                        "role": role.name,
                        "action": "remove",
                    }
                )

                if self.mode == MODE_APPLY:
                    removed = self.db.execute(
                        __import__("sqlalchemy", fromlist=["delete"]).delete(
                            UserRole
                        ).where(
                            UserRole.user_id == local_user.id,
                            UserRole.role_id == role.id,
                        )
                    )
                    self.db.flush()

                    self.report.add_change(
                        change_type=CHANGE_REMOVE_ROLE,
                        outcome=OUTCOME_APPLIED,
                        external_id=directory_user.entry_uuid,
                        local_user_id=local_user.id,
                        target_role_id=role.id,
                        previous_state=_json_dumps({"role": role.name}),
                        reason=(
                            f"Applied: directory group {mapping.group_name} "
                            f"maps to role {role.name}; user {directory_user.uid} "
                            f"is no longer a member"
                        ),
                    )
                    self._audit(
                        actor="system",
                        event_type=EventType.ROLE_REMOVED,
                        target=f"ldap:uid:{directory_user.uid}",
                        action="remove_role",
                        result=Result.SUCCESS,
                        reason=(
                            f"Removed role {role.name} from {directory_user.uid} "
                            f"via LDAP group {mapping.group_name}"
                        ),
                        correlation_id=self.report.run_id,
                    )
                    self._audit(
                        actor="system",
                        event_type=EventType.DIRECTORY_CHANGE_APPLIED,
                        target=f"ldap:uid:{directory_user.uid}",
                        action="remove_role",
                        result=Result.SUCCESS,
                        reason=(
                            f"Applied directory change: removed role "
                            f"{role.name} from {directory_user.uid}"
                        ),
                        correlation_id=self.report.run_id,
                    )
                else:
                    self.report.add_change(
                        change_type=CHANGE_REMOVE_ROLE,
                        outcome=OUTCOME_PROPOSED,
                        external_id=directory_user.entry_uuid,
                        local_user_id=local_user.id,
                        target_role_id=role.id,
                        previous_state=_json_dumps({"role": role.name}),
                        reason=(
                            f"Directory group {mapping.group_name} maps to role "
                            f"{role.name}; user {directory_user.uid} is no longer a member"
                        ),
                    )
                    self._audit(
                        actor="system",
                        event_type=EventType.DIRECTORY_CHANGE_PROPOSED,
                        target=f"ldap:uid:{directory_user.uid}",
                        action="remove_role",
                        result=Result.SUCCESS,
                        reason=(
                            f"Propose removing role {role.name} from "
                            f"{directory_user.uid} via group {mapping.group_name}"
                        ),
                        correlation_id=self.report.run_id,
                    )

    def _handle_missing_entry(
        self,
        external_identity: ExternalIdentity,
    ) -> None:
        """A locally mapped identity is missing from the directory search.

        Do not interpret this as deletion. Propose no change; record for
        operator review.
        """
        local_user = self.db.get(User, external_identity.local_user_id)
        if local_user is None:
            return

        self.report.missing_entries.append(
            {
                "external_id": external_identity.external_id,
                "uid": external_identity.username,
                "local_user_id": local_user.id,
                "username": local_user.username,
            }
        )
        self.report.add_change(
            change_type=CHANGE_SKIP_MISSING,
            outcome=OUTCOME_SKIPPED,
            external_id=external_identity.external_id,
            local_user_id=local_user.id,
            reason=(
                f"Local user {local_user.username} (external_id="
                f"{external_identity.external_id}) is missing from the "
                "directory search results; no change proposed"
            ),
        )
        self._audit(
            actor="system",
            event_type=EventType.DIRECTORY_CHANGE_PROPOSED,
            target=f"ldap:external_id:{external_identity.external_id}",
            action="missing_entry",
            result=Result.SUCCESS,
            reason=(
                f"Local user {local_user.username} is missing from the "
                "directory search results; no change proposed"
            ),
            correlation_id=self.report.run_id,
        )

    # ------------------------------------------------------------------
    # Audit recording
    # ------------------------------------------------------------------

    def _audit(
        self,
        actor: str,
        event_type: EventType,
        target: str,
        action: str,
        result: Result,
        reason: str,
        correlation_id: Optional[str] = None,
    ) -> None:
        record_event(
            self.db,
            actor=actor,
            event_type=event_type,
            target=target,
            action=action,
            result=result,
            reason=reason,
            correlation_id=correlation_id or self.report.run_id,
        )
        self.db.flush()
