"""Shared permission request and grant-check utilities for tools."""

from __future__ import annotations

import hashlib
from typing import Any


class PermissionGate:
    """Unified permission checking and permission-request payload builder."""

    @staticmethod
    def subject_hash(subject: str) -> str:
        """Build a stable hash for one-time permission matching."""
        return hashlib.sha256(subject.strip().encode("utf-8")).hexdigest()[:16]

    def check_or_request(
        self,
        *,
        session: Any,
        subject: str,
        required_permissions: set[str],
        details: dict[str, str] | None = None,
        risk_level: str = "low",
        default_grant_mode: str = "persistent",
    ) -> dict[str, Any] | None:
        """Return permission_request payload when permissions are missing, else None."""
        if not required_permissions:
            return None

        granted = self._consume_granted_permissions(session=session, subject=subject)
        missing_permissions = required_permissions - granted
        if not missing_permissions:
            return None

        return {
            "type": "permission_request",
            "command": subject,
            "command_hash": self.subject_hash(subject) if session else None,
            "risk_level": risk_level,
            "default_grant_mode": default_grant_mode,
            "required_permissions": sorted(missing_permissions),
            "details": {
                perm: (details or {}).get(perm, "")
                for perm in sorted(missing_permissions)
            },
        }

    def _consume_granted_permissions(self, *, session: Any, subject: str) -> set[str]:
        """Read persistent permissions and consume one-time permissions for a subject."""
        if not session or not hasattr(session, "granted_permissions"):
            return set()

        granted_permissions = set(session.granted_permissions.get("persistent", set()))
        one_time = session.granted_permissions.get("one_time", {})
        cmd_hash = self.subject_hash(subject)
        if cmd_hash in one_time:
            granted_permissions.update(one_time[cmd_hash])
            del one_time[cmd_hash]

        return granted_permissions
