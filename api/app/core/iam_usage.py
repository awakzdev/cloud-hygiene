"""Helpers for IAM service/action last-accessed data."""
from __future__ import annotations

from datetime import datetime, timezone

from app.models import IamPermUsage


def _parse_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return None


def _normalize_action(action: str, service: str) -> str:
    if ":" in action:
        return action
    svc = (service or "").lower()
    return f"{svc}:{action}" if svc else action


def used_actions_from_usages(usages: list[IamPermUsage], cutoff: datetime) -> list[str]:
    """Return distinct action names used on or after cutoff (preserves AWS casing)."""
    seen: dict[str, str] = {}
    for u in usages:
        for entry in u.actions_json or []:
            if isinstance(entry, str):
                if u.last_authenticated and u.last_authenticated >= cutoff:
                    action = _normalize_action(entry, u.service)
                    key = action.lower()
                    seen.setdefault(key, action)
                continue
            if not isinstance(entry, dict):
                continue
            action = entry.get("action")
            if not action:
                continue
            action = _normalize_action(action, u.service)
            la = _parse_dt(entry.get("last_authenticated"))
            if la is None or la < cutoff:
                continue
            key = action.lower()
            seen.setdefault(key, action)
    return sorted(seen.values(), key=str.lower)


def service_has_tracked_actions_in_window(usage: IamPermUsage, cutoff: datetime) -> bool:
    """True when IAM returned per-action last-access within the window."""
    if not usage.actions_json:
        return False
    for entry in usage.actions_json:
        if isinstance(entry, str):
            if usage.last_authenticated and usage.last_authenticated >= cutoff:
                return True
            continue
        if not isinstance(entry, dict):
            continue
        la = _parse_dt(entry.get("last_authenticated"))
        if la is not None and la >= cutoff:
            return True
    return False


def used_services_from_usages(usages: list[IamPermUsage], cutoff: datetime) -> set[str]:
    return {
        u.service for u in usages
        if u.last_authenticated is not None and u.last_authenticated >= cutoff
    }


def services_with_action_evidence(usages: list[IamPermUsage], cutoff: datetime) -> set[str]:
    return {
        u.service for u in usages
        if u.last_authenticated is not None
        and u.last_authenticated >= cutoff
        and service_has_tracked_actions_in_window(u, cutoff)
    }


def services_with_service_only_evidence(usages: list[IamPermUsage], cutoff: datetime) -> set[str]:
    used = used_services_from_usages(usages, cutoff)
    with_actions = services_with_action_evidence(usages, cutoff)
    return used - with_actions


def augment_used_actions_with_granted_for_service_only(
    tracked_actions: list[str],
    usages: list[IamPermUsage],
    cutoff: datetime,
    granted_actions: list[str],
) -> tuple[list[str], list[str]]:
    """Preserve permissions for services that are used but lack action-level detail.

    IAM service-last-accessed sometimes reports that a service was used recently without
    per-action timestamps. Dropping such a service would break the workload, so we preserve
    the best signal available, in order of preference (least-privilege first):

      1. Specific granted actions for the service (e.g. ``dynamodb:PutItem``) — kept as-is.
      2. Otherwise, if the service is only granted via a wildcard (``svc:*`` or ``*``),
         preserve a service-scoped wildcard (``svc:*``) and warn. This narrows ``*`` to the
         single service and never silently removes a service that has recorded usage.
      3. Otherwise (no grant matches the service), warn only — there is nothing to preserve.

    Returns (actions, warnings).
    """
    seen: dict[str, str] = {a.lower(): a for a in tracked_actions}
    warnings: list[str] = []
    tracked_svcs = {a.split(":")[0].lower() for a in tracked_actions if ":" in a}
    granted_has_star = any(g == "*" for g in granted_actions)

    for u in usages:
        svc = (u.service or "").lower()
        if not svc:
            continue
        if u.last_authenticated is None or u.last_authenticated < cutoff:
            continue
        if service_has_tracked_actions_in_window(u, cutoff):
            continue
        if svc in tracked_svcs:
            continue

        specific = [
            g
            for g in granted_actions
            if g != "*" and not g.endswith(":*") and ":" in g and g.split(":")[0].lower() == svc
        ]
        if specific:
            for action in specific:
                seen.setdefault(action.lower(), action)
            continue

        svc_wildcard_granted = granted_has_star or any(
            g.endswith(":*") and g.split(":")[0].lower() == svc for g in granted_actions
        )
        if svc_wildcard_granted:
            wildcard = f"{svc}:*"
            seen.setdefault(wildcard.lower(), wildcard)
            warnings.append(
                f"{svc}: used recently but IAM returned service-level evidence only and the grant is a "
                f"wildcard. Preserved as {wildcard} so the workload keeps working — could not scope to "
                "specific actions. Run CloudTrail policy generation for this role (Remediation → "
                "advanced generate) once CloudTrail has enough history for this service."
            )
        else:
            warnings.append(
                f"{svc}: IAM reported service-level use only; no matching grant found for this service."
            )

    return sorted(seen.values(), key=str.lower), warnings


def unused_services_from_usages(usages: list[IamPermUsage], cutoff: datetime) -> set[str]:
    return {
        u.service for u in usages
        if u.last_authenticated is None or u.last_authenticated < cutoff
    }
