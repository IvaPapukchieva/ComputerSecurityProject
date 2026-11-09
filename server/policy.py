"""Access checks for the SFTP server using DAC, MAC and RBAC.

Call authorize() before working with a file or directory. 
The path must already be a canonical POSIX path inside the jail. 
Resolving paths and checking jail boundaries are the SFTP server's responsibility.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

LOGGER = logging.getLogger(__name__)
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
AUDIT_PATH = Path(__file__).resolve().parent / "audit.jsonl"

_OPERATIONS = {"realpath", "stat", "list", "mkdir", "read", "write", "remove", "rename", "create"}
_PERM_COLUMNS = {"read", "write", "delete", "mkdir", "create", "remove", "rename", "stat", "list", "realpath"}
_ALIASES = {"delete": "remove"}
_LOCK = threading.Lock()


class PolicyConfigError(RuntimeError):
    """The authorization settings are missing or cannot be loaded."""


@dataclass(frozen=True)
class OwnerRule:
    prefix: str
    owner: str
    group: str
    mode: int
    kind: str


@dataclass(frozen=True)
class Policy:
    user_roles: dict[str, tuple[str, ...]]
    role_perms: dict[str, tuple[dict[str, Any], ...]]
    user_clearances: dict[str, int]
    labels: tuple[tuple[str, int], ...]
    owners: tuple[OwnerRule, ...]
    user_groups: dict[str, tuple[str, ...]]


def _canonical_config_prefix(value: str, source: str) -> str:
    if not value.startswith("/") or "\\" in value or "\x00" in value:
        raise PolicyConfigError(f"{source}: resource prefix must be an absolute POSIX path")
    parts = value.split("/")
    if ".." in parts:
        raise PolicyConfigError(f"{source}: resource prefix may not contain '..'")
    normalized = str(PurePosixPath(value))
    return normalized if normalized != "." else "/"


def _load_policy(directory: Path) -> Policy:
    required = ("user_roles.json", "role_perms.csv", "mac_labels.json", "dac_owners.csv", "user_groups.json")
    for name in required:
        if not (directory / name).is_file():
            raise PolicyConfigError(f"missing required authorization configuration: {directory / name}")

    try:
        roles_doc = json.loads((directory / "user_roles.json").read_text(encoding="utf-8"))
        if not isinstance(roles_doc, dict) or not roles_doc or any(
            not isinstance(user, str) or not user or not isinstance(roles, list)
            or any(not isinstance(role, str) or not role for role in roles)
            for user, roles in roles_doc.items()
        ):
            raise ValueError("user_roles.json must map non-empty usernames to role lists")
        user_roles = {u: tuple(dict.fromkeys(rs)) for u, rs in roles_doc.items()}
        groups_doc = json.loads((directory / "user_groups.json").read_text(encoding="utf-8"))
        if not isinstance(groups_doc, dict) or set(groups_doc) != set(user_roles) or any(
            not isinstance(groups, list) or any(not isinstance(g, str) or not g for g in groups)
            for groups in groups_doc.values()
        ):
            raise ValueError("user_groups.json must map every configured username to a group list")

        role_perms: dict[str, list[dict[str, Any]]] = {}
        with (directory / "role_perms.csv").open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames or not {"role", "resource/prefix"}.issubset(reader.fieldnames):
                raise ValueError("role_perms.csv requires role,resource/prefix columns")
            actions = set(reader.fieldnames) & _PERM_COLUMNS
            if not actions:
                raise ValueError("role_perms.csv requires at least one operation permission column")
            for row in reader:
                role = (row.get("role") or "").strip()
                prefix = _canonical_config_prefix((row.get("resource/prefix") or "").strip(), "role_perms.csv")
                if not role:
                    raise ValueError("role_perms.csv contains an empty role")
                allow = {a for a in actions if (row.get(a) or "").strip().lower() in {"1", "true", "yes", "allow", "x"}}
                deny = {a for a in actions if (row.get(a) or "").strip().lower() in {"deny", "!", "-1"}}
                invalid = {a for a in actions if (row.get(a) or "").strip().lower() not in {"", "0", "false", "no", "allow", "yes", "true", "1", "x", "deny", "!", "-1"}}
                if invalid:
                    raise ValueError(f"role_perms.csv has invalid permission token(s): {sorted(invalid)}")
                role_perms.setdefault(role, []).append({"prefix": prefix, "allow": allow, "deny": deny})

        mac_doc = json.loads((directory / "mac_labels.json").read_text(encoding="utf-8"))
        if not isinstance(mac_doc, dict) or not isinstance(mac_doc.get("users"), dict) or not isinstance(mac_doc.get("labels"), dict):
            raise ValueError("mac_labels.json requires 'users' and 'labels' objects")
        levels = {"public": 0, "internal": 1, "confidential": 2}
        clearances = mac_doc["users"]
        if any(u not in user_roles or label not in levels for u, label in clearances.items()):
            raise ValueError("MAC users must exist in user_roles.json and use a known clearance")
        if set(clearances) != set(user_roles):
            raise ValueError("every configured user must have exactly one MAC clearance")
        labels: list[tuple[str, int]] = []
        for prefix, label in mac_doc["labels"].items():
            if label not in levels:
                raise ValueError(f"unknown MAC label {label!r} for {prefix!r}")
            labels.append((_canonical_config_prefix(prefix, "mac_labels.json"), levels[label]))

        owners: list[OwnerRule] = []
        with (directory / "dac_owners.csv").open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames or not {"path-prefix", "owner", "group", "mode", "kind"}.issubset(reader.fieldnames):
                raise ValueError("dac_owners.csv requires path-prefix,owner,group,mode,kind columns")
            for row in reader:
                prefix = _canonical_config_prefix((row.get("path-prefix") or "").strip(), "dac_owners.csv")
                owner, group = (row.get("owner") or "").strip(), (row.get("group") or "").strip()
                raw_mode = (row.get("mode") or "").strip()
                mode = int(raw_mode, 8)
                kind = (row.get("kind") or "").strip()
                if not owner or not group or not raw_mode or mode < 0 or mode > 0o777 or kind not in {"file", "directory"}:
                    raise ValueError("DAC owner rows require owner, group and a mode from 000 to 777")
                owners.append(OwnerRule(prefix, owner, group, mode, kind))
        if not owners:
            raise ValueError("dac_owners.csv must contain at least one ownership rule")

        for user, assigned in user_roles.items():
            unknown = set(assigned) - set(role_perms)
            if unknown:
                raise ValueError(f"user {user!r} refers to undefined role(s): {sorted(unknown)}")
        return Policy(user_roles, {r: tuple(v) for r, v in role_perms.items()},
                      {u: levels[v] for u, v in clearances.items()},
                      tuple(sorted(labels, key=lambda x: len(x[0]), reverse=True)),
                      tuple(sorted(owners, key=lambda x: len(x.prefix), reverse=True)),
                      {u: tuple(gs) for u, gs in groups_doc.items()})
    except PolicyConfigError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, csv.Error, ValueError, TypeError) as exc:
        raise PolicyConfigError(f"invalid authorization configuration in {directory}: {exc}") from exc


_POLICY = _load_policy(DATA_DIR)
for _config_name in ("user_roles.json", "role_perms.csv", "mac_labels.json", "dac_owners.csv", "user_groups.json"):
    LOGGER.info("Loaded authorization configuration file: %s", DATA_DIR / _config_name)


def _path_is_within(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _matching_rule(path: str, rules: tuple[Any, ...], prefix_getter=lambda rule: rule.prefix) -> Any | None:
    return next((rule for rule in rules if _path_is_within(path, prefix_getter(rule))), None)


def _valid_path(full_path: str) -> bool:
    if not isinstance(full_path, str) or not full_path.startswith("/") or "\\" in full_path or "\x00" in full_path:
        return False
    parts = full_path.split("/")
    return ".." not in parts and str(PurePosixPath(full_path)) == full_path


def _dac(user: str, op: str, path: str, policy: Policy) -> tuple[bool, str]:
    # Changes to directory entries need permissions on the parent.
    permission_path = path
    if op in {"mkdir", "create", "remove", "rename"}:
        permission_path = path.rsplit("/", 1)[0] or "/"
    rule = _matching_rule(permission_path, policy.owners)
    if rule is None:
        return False, "DAC: no ownership/mode rule for path"
    is_directory = rule.kind == "directory" and (
        op == "list" or permission_path == rule.prefix
    )
    # Use the mode bits for the matching owner, group or everyone else.
    if user == rule.owner:
        bits = (rule.mode >> 6) & 7
        category = "owner"
    elif rule.group in policy.user_groups.get(user, ()):
        bits = (rule.mode >> 3) & 7
        category = "group"
    else:
        bits = rule.mode & 7
        category = "other"
    if op in {"read", "write"}:
        if is_directory:
            return False, f"DAC: {op} requires a file, but the configured resource is a directory"
        needed = 4 if op == "read" else 2
    elif op == "list":
        if not is_directory:
            return False, "DAC: list requires a configured directory"
        needed = 5  # read and search
    elif op in {"stat", "realpath"}:
        needed = 1 if is_directory else 4
    elif op in {"mkdir", "create", "remove", "rename"}:
        needed = 3  # write and search on the parent
    else:
        return False, f"DAC: unsupported operation {op!r}"
    if bits & needed != needed:
        return False, f"DAC: {category} mode denies {op} (requires {needed:o}, has {bits:o})"
    # Each parent directory also needs the search bit.
    components = path.strip("/").split("/")[:-1]
    parent_paths = ["/"]
    for component in components:
        parent_paths.append((parent_paths[-1].rstrip("/") + "/" + component) or "/")
    for parent in parent_paths:
        parent_rule = _matching_rule(parent, policy.owners)
        if parent_rule is None or parent_rule.kind != "directory":
            return False, f"DAC: no directory ownership/mode rule for parent {parent}"
        if user == parent_rule.owner:
            parent_bits = (parent_rule.mode >> 6) & 7
        elif parent_rule.group in policy.user_groups.get(user, ()):
            parent_bits = (parent_rule.mode >> 3) & 7
        else:
            parent_bits = parent_rule.mode & 7
        if not parent_bits & 1:
            return False, f"DAC: directory search bit denies traversal through {parent}"
    return True, f"DAC: {category} mode on {permission_path} allows {op}"


def _mac(user: str, op: str, path: str, policy: Policy) -> tuple[bool, str]:
    clearance = policy.user_clearances.get(user)
    if clearance is None:
        return False, "MAC: user has no clearance"
    rule = _matching_rule(path, policy.labels, prefix_getter=lambda item: item[0])
    label = rule[1] if rule else 0  # public by default
    if op in {"read", "list", "stat", "realpath"}:
        if clearance < label:
            return False, "MAC: no read up (clearance below resource label)"
    elif op in {"write", "mkdir", "create", "remove", "rename"}:
        if clearance > label:
            return False, "MAC: no write down (resource label below clearance)"
    else:
        return False, f"MAC: unsupported operation {op!r}"
    return True, "MAC: clearance permits operation"


def _rbac(user: str, op: str, path: str, policy: Policy) -> tuple[bool, str]:
    roles = policy.user_roles.get(user)
    if roles is None:
        return False, "RBAC: user has no configured roles"
    action = _ALIASES.get(op, op)
    permission_names = {op, action}
    permission_names.update(alias for alias, target in _ALIASES.items() if target == action)
    allowed = False
    denied = False
    for role in roles:
        for entry in policy.role_perms.get(role, ()):
            if not _path_is_within(path, entry["prefix"]):
                continue
            if permission_names & entry["deny"]:
                denied = True
            if permission_names & entry["allow"]:
                allowed = True
    if denied:
        return False, "RBAC: explicit deny overrides role grants"
    if allowed:
        return True, f"RBAC: granted by role(s) {', '.join(roles)}"
    return False, "RBAC: no role grants this operation on this path"


def _audit(user: str, op: str, path: str, allowed: bool, reason: str) -> None:
    record = {"user": user, "op": op, "path": path, "allowed": allowed,
              "reason": reason, "timestamp": datetime.now(timezone.utc).isoformat()}
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with _LOCK, AUDIT_PATH.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
    except OSError:
        # Log the error without changing the authorization result.
        LOGGER.exception("Could not write authorization audit record")

def authorize(user: str, op: str, full_path: str) -> tuple[bool, str]:
    """Check all three policies and return whether access is allowed and why."""
    user = user if isinstance(user, str) else ""
    op = op if isinstance(op, str) else ""
    path = full_path if isinstance(full_path, str) else "<invalid>"
    if op not in _OPERATIONS:
        allowed, reason = False, f"default deny: unsupported operation {op!r}"
    elif not _valid_path(path):
        allowed, reason = False, "default deny: path is not canonical, absolute POSIX jail path"
    elif user not in _POLICY.user_roles:
        allowed, reason = False, "default deny: unknown user"
    else:
        decisions = (_dac(user, op, path, _POLICY), _mac(user, op, path, _POLICY), _rbac(user, op, path, _POLICY))
        allowed = all(result for result, _ in decisions)
        reason = "; ".join(message for _, message in decisions)
    _audit(user, op, path, allowed, reason)
    return bool(allowed), str(reason)
