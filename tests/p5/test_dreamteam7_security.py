"""
Security Evaluation & CTF Audit for DreamTeam7.
Tests access control logic, path canonicalization, handle security, and attack resistance.
All code and tests are restricted strictly to tests/p5.
"""

import asyncio
import base64
import json
import os
import shutil
import struct
import sys
import tempfile
from pathlib import Path
import pytest
import asyncssh

# Ensure DreamTeam7 directories are importable
TARGET_DIR = Path(__file__).resolve().parents[2] / "targets" / "DreamTeam7"
sys.path.insert(0, str(TARGET_DIR / "server"))
sys.path.insert(0, str(TARGET_DIR / "client"))
sys.path.insert(0, str(TARGET_DIR / "ctf"))

import audit
import auth
import loader
import policy
import server
import setup_flag


@pytest.fixture
def dreamteam7_env(tmp_path, monkeypatch):
    """Set up an isolated DreamTeam7 environment with a planted flag and test accounts."""
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(audit, "audit_file", audit_file)
    auth._failed.clear()
    auth._locked_until.clear()

    # Load base configuration
    data = loader.load_data(TARGET_DIR / "server" / "data")
    
    # Pre-provision test passwords for end-to-end evaluation
    passwords = {
        "alice": "alice-test-pass",
        "bob": "bob-test-pass",
        "carol": "carol-test-pass",
        "eve": "eve-test-pass",
    }
    data["users"] = {}
    for user, pw in passwords.items():
        u = auth.make_user(user, pw)
        data["users"][user] = {
            "salt": base64.b64decode(u["salt"]),
            "password_hash": base64.b64decode(u["password_hash"]),
            "n": u["n"], "r": u["r"], "p": u["p"], "dklen": u["dklen"]
        }

    jail_dir = tmp_path / "jail"
    key = tmp_path / "hostkey"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(key))

    # Plant flag using DreamTeam7's CTF setup script
    flag_content = "FLAG{group07_sftp_wins}"
    setup_flag.plant_flag(jail_dir, flag_content)

    return {
        "data": data,
        "passwords": passwords,
        "jail": jail_dir,
        "key": key,
        "audit": audit_file,
        "flag": flag_content,
    }


def test_flag_configuration(dreamteam7_env):
    """
    Verify flag location and format inside the jail.
    Flag is located at /projects/confidential/flag.txt and follows standard FLAG{...} format.
    """
    flag_file = dreamteam7_env["jail"] / "projects" / "confidential" / "flag.txt"
    assert flag_file.is_file(), f"Flag file does not exist at {flag_file}"
    content = flag_file.read_text(encoding="utf-8").strip()
    assert content == dreamteam7_env["flag"]
    assert content.startswith("FLAG{") and content.endswith("}")


def test_access_control_triad_and_composition(dreamteam7_env):
    """
    Verify that DreamTeam7's access control gate (DAC AND MAC AND RBAC)
    properly blocks unauthorized users and permits only authorized users.
    """
    policy.init(dreamteam7_env["data"])
    flag_path = "/projects/confidential/flag.txt"

    # Eve: guest role, public clearance -> denied by DAC, MAC, and RBAC
    allowed_eve, reason_eve = policy.authorize("eve", "read", flag_path)
    assert allowed_eve is False
    assert "DAC:" in reason_eve and "MAC:" in reason_eve and "RBAC:" in reason_eve

    # Bob: admin role, internal clearance -> denied by DAC (other on 660) and MAC (internal < confidential)
    allowed_bob, reason_bob = policy.authorize("bob", "read", flag_path)
    assert allowed_bob is False
    assert "DAC:" in reason_bob and "MAC:" in reason_bob

    # Alice: analyst role, internal clearance -> DAC and RBAC allow, but MAC strictly denies (no read up)
    assert policy.check_dac("alice", "read", flag_path, dreamteam7_env["data"])[0] is True
    assert policy.check_rbac("alice", "read", flag_path, dreamteam7_env["data"])[0] is True
    assert policy.check_mac("alice", "read", flag_path, dreamteam7_env["data"])[0] is False
    allowed_alice, reason_alice = policy.authorize("alice", "read", flag_path)
    assert allowed_alice is False
    assert "MAC: no read up" in reason_alice

    # Carol: analyst role, confidential clearance, owner -> all 3 models allow
    allowed_carol, reason_carol = policy.authorize("carol", "read", flag_path)
    assert allowed_carol is True
    assert "allowed:" in reason_carol


def test_path_traversal_and_canonicalization_resistance():
    """
    Verify that canonicalize and safe_join refuse path traversal, escapes, and Windows anomalies.
    """
    escapes = [
        "..",
        "/../etc/passwd",
        "/public/../../secret",
        "..\\..\\server\\data\\users.json",
        "/projects/confidential/flag.txt\0.jpg",
        "C:/Windows/win.ini",
        "file:stream",
    ]
    for raw in escapes:
        with pytest.raises(server.PathError):
            server.canonicalize(raw)


def test_live_sftp_attacks_resistance(dreamteam7_env):
    """
    Run an end-to-end SFTP attack suite over live SSH channels:
    1. Eve connects -> tries reading flag directly and via traversal -> DENIED.
    2. Alice connects -> tries reading flag and opening read+write -> DENIED.
    3. Bob connects -> tries reading flag -> DENIED.
    4. Carol connects -> reads flag -> SUCCEEDS and extracts FLAG{group07_sftp_wins}.
    """
    async def scenario():
        srv = await server.start_server(
            dreamteam7_env["data"], "127.0.0.1", 0,
            host_key=dreamteam7_env["key"], jail_dir=dreamteam7_env["jail"]
        )
        port = srv.get_port()

        try:
            # 1. Eve attack probe
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="eve",
                password=dreamteam7_env["passwords"]["eve"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.open("/projects/confidential/flag.txt", "rb")
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.stat("/projects/confidential/flag.txt")

            # 2. Alice attack probe (try read and try read+write)
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="alice",
                password=dreamteam7_env["passwords"]["alice"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.open("/projects/confidential/flag.txt", "rb")
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.open("/projects/confidential/flag.txt", "r+b")

            # 3. Bob attack probe
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="bob",
                password=dreamteam7_env["passwords"]["bob"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.open("/projects/confidential/flag.txt", "rb")

            # 4. Authorized retrieval by Carol
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="carol",
                password=dreamteam7_env["passwords"]["carol"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open("/projects/confidential/flag.txt", "rb") as f:
                        data = await f.read()
                        assert data.decode("utf-8").strip() == dreamteam7_env["flag"]

        finally:
            srv.close()
            # Append audit log to evidence folder
            evidence_file = Path(__file__).resolve().parents[2] / "results" / "group_7" / "evidence" / "p5_audit_extract.jsonl"
            evidence_file.parent.mkdir(parents=True, exist_ok=True)
            if dreamteam7_env["audit"].exists():
                with open(evidence_file, "a", encoding="utf-8") as out_f:
                    out_f.write(dreamteam7_env["audit"].read_text(encoding="utf-8"))

    asyncio.run(scenario())


def test_vuln_unauthorized_flag_overwrite_via_bell_lapadula_writeup(dreamteam7_env):
    """
    Vulnerability 7.1: Integrity Failure / Blind Flag Overwrite & Destruction.
    Due to DAC policy granting 0660 to group 'analyst' on /projects/confidential,
    combined with Bell-LaPadula allowing write-up (clearance 'internal' <= classification 'confidential')
    and RBAC granting 'write' on /projects, alice (internal) is granted write permissions on the flag.
    While alice cannot read the flag, she can open it with SSH_FXF_WRITE | SSH_FXF_TRUNC
    and overwrite or destroy the confidential flag.
    """
    policy.init(dreamteam7_env["data"])
    flag_path = "/projects/confidential/flag.txt"

    # Verify authorization engine allows alice to write
    allowed, reason = policy.authorize("alice", "write", flag_path)
    assert allowed is True, f"Expected write to be allowed, got: {reason}"
    assert "DAC: group has 0o2" in reason
    assert "MAC: internal may write confidential" in reason
    assert "RBAC: allowed (write)" in reason

    async def scenario():
        srv = await server.start_server(
            dreamteam7_env["data"], "127.0.0.1", 0,
            host_key=dreamteam7_env["key"], jail_dir=dreamteam7_env["jail"]
        )
        port = srv.get_port()

        try:
            # Alice connects and maliciously overwrites the confidential flag
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="alice",
                password=dreamteam7_env["passwords"]["alice"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open("/projects/confidential/flag.txt", "wb") as f:
                        await f.write(b"CORRUPTED_BY_ALICE")

            # Carol connects to read the flag - original flag was destroyed
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="carol",
                password=dreamteam7_env["passwords"]["carol"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open("/projects/confidential/flag.txt", "rb") as f:
                        content = await f.read()
                        assert content == b"CORRUPTED_BY_ALICE"

        finally:
            srv.close()
            # Append to evidence file
            evidence_file = Path(__file__).resolve().parents[2] / "results" / "group_7" / "evidence" / "p5_audit_extract.jsonl"
            if dreamteam7_env["audit"].exists():
                with open(evidence_file, "a", encoding="utf-8") as out_f:
                    out_f.write(dreamteam7_env["audit"].read_text(encoding="utf-8"))

    asyncio.run(scenario())


def test_vuln_account_lockout_denial_of_service(dreamteam7_env):
    """
    Vulnerability 7.2: Unauthenticated Account Lockout Denial-of-Service (DoS).
    auth.check_password tracks failed attempts per username without client authentication
    or IP binding. An attacker can repeatedly submit 5 invalid attempts for carol
    (the only user authorized to read confidential data) to lock her out for 60 seconds,
    denying all legitimate confidential operations.
    """
    users = dreamteam7_env["data"]["users"]

    # 1. Initially Carol can log in
    assert auth.check_password(users, "carol", dreamteam7_env["passwords"]["carol"]) is True

    # 2. Attacker floods 5 invalid passwords for Carol
    for _ in range(5):
        assert auth.check_password(users, "carol", "attacker_wrong_pass") is False

    # 3. Carol is now locked out; even correct password is rejected
    assert auth.check_password(users, "carol", dreamteam7_env["passwords"]["carol"]) is False

    # Update evidence file with lockout logs
    evidence_file = Path(__file__).resolve().parents[2] / "results" / "group_7" / "evidence" / "p5_audit_extract.jsonl"
    if dreamteam7_env["audit"].exists():
        with open(evidence_file, "a", encoding="utf-8") as out_f:
            out_f.write(dreamteam7_env["audit"].read_text(encoding="utf-8"))

