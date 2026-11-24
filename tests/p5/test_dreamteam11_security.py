"""
Security Evaluation & CTF Audit for DreamTeam11.
Tests two-layer defense architecture (DAC + MAC), independence of layers, overwrite resistance,
jail protection, and live SFTP attack probes.
All code and tests are restricted strictly to tests/p5.
"""

import asyncio
import csv
import json
import os
import shutil
import sys
from pathlib import Path
import pytest
import asyncssh

# Ensure DreamTeam11 directories are importable
TARGET_DIR = Path(__file__).resolve().parents[2] / "targets" / "DreamTeam11"
for m in list(sys.modules):
    if m in ("server", "policy", "auth", "jail", "rbac", "setup_demo", "setup_ctf", "e2e_support"):
        del sys.modules[m]

sys.path.insert(0, str(TARGET_DIR))
sys.path.insert(0, str(TARGET_DIR / "scripts"))
sys.path.insert(0, str(TARGET_DIR / "tests"))

import setup_ctf
import e2e_support
from server.policy import initialize_policy, load_policy
from server.auth import PasswordRecord, load_users, verify_password
from server import jail
import time


@pytest.fixture
def dreamteam11_env(tmp_path):
    """Set up an isolated DreamTeam11 environment with a planted flag and test accounts."""
    root = tmp_path / "install"
    shutil.copytree(
        TARGET_DIR, root,
        ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache", "sftp_root", "audit.jsonl")
    )
    
    # Pre-provision test accounts using DreamTeam11's e2e password mechanism
    passwords = {"alice": "alice-test-pw", "bob": "bob-test-pw", "eve": "eve-test-pw"}
    e2e_support.write_users(root / "data" / "users.json", passwords)

    # Plant flag
    jail_dir = root / "server" / "sftp_root"
    host_key = root / "server" / "ssh_host_ed25519_key"
    data_dir = root / "data"
    flag_content = setup_ctf.plant_flag(jail_dir, host_key, data_dir, new_flag=True).strip()

    audit_file = root / "server" / "audit.jsonl"
    policy = load_policy(jail_dir, data_dir=data_dir, audit_path=audit_file)

    return {
        "root": root,
        "jail": jail_dir,
        "data": data_dir,
        "audit": audit_file,
        "key": host_key,
        "passwords": passwords,
        "policy": policy,
        "flag": flag_content,
    }


def test_flag_configuration(dreamteam11_env):
    """
    Verify flag location and format inside the jail.
    Flag is located at /projects/confidential/flag.txt and follows standard FLAG{group11_sftp_...} format.
    """
    flag_file = dreamteam11_env["jail"] / "projects" / "confidential" / "flag.txt"
    assert flag_file.is_file(), f"Flag file does not exist at {flag_file}"
    content = flag_file.read_text(encoding="utf-8").strip()
    assert content == dreamteam11_env["flag"]
    assert content.startswith("FLAG{group11_sftp_") and content.endswith("}")


def test_two_layer_access_control_matrix(dreamteam11_env):
    """
    Verify DreamTeam11's two-layer defense (DAC + MAC) on /projects/confidential/flag.txt:
    - Alice: DAC allow, MAC allow, RBAC allow -> ALLOWED.
    - Bob: DAC deny (other lacks 0o4 on 0700/0600), MAC deny (internal < confidential) -> DENIED.
    - Eve: DAC deny, MAC deny -> DENIED.
    """
    policy = dreamteam11_env["policy"]
    flag_path = dreamteam11_env["jail"] / "projects" / "confidential" / "flag.txt"

    # 1. Alice (admin, confidential)
    allowed_alice, reason_alice = policy.authorize("alice", "read", flag_path)
    assert allowed_alice is True, f"Alice should be allowed: {reason_alice}"

    # 2. Bob (analyst, internal)
    allowed_bob, reason_bob = policy.authorize("bob", "read", flag_path)
    assert allowed_bob is False, f"Bob should be denied: {reason_bob}"
    assert "DAC permissions deny" in reason_bob
    assert "MAC no read up" in reason_bob

    # 3. Eve (intern, public)
    allowed_eve, reason_eve = policy.authorize("eve", "read", flag_path)
    assert allowed_eve is False, f"Eve should be denied: {reason_eve}"


def test_defense_in_depth_layer_independence(dreamteam11_env):
    """
    Demonstrate independence of DreamTeam11's protection layers:
    1. If DAC is opened (/projects/confidential set to 0777/0666), MAC alone still blocks Bob.
    2. If MAC is raised (Bob given confidential clearance), DAC alone still blocks Bob.
    """
    jail_dir = dreamteam11_env["jail"]
    data_dir = dreamteam11_env["data"]
    audit_file = dreamteam11_env["audit"]
    flag_path = jail_dir / "projects" / "confidential" / "flag.txt"

    # Case 1: Weaken DAC only
    dac_path = data_dir / "dac_owners.csv"
    rows = list(csv.reader(dac_path.open(encoding="utf-8")))
    for row in rows:
        if row[0] == "/projects/confidential":
            row[3], row[4] = "0666", "0777"
    with dac_path.open("w", encoding="utf-8", newline="") as f:
        csv.writer(f, lineterminator="\n").writerows(rows)

    policy_dac_weak = load_policy(jail_dir, data_dir=data_dir, audit_path=audit_file)
    allowed, reason = policy_dac_weak.authorize("bob", "read", flag_path)
    assert allowed is False
    assert "MAC no read up" in reason

    # Case 2: Restore DAC, Weaken MAC only
    for row in rows:
        if row[0] == "/projects/confidential":
            row[3], row[4] = "0600", "0700"
    with dac_path.open("w", encoding="utf-8", newline="") as f:
        csv.writer(f, lineterminator="\n").writerows(rows)

    mac_path = data_dir / "mac_labels.json"
    labels = json.loads(mac_path.read_text(encoding="utf-8"))
    labels["users"]["bob"] = "confidential"
    mac_path.write_text(json.dumps(labels, indent=2), encoding="utf-8")

    policy_mac_weak = load_policy(jail_dir, data_dir=data_dir, audit_path=audit_file)
    allowed, reason = policy_mac_weak.authorize("bob", "read", flag_path)
    assert allowed is False
    assert "DAC permissions deny" in reason


def test_flag_overwrite_tampering_resistance(dreamteam11_env):
    """
    Verify that Bob cannot overwrite or truncate the flag.
    Unlike DreamTeam7 (where group mode 0660 allowed write-up), DreamTeam11
    sets /projects/confidential to alice:admins mode 0700/0600, so DAC denies Bob.
    """
    policy = dreamteam11_env["policy"]
    flag_path = dreamteam11_env["jail"] / "projects" / "confidential" / "flag.txt"

    allowed, reason = policy.authorize("bob", "write", flag_path)
    assert allowed is False, f"Expected write to be denied, but got: {reason}"
    assert "DAC permissions deny" in reason


def test_live_sftp_attacks_resistance(dreamteam11_env):
    """
    End-to-end SFTP attack test over real SSH channels:
    1. Bob attempts to read /projects/confidential/flag.txt -> DENIED.
    2. Eve attempts to read /projects/confidential/flag.txt -> DENIED.
    3. Bob attempts to overwrite /projects/confidential/flag.txt -> DENIED.
    4. Alice connects and reads the flag -> SUCCEEDS.
    5. Copy audit log to results/group_11/evidence/p5_audit_extract.jsonl.
    """
    with e2e_support.ServerProcess(dreamteam11_env["root"], users=dreamteam11_env["data"] / "users.json") as server_proc:
        port = server_proc.port

        async def scenario():
            # 1. Bob probe
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="bob",
                password=dreamteam11_env["passwords"]["bob"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.open("/projects/confidential/flag.txt", "rb")
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.stat("/projects/confidential/flag.txt")

            # 2. Eve probe
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="eve",
                password=dreamteam11_env["passwords"]["eve"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.open("/projects/confidential/flag.txt", "rb")

            # 3. Bob overwrite probe
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="bob",
                password=dreamteam11_env["passwords"]["bob"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    with pytest.raises(asyncssh.SFTPPermissionDenied):
                        await sftp.open("/projects/confidential/flag.txt", "wb")

            # 4. Authorized retrieval by Alice
            async with asyncssh.connect(
                "127.0.0.1", port=port, username="alice",
                password=dreamteam11_env["passwords"]["alice"], known_hosts=None
            ) as conn:
                async with conn.start_sftp_client() as sftp:
                    async with sftp.open("/projects/confidential/flag.txt", "rb") as f:
                        data = await f.read()
                        assert data.decode("utf-8").strip() == dreamteam11_env["flag"]
                        print(f"\n[+] Flag successfully verified by Alice: {dreamteam11_env['flag']}")

        asyncio.run(scenario())

        # Copy audit log to evidence folder
        evidence_file = Path(__file__).resolve().parents[2] / "results" / "group_11" / "evidence" / "p5_audit_extract.jsonl"
        evidence_file.parent.mkdir(parents=True, exist_ok=True)
        if server_proc.audit_path.exists():
            shutil.copyfile(server_proc.audit_path, evidence_file)


def test_vuln_auth_timing_side_channel_user_enumeration(dreamteam11_env):
    """
    Vulnerability 11.1: Timing Side-Channel in Authentication User Verification.
    In server/auth.py::verify_password:
        record = users.get(username)
        if record is None:
            return False
        derived_hash = record.derive_hash(...)
    When a username does not exist, verify_password exits immediately (< 0.01 ms).
    When a username exists, verify_password invokes computationally heavy scrypt (N=16384, r=8, p=1),
    taking ~30ms-120ms.
    This creates a huge timing differential (>10,000x) that enables an unauthenticated attacker
    to enumerate valid usernames.
    """
    users = load_users(dreamteam11_env["data"] / "users.json")
    assert "alice" in users

    # 1. Measure non-existent user lookup time
    t0 = time.perf_counter()
    res_nonexistent = verify_password(users, "nonexistent_user_999", "wrong_password")
    t_nonexistent = time.perf_counter() - t0
    assert res_nonexistent is False

    # 2. Measure existing user lookup time (with incorrect password)
    t0 = time.perf_counter()
    res_existing = verify_password(users, "alice", "wrong_password")
    t_existing = time.perf_counter() - t0
    assert res_existing is False

    ratio = t_existing / max(t_nonexistent, 1e-9)
    print(f"\n[Side-Channel Benchmark] Non-existent: {t_nonexistent*1000:.4f} ms, Existing: {t_existing*1000:.4f} ms, Ratio: {ratio:.1f}x")

    # The existing user lookup must execute scrypt (at least 15ms), while non-existent exits in sub-millisecond.
    assert t_existing > 0.015, f"Expected scrypt execution to take > 15ms, took {t_existing*1000:.2f}ms"
    assert ratio > 50.0, f"Expected timing difference ratio > 50x, got {ratio:.1f}x"
