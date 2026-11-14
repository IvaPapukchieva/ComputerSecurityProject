"""Automated tests for SFTP server: DAC, MAC, RBAC, auth, path jail, and wire protocol.
Gen AI was used to help set up pytest fixtures.
"""

import base64
import json
import os
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

# Configure paths so server modules can be imported
root_dir = Path(__file__).resolve().parent.parent
server_dir = root_dir / "server"
if str(server_dir) not in sys.path:
    sys.path.insert(0, str(server_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from server import auth
from server import policy
import server



# Isolate tests from live environment


@pytest.fixture
def mock_audit_log(tmp_path):
    """Provides a temporary file for the audit log to isolate test runs."""
    audit_file = tmp_path / "audit.jsonl"
    with patch("policy.AUDIT_PATH", audit_file):
        yield audit_file


@pytest.fixture
def mock_policy_engine(mock_audit_log):
    """Mocks the _POLICY object in policy.py to provide a stable, controlled dataset for tests."""
    mock_policy_obj = policy.Policy(
        user_roles={
            "alice": ("analyst", "base"),
            "bob": ("analyst", "base"),
            "eve": ("visitor", "base"),
            "admin": ("admin", "base"),
            "multirole_user": ("analyst", "visitor", "base"),
            "norole_user": ()
        },
        user_clearances={
            "alice": 1, # internal
            "bob": 1, # internal
            "eve": 0, # public
            "admin": 2, # confidential
            "multirole_user": 1,
            "norole_user": 0
        },
        user_groups={
            "alice": ("students",),
            "bob": ("students",),
            "eve": ("guests",),
            "admin": ("admins",),
            "multirole_user": ("students",),
            "norole_user": ("guests",)
        },
        labels=(
            ("/admin", 2), # confidential
            ("/projects/internal", 1), # internal
            ("/projects/public", 0), # public
            ("/projects", 1), # internal
            ("/", 0) # public
        ),
        owners=(
            policy.OwnerRule("/admin/flag.txt", "admin", "admins", 0o600, "file"),
            policy.OwnerRule("/admin", "admin", "admins", 0o700, "directory"),
            policy.OwnerRule("/projects/public/readme.txt", "alice", "students", 0o644, "file"),
            policy.OwnerRule("/projects/public", "alice", "students", 0o755, "directory"),
            policy.OwnerRule("/projects/internal/notes.txt", "alice", "students", 0o640, "file"),
            policy.OwnerRule("/projects/internal/public_dac.txt", "alice", "students", 0o666, "file"),  # MAC trap
            policy.OwnerRule("/projects/internal", "alice", "students", 0o750, "directory"),
            policy.OwnerRule("/projects/no_search", "admin", "admins", 0o600, "directory"),  # Missing group/other search (+x)
            policy.OwnerRule("/projects", "alice", "students", 0o775, "directory"),
            policy.OwnerRule("/", "admin", "admins", 0o755, "directory"),
        ),
        role_perms={
            "admin": ({"prefix": "/", "allow": {"read", "write", "mkdir", "list", "stat", "realpath", "remove", "create"}, "deny": set()},),
            "analyst": (
                {"prefix": "/projects", "allow": {"read", "write", "list", "stat", "realpath"}, "deny": set()},
                {"prefix": "/projects/internal/notes.txt", "allow": set(), "deny": {"write"}},  # Explicit deny override
            ),
            "visitor": ({"prefix": "/projects/public", "allow": {"read", "list", "stat", "realpath"}, "deny": set()},),
            "base": ({"prefix": "/", "allow": {"list", "stat", "realpath"}, "deny": set()},)
        }
    )
    with patch("policy._POLICY", mock_policy_obj):
        yield mock_policy_obj



# DAC tests

class TestDACPolicy:

    def test_dac_owner_read_write(self, mock_policy_engine):
        """Test that the file owner can read and write their own file."""
        allowed_read, reason_read = policy.authorize("alice", "read", "/projects/internal/notes.txt")
        assert allowed_read, f"Expected Alice (owner) to read her file. Reason: {reason_read}"
        assert "DAC: owner mode" in reason_read

        allowed_write, reason_write = policy.authorize("alice", "write", "/projects/internal/public_dac.txt")
        assert allowed_write, f"Expected Alice (owner) to write to her file. Reason: {reason_write}"
        assert "DAC: owner mode" in reason_write

    def test_dac_other_write_denied(self, mock_policy_engine):
        """Test that other users cannot write"""
        allowed, reason = policy.authorize("eve", "write", "/projects/public/readme.txt")
        assert not allowed
        assert "DAC: other mode denies write" in reason

    def test_dac_group_read_allowed(self, mock_policy_engine):
        """Test that same-group member can read when group read is set."""
        allowed, reason = policy.authorize("bob", "read", "/projects/internal/notes.txt")
        assert allowed, f"Expected Bob to read file in same group. Reason: {reason}"
        assert "DAC: group mode" in reason

    def test_dac_other_read_denied(self, mock_policy_engine):
        """Test that other user cannot read a group-restricted file."""
        allowed, reason = policy.authorize("eve", "read", "/projects/internal/notes.txt")
        assert not allowed
        assert "DAC: other mode denies read" in reason

    def test_dac_dir_execute_bit(self, mock_policy_engine):
        """Test that missing the directory execute bit blocks ls/stat operations."""
        allowed, reason = policy.authorize("eve", "list", "/projects/no_search")
        assert not allowed
        assert "DAC: other mode denies list" in reason

    def test_dac_parent_dir_execute_bit_traversal(self, mock_policy_engine):
        """Test that directory search bit (+x) on parent is required to access child resources."""
        allowed, reason = policy.authorize("bob", "stat", "/projects/no_search/notes.txt")
        assert not allowed
        assert "directory search bit denies traversal" in reason or "denies stat" in reason

    def test_dac_create_file_requires_parent_write(self, mock_policy_engine):
        """Test that creating a new file requires write+search permissions on the parent directory."""
        allowed, reason = policy.authorize("eve", "create", "/projects/public/new_doc.txt")
        assert not allowed
        assert "DAC: other mode denies create" in reason

    def test_dac_mkdir_requires_parent_write(self, mock_policy_engine):
        """Test that creating a directory requires write+search permissions on the parent."""
        allowed, reason = policy.authorize("eve", "mkdir", "/new_folder")
        assert not allowed
        assert "DAC: other mode denies mkdir" in reason


# MAC tests

class TestMACPolicy:
    def test_mac_no_read_up(self, mock_policy_engine):
        """Test that an internal user cannot read a confidential file."""
        # Alice attempts to read /admin/flag.txt
        allowed, reason = policy.authorize("alice", "read", "/admin/flag.txt")
        assert not allowed
        assert "MAC: no read up" in reason

    def test_mac_no_write_down(self, mock_policy_engine):
        """Test that a confidential user cannot write to a public file."""
        allowed, reason = policy.authorize("admin", "write", "/projects/public/readme.txt")
        assert not allowed
        assert "MAC: no write down" in reason

    def test_mac_read_equal_or_down(self, mock_policy_engine):
        """Test that an internal user can read internal and public files."""
        # Internal
        allowed_internal, _ = policy.authorize("alice", "read", "/projects/internal/notes.txt")
        assert allowed_internal
        # Public
        allowed_public, _ = policy.authorize("alice", "read", "/projects/public/readme.txt")
        assert allowed_public

    def test_mac_unlabeled_resource_defaults_to_public(self, mock_policy_engine):
        """Test that unlabeled paths default to public clearance."""
        # Eve should be able to pass MAC for an unlabeled root path
        allowed, reason = policy.authorize("eve", "stat", "/")
        assert "MAC: clearance permits operation" in reason

# RBAC tests

class TestRBACPolicy:

    def test_rbac_analyst_limits(self, mock_policy_engine):
        """Test that an analyst can access /projects but is denied operations under /admin."""
        # Allowed
        allowed_read, _ = policy.authorize("alice", "read", "/projects/public/readme.txt")
        assert allowed_read

        # Admin privellege, not allowed
        allowed_mkdir, reason_mkdir = policy.authorize("alice", "mkdir", "/admin/new_folder")
        assert not allowed_mkdir
        assert "RBAC: no role grants this operation" in reason_mkdir

    def test_rbac_admin_enables_action(self, mock_policy_engine):
        """Test that the admin role enables operations across the server."""
        allowed, reason = policy.authorize("admin", "mkdir", "/admin/new_folder")
        assert allowed, f"Expected admin role to allow mkdir. Reason: {reason}"

    def test_rbac_multi_role_union(self, mock_policy_engine):
        """Test that a user with multiple roles inherits permissions of all assigned roles."""
        allowed, reason = policy.authorize("multirole_user", "read", "/projects/public/readme.txt")
        assert allowed
        assert "RBAC: granted by role(s)" in reason

    def test_rbac_deny_overrides(self, mock_policy_engine):
        """Test that an explicit deny rule overrides role grants."""
        allowed, reason = policy.authorize("alice", "write", "/projects/internal/notes.txt")
        assert not allowed
        assert "RBAC: explicit deny overrides role grants" in reason

    def test_rbac_user_without_roles_denied(self, mock_policy_engine):
        """Test that a user with no assigned roles is denied access by default."""
        allowed, reason = policy.authorize("norole_user", "read", "/projects/public/readme.txt")
        assert not allowed
        assert "RBAC: no role grants this operation" in reason


# Gates check and default denial

class TestCompositeGate:

    def test_composite_dac_allows_mac_denies(self, mock_policy_engine):
        """Test that if DAC allows but MAC denies, the final decision is a denial."""
        # Eve has DAC permission, but MAC must deny.
        allowed, reason = policy.authorize("eve", "read", "/projects/internal/public_dac.txt")
        assert not allowed
        assert "MAC: no read up" in reason

    def test_composite_mac_allows_rbac_denies(self, mock_policy_engine):
        """Test that if MAC allows but RBAC denies, the final decision is a denial."""
        # DAC allows, MAC allows, but analyst role lacks 'mkdir'.
        allowed, reason = policy.authorize("alice", "mkdir", "/projects/new_subfolder")
        assert not allowed
        assert "RBAC: no role grants this operation" in reason

    def test_composite_rbac_allows_dac_denies(self, mock_policy_engine):
        """Test that if RBAC allows but DAC denies, the final decision is a denial."""
        allowed, reason = policy.authorize("eve", "write", "/projects/public/readme.txt")
        assert not allowed
        assert "DAC: other mode denies write" in reason

    def test_composite_all_pass(self, mock_policy_engine):
        """Test that access is granted only when all three security models agree."""
        allowed, reason = policy.authorize("alice", "read", "/projects/public/readme.txt")
        assert allowed
        assert "DAC:" in reason and "MAC:" in reason and "RBAC:" in reason

    def test_composite_path_traversal_default_deny(self, mock_policy_engine):
        """Test that non-canonical path traversal attempts trigger immediate default-deny."""
        allowed, reason = policy.authorize("eve", "read", "../../admin/flag.txt")
        assert not allowed
        assert "path is not canonical" in reason

    def test_composite_unsupported_operation_default_deny(self, mock_policy_engine):
        """Test that unrecognized operations trigger immediate default-deny."""
        allowed, reason = policy.authorize("admin", "drop_table", "/admin")
        assert not allowed
        assert "unsupported operation" in reason

    def test_composite_unknown_user_default_deny(self, mock_policy_engine):
        """Test that unauthenticated or unknown users trigger immediate default-deny."""
        allowed, reason = policy.authorize("intruder", "read", "/projects/public/readme.txt")
        assert not allowed
        assert "unknown user" in reason


# Check proper writing of logs

class TestAuditLogging:
    def test_audit_record_written_on_allow(self, mock_policy_engine, mock_audit_log):
        """Test that an allow decision writes a structured audit log entry."""
        policy.authorize("alice", "read", "/projects/public/readme.txt")

        with open(mock_audit_log, "r", encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) == 1, "Exactly one audit record should be recorded."
        record = json.loads(lines[0])

        assert record["user"] == "alice"
        assert record["op"] == "read"
        assert record["path"] == "/projects/public/readme.txt"
        assert record["allowed"] is True
        assert "timestamp" in record

    def test_audit_record_written_on_deny(self, mock_policy_engine, mock_audit_log):
        """Test that a denied decision writes a structured audit log entry with failure reason."""
        policy.authorize("eve", "write", "/projects/public/readme.txt")

        with open(mock_audit_log, "r", encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) == 1
        record = json.loads(lines[0])

        assert record["user"] == "eve"
        assert record["op"] == "write"
        assert record["allowed"] is False
        assert "DAC: other mode denies write" in record["reason"]

    def test_audit_record_json_schema(self, mock_policy_engine, mock_audit_log):
        """Test that audit records contain all required schema fields."""
        policy.authorize("admin", "stat", "/admin")

        with open(mock_audit_log, "r", encoding="utf-8") as f:
            record = json.loads(f.readline())

        required_keys = {"user", "op", "path", "allowed", "reason", "timestamp"}
        assert required_keys.issubset(record.keys())


# Authentication tests

class TestAuthentication:
    """Password hashing, timing defense, and account lockout rate-limiting."""

    def test_scrypt_hashing_consistency(self):
        """Test that scrypt produces consistent hashes for the same input."""
        salt = b"test_salt_16byte"
        h1 = auth.scrypt_hash("Password123!", salt, n=16384, r=8, p=1, dklen=32)
        h2 = auth.scrypt_hash("Password123!", salt, n=16384, r=8, p=1, dklen=32)
        assert h1 == h2
        assert len(h1) == 32

    def test_verify_password_valid(self):
        """Test successful password verification against base64 salt and hash."""
        salt = os.urandom(16)
        pw = "Password123!"
        hashed = auth.scrypt_hash(pw, salt)

        salt_b64 = base64.b64encode(salt).decode()
        hash_b64 = base64.b64encode(hashed).decode()

        assert auth.verify_password(pw, salt_b64, hash_b64)

    def test_verify_password_invalid(self):
        """Test rejection of incorrect password."""
        salt = os.urandom(16)
        hashed = auth.scrypt_hash("Password123!", salt)

        salt_b64 = base64.b64encode(salt).decode()
        hash_b64 = base64.b64encode(hashed).decode()

        assert not auth.verify_password("Password123", salt_b64, hash_b64)

    def test_timing_dummy_user_fallback(self):
        """Test that non-existent users use dummy hashing to prevent timing leaks."""
        dummy_users = [
            {"username": "realuser", "salt": base64.b64encode(os.urandom(16)).decode(),
             "password_hash": base64.b64encode(os.urandom(32)).decode(),
             "n": 16384, "r": 8, "p": 1, "dklen": 32}
        ]
        result = auth.verify_user_password("not_user", "any_password", dummy_users)
        assert result is False

    def test_lockout_10_attempts_trigger(self):
        """Test that 10 consecutive failed logins lock the account for 10 minutes."""
        lockout_mgr = auth.LockoutManager(max_attempts=10, lockout_duration=600)
        user = "test"

        # first 9 attempts should not be locked
        for _ in range(9):
            lockout_mgr.failure_case(user)
            assert not lockout_mgr.is_locked(user)

        # at 10th attempt must be locked
        lockout_mgr.failure_case(user)
        assert lockout_mgr.is_locked(user)

    def test_lockout_reset_on_success(self):
        """Test that a successful authentication resets the failure count."""
        lockout_mgr = auth.LockoutManager(max_attempts=10, lockout_duration=600)
        user = "test_user"

        # Accumulate 6 failures
        for _ in range(6):
            lockout_mgr.failure_case(user)
        assert not lockout_mgr.is_locked(user)

        # Successful login resets the counter
        lockout_mgr.success_case(user)
        assert lockout_mgr._failures[user] == 0

    def test_load_users_missing_file(self, tmp_path):
        """Test that load_users raises FileNotFoundError on missing file."""
        nonexistent = tmp_path / "missing_users.json"
        with pytest.raises(FileNotFoundError):
            auth.load_users(str(nonexistent))

    def test_load_users_malformed_json(self, tmp_path):
        """Test that load_users raises ValueError on malformed JSON syntax."""
        bad_json = tmp_path / "bad_users.json"
        bad_json.write_text("{ unclosed json: ", encoding="utf-8")
        with pytest.raises(ValueError, match="Malformed JSON"):
            auth.load_users(str(bad_json))

    def test_load_users_missing_keys(self, tmp_path):
        """Test that load_users raises ValueError if required user fields are missing."""
        invalid_schema = tmp_path / "invalid_schema.json"
        invalid_schema.write_text('[{"username": "alice"}]', encoding="utf-8")
        with pytest.raises(ValueError, match="missing required fields"):
            auth.load_users(str(invalid_schema))


# Check that no outside access

class TestJailAndPaths:
    def test_canon_sftp_path_basic(self):
        """Test normalization of relative POSIX path components."""
        canon = server.canon_sftp_path(b"/projects/../demo")
        assert canon == "/demo"

    def test_canon_sftp_path_clamp_root(self):
        """Test that leading /../../ stays clamped inside the jail root."""
        canon = server.canon_sftp_path(b"/../../../../")
        assert canon == "/"

    def test_canon_sftp_path_backslash_conversion(self):
        """Test that Windows backslashes are converted to forward slashes."""
        canon = server.canon_sftp_path(b"\\projects\\notes.txt")
        assert canon == "/projects/notes.txt"

    def test_canon_sftp_path_null_byte_rejected(self):
        """Test that null bytes in paths raise PermissionError."""
        with pytest.raises(PermissionError, match="bad path"):
            server.canon_sftp_path(b"/projects/file\x00.txt")

    def test_canon_sftp_path_colon_rejected(self):
        """Test that colons (Windows drive letters & ADS) raise PermissionError."""
        with pytest.raises(PermissionError, match="bad path"):
            server.canon_sftp_path(b"C:/windows/system32")

        with pytest.raises(PermissionError, match="bad path"):
            server.canon_sftp_path(b"/projects/flag.txt::$DATA")

    def test_safe_join_within_jail(self, tmp_path):
        """Test safe path resolution within the jail directory."""
        jail = tmp_path / "jail"
        jail.mkdir()
        sub = jail / "projects"
        sub.mkdir()

        resolved = server.safe_join(str(jail), b"/projects")
        assert resolved == os.path.realpath(str(sub))

    def test_safe_join_escape_rejected(self, tmp_path):
        """Test that path escapes outside the jail raise PermissionError."""
        jail = tmp_path / "jail"
        jail.mkdir()

        # Windows drive letters or colons are forbidden escape patterns
        with pytest.raises(PermissionError):
            server.safe_join(str(jail), b"C:/windows/system32")

    def test_resolve_audit_logging_on_jail_escape(self, tmp_path, mock_audit_log):
        """Test that jail escape attempts are caught and logged into audit.jsonl."""
        session = server.SFTPSession(username="attacker")
        with patch.object(server, "JAIL_ROOT", str(tmp_path)):
            with pytest.raises(PermissionError):
                session._resolve(b"C:/windows/system32", op="open")

        with open(mock_audit_log, "r", encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) >= 1
        record = json.loads(lines[-1])
        assert record["user"] == "attacker"
        assert record["op"] == "open"
        assert record["allowed"] is False
        assert "Jail boundary violation" in record["reason"]


# Check integrity

class TestHandleManagement:
    def test_handles_add_and_retrieve(self):
        """Test adding and retrieving handles from the handle table."""
        table = server.Handles(max_handles=10)
        dummy_obj = MagicMock()
        handle_wire = table.add(dummy_obj)

        # Wire format is p_str(hid)
        ln, hid = struct.unpack(">I", handle_wire[:4])[0], handle_wire[4:]
        retrieved = table.get(hid)
        assert retrieved is dummy_obj

    def test_handles_close(self):
        """Test closing handles properly removes them and invokes close()."""
        table = server.Handles(max_handles=10)
        dummy_obj = MagicMock()
        handle_wire = table.add(dummy_obj)
        hid = handle_wire[4:]

        assert table.close(hid) is True
        dummy_obj.close.assert_called_once()
        assert table.get(hid) is None

    def test_handles_close_invalid(self):
        """Test that closing an invalid handle returns False."""
        table = server.Handles(max_handles=10)
        assert table.close(b"nonexistent_handle") is False

    def test_handles_capacity_limit_dos_protection(self):
        """Test that exceeding max_handles raises OSError when too many handles are open."""
        table = server.Handles(max_handles=3)
        table.add(MagicMock())
        table.add(MagicMock())
        table.add(MagicMock())

        with pytest.raises(OSError, match="Too many open handles"):
            table.add(MagicMock())

    def test_handles_close_all_on_disconnect(self):
        """Test that close_all() closes all active handles on session disconnect."""
        table = server.Handles(max_handles=10)
        h1, h2 = MagicMock(), MagicMock()
        table.add(h1)
        table.add(h2)

        table.close_all()
        h1.close.assert_called_once()
        h2.close.assert_called_once()
        assert len(table._map) == 0

    def test_oversized_packet_dos_rejected(self):
        """Test that packets larger than MAX_PACKET close the channel and clear the buffer."""
        session = server.SFTPSession(username="attacker")
        session._chan = MagicMock()
        oversized_len = server.MAX_PACKET + 1024
        packet_header = struct.pack(">I", oversized_len)
        session.data_received(packet_header, None)
        assert session.buf == b""
        session._chan.close.assert_called_once()

# Production Data Integrity

class TestProductionData:
    """Verifies that production configuration files in data/ load cleanly."""
    def test_production_policy_loads(self):
        """Check that real data/ policy configuration loads without error."""
        prod_policy = policy._load_policy(policy.DATA_DIR)
        assert prod_policy is not None
        assert "admin" in prod_policy.user_roles
        assert "alice" in prod_policy.user_roles
    def test_production_users_load(self):
        """Check that real data/users.json loads and contains required schema."""
        users = auth.load_users(os.path.join(policy.DATA_DIR, "users.json"))
        assert len(users) >= 4
        usernames = {u["username"] for u in users}
        assert {"admin", "alice", "bob", "eve"}.issubset(usernames)


# SFTP v3 Wire Protocol & Message Serialization Tests

class TestSFTPWireProtocol:
    """Tests for binary SFTP v3 packet parsing and responses."""

    @staticmethod
    def _unpack_wire_response(raw_bytes: bytes) -> tuple[int, bytes]:
        """Parses a wire packet emitted to session._chan.write().
        Returns (packet_type, payload).
        """
        assert len(raw_bytes) >= 5, "Response is shorter than minimum SFTP header length"
        pkt_len = struct.unpack(">I", raw_bytes[:4])[0]
        assert len(raw_bytes) == 4 + pkt_len, "Packet wire length mismatch"
        ptype = raw_bytes[4]
        payload = raw_bytes[5:]
        return ptype, payload

    def test_wire_init_version_handshake(self):
        """Test that SSH_FXP_INIT triggers an SSH_FXP_VERSION(3) response and initializes the session."""
        session = server.SFTPSession(username="alice")
        session._chan = MagicMock()

        init_pkt = server.pack_pkt(server.SSH_FXP_INIT, server.p_u32(3))
        session.data_received(init_pkt, None)

        session._chan.write.assert_called_once()
        raw_resp = session._chan.write.call_args[0][0]
        ptype, payload = self._unpack_wire_response(raw_resp)

        assert ptype == server.SSH_FXP_VERSION, f"Expected SSH_FXP_VERSION(2), got {ptype}"
        version, = struct.unpack(">I", payload[:4])
        assert version == 3, f"Expected negotiated SFTP version 3, got {version}"
        assert session.initialized is True

    def test_wire_pre_init_packets_rejected(self):
        """Test that sending operational packets before INIT causes immediate channel termination."""
        session = server.SFTPSession(username="alice")
        session._chan = MagicMock()

        early_pkt = server.pack_pkt(server.SSH_FXP_REALPATH, server.p_u32(1) + server.p_str(b"/"))
        session.data_received(early_pkt, None)

        session._chan.close.assert_called_once()
        assert session.initialized is False

    def test_wire_realpath_request_id_matching(self, mock_policy_engine, tmp_path):
        """Test that REALPATH echoes the client's request ID and returns canonical name."""
        session = server.SFTPSession(username="admin")
        session._chan = MagicMock()

        session.data_received(server.pack_pkt(server.SSH_FXP_INIT, server.p_u32(3)), None)

        req_id = 0xABCD1234
        with patch.object(server, "JAIL_ROOT", str(tmp_path)):
            session.data_received(server.pack_pkt(server.SSH_FXP_REALPATH, server.p_u32(req_id) + server.p_str(b"/")), None)

        raw_resp = session._chan.write.call_args[0][0]
        ptype, payload = self._unpack_wire_response(raw_resp)

        assert ptype == server.SSH_FXP_NAME, f"Expected SSH_FXP_NAME(104), got {ptype}"
        echoed_id, count = struct.unpack(">II", payload[:8])
        assert echoed_id == req_id, f"Request ID mismatch: sent {req_id}, got {echoed_id}"
        assert count == 1
        name, _ = server.ustr(payload, 8)
        assert name == b"/"

    def test_wire_open_write_read_close_lifecycle(self, mock_policy_engine, tmp_path):
        """Test opening, writing, reading, and closing a file over SFTP."""
        jail = tmp_path / "jail"
        jail.mkdir()
        admin_dir = jail / "admin"
        admin_dir.mkdir()
        session = server.SFTPSession(username="admin")
        session._chan = MagicMock()

        with patch.object(server, "JAIL_ROOT", str(jail)):
            session.data_received(server.pack_pkt(server.SSH_FXP_INIT, server.p_u32(3)), None)

            # OPEN file for read/write under /admin (confidential clearance match)
            open_pkt = server.pack_pkt(
                server.SSH_FXP_OPEN,
                server.p_u32(101) + server.p_str(b"/admin/wire_test.txt") +
                server.p_u32(server.PF_READ | server.PF_WRITE | server.PF_CREAT | server.PF_TRUNC) + server.p_u32(0)
            )
            session.data_received(open_pkt, None)
            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_HANDLE
            handle_str, _ = server.ustr(payload, 4)

            # WRITE binary data
            test_payload = b"SFTP v3 Wire Test Data 12345"
            write_pkt = server.pack_pkt(
                server.SSH_FXP_WRITE,
                server.p_u32(102) + server.p_str(handle_str) + server.p_u64(0) + server.p_str(test_payload)
            )
            session.data_received(write_pkt, None)
            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_STATUS
            _, code = struct.unpack(">II", payload[:8])
            assert code == server.SSH_FX_OK

            # READ data back
            read_pkt = server.pack_pkt(
                server.SSH_FXP_READ,
                server.p_u32(103) + server.p_str(handle_str) + server.p_u64(0) + server.p_u32(64)
            )
            session.data_received(read_pkt, None)
            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_DATA
            read_data, _ = server.ustr(payload, 4)
            assert read_data == test_payload

            # CLOSE handle
            close_pkt = server.pack_pkt(server.SSH_FXP_CLOSE, server.p_u32(104) + server.p_str(handle_str))
            session.data_received(close_pkt, None)
            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_STATUS
            _, code = struct.unpack(">II", payload[:8])
            assert code == server.SSH_FX_OK

    def test_wire_readdir_eof_signaling(self, mock_policy_engine, tmp_path):
        """Test that repeated READDIR calls properly return entries and terminate with SSH_FX_EOF."""
        proj_dir = tmp_path / "projects"
        proj_dir.mkdir()
        (proj_dir / "sample.txt").write_text("content", encoding="utf-8")

        session = server.SFTPSession(username="admin")
        session._chan = MagicMock()

        with patch.object(server, "JAIL_ROOT", str(tmp_path)):
            session.data_received(server.pack_pkt(server.SSH_FXP_INIT, server.p_u32(3)), None)

            # OPENDIR
            opendir_pkt = server.pack_pkt(server.SSH_FXP_OPENDIR, server.p_u32(201) + server.p_str(b"/projects"))
            session.data_received(opendir_pkt, None)
            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_HANDLE
            dh, _ = server.ustr(payload, 4)

            # First READDIR -> returns entries
            session.data_received(server.pack_pkt(server.SSH_FXP_READDIR, server.p_u32(202) + server.p_str(dh)), None)
            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_NAME

            # Second READDIR -> must return EOF status (code 1)
            session.data_received(server.pack_pkt(server.SSH_FXP_READDIR, server.p_u32(203) + server.p_str(dh)), None)
            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_STATUS
            _, code = struct.unpack(">II", payload[:8])
            assert code == server.SSH_FX_EOF, f"Expected EOF status code 1, got {code}"

    def test_wire_authorization_denial_status_code(self, mock_policy_engine, tmp_path):
        """Test that an unauthorized request returns wire STATUS with SSH_FX_PERMISSION_DENIED (3)."""
        session = server.SFTPSession(username="eve")
        session._chan = MagicMock()

        with patch.object(server, "JAIL_ROOT", str(tmp_path)):
            session.data_received(server.pack_pkt(server.SSH_FXP_INIT, server.p_u32(3)), None)

            # Eve attempts to open /admin/flag.txt
            unauth_pkt = server.pack_pkt(
                server.SSH_FXP_OPEN,
                server.p_u32(301) + server.p_str(b"/admin/flag.txt") +
                server.p_u32(server.PF_READ) + server.p_u32(0)
            )
            session.data_received(unauth_pkt, None)

            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_STATUS
            req_id, code = struct.unpack(">II", payload[:8])
            assert req_id == 301
            assert code == server.SSH_FX_PERMISSION_DENIED

    def test_wire_stat_no_such_file_status_code(self, mock_policy_engine, tmp_path):
        """Test that stat on a non-existent file returns wire STATUS with SSH_FX_NO_SUCH_FILE (2)."""
        session = server.SFTPSession(username="admin")
        session._chan = MagicMock()

        with patch.object(server, "JAIL_ROOT", str(tmp_path)):
            session.data_received(server.pack_pkt(server.SSH_FXP_INIT, server.p_u32(3)), None)

            stat_pkt = server.pack_pkt(server.SSH_FXP_STAT, server.p_u32(401) + server.p_str(b"/no_such_file.txt"))
            session.data_received(stat_pkt, None)

            ptype, payload = self._unpack_wire_response(session._chan.write.call_args[0][0])
            assert ptype == server.SSH_FXP_STATUS
            req_id, code = struct.unpack(">II", payload[:8])
            assert req_id == 401
            assert code == server.SSH_FX_NO_SUCH_FILE