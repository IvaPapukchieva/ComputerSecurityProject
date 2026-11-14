# SFTP over SSH: Access Control (DAC, MAC, RBAC) and Secure File Operations

**Group:** Group 06  
**Course:** Computer Security — Group Project  
**Date:** November 2026  

---

## Overview

This project implements an SFTP v3 client and server using `asyncssh` for the SSH transport. Instead of relying on the host OS user accounts and permissions, the server implements its own application-level access control:
- **Discretionary Access Control (DAC):** Standard Unix permissions (owner, group, other) and checking the directory search bit (`+x`) on all parent directories leading to a file.
- **Mandatory Access Control (MAC):** Clearance levels and resource labels enforcing **No Read Up** and **No Write Down** (`public` < `internal` < `confidential`).
- **Role-Based Access Control (RBAC):** Role permissions with multi-role support and explicit deny overrides.
- **Combined Policy Gate:** Access is allowed only when all three models agree ($\text{DAC} \wedge \text{MAC} \wedge \text{RBAC}$), with default-deny if any check fails or if an operation is unrecognized.
- **Audit Logging:** Every authorization decision (allowed or denied) is logged to `server/audit.jsonl`.
- **Password Authentication:** Salted `scrypt` hashing with constant-time verification, dummy hashing against timing attacks, and automatic account lockout after 10 failed attempts.
- **Jail Normalization:** Strict path normalization to POSIX format, keeping all operations inside `server/sftp_root` and blocking path traversal attempts.
- **Safety Limits:** Packet size limit (256 KB) and per-session handle limits (up to 100 open handles) to prevent memory issues or opening too many files.

---

## Installation & Prerequisites

This project requires **Python 3.10+**. Dependencies are listed in `requirements.txt`:
- `asyncssh` (SSH transport, key exchange, and channels)
- `cryptography` (cryptographic primitives)
- `pytest` (automated testing framework)

To set up the virtual environment and install dependencies:

```bash
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate the virtual environment
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

# 3. Install required packages
pip install -r requirements.txt
```

---

## Server

The server entrypoint is `server/server.py`. It listens on port `2222` and handles SFTP v3 binary packets.

### 1. Host Key Generation (One-Time Setup)
Before starting the server for the first time, generate an unencrypted Ed25519 host key:

```bash
ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key
```

### 2. Starting the Server
Run:

```bash
python server/server.py
```

*Notes:*
- The server will automatically create `server/sftp_root` as the jail directory if it does not already exist.
- On startup, the server loads and validates all static dataset files from `data/` (`users.json`, `user_roles.json`, `role_perms.csv`, `mac_labels.json`, `dac_owners.csv`, `user_groups.json`). Malformed or missing files cause a clean startup failure with a readable error message.

---

## Client

`client/client.py` is an SFTP v3 client. `asyncssh` provides the SSH connection; the client handles all SFTP packets itself.

### Running the Client

With the server running in another terminal:

```bash
python client/client.py --host 127.0.0.1 --port 2222 --username bob
```

The password is asked for interactively and is never echoed or stored in logs.

### Host Key Verification (TOFU)

On the first connection, the client displays the server's host key fingerprint and prompts you to trust it (Trust-On-First-Use). You can verify it against `ssh-keygen -lf server/ssh_host_ed25519_key`, then type `yes`. The key is saved to `client/known_hosts`. If the server's key ever changes, the client refuses connection. Alternatively, you can provide an existing known_hosts file with `--known-hosts`.

### Available Commands

| Command | Description |
|---|---|
| `pwd` | Print remote working directory |
| `cd <path>` | Change remote directory |
| `ls [path]` | List a directory (`OPENDIR` / `READDIR`) |
| `mkdir <path>` | Create a directory (`MKDIR`) |
| `stat <path>` | Show remote file attributes (`STAT` / `LSTAT`) |
| `get <rpath> [lpath]` | Download a file (`OPEN` read + `READ` + `CLOSE`) |
| `put <lpath> [rpath]` | Upload a file (`OPEN` write + `WRITE` + `CLOSE`) |
| `help` | Show command help |
| `quit` / `exit` | Disconnect cleanly |

Server errors are shown cleanly (e.g. `remote: permission denied`) and the interactive session continues.

### Client Example Session

```text
sftp> ls
-rw-rw-rw-   0 0        0               0 Nov 11 12:09 Test.txt
drwxrwxrwx   0 0        0               0 Nov 11 12:09 admin
drwxrwxrwx   0 0        0               0 Nov 11 12:09 projects
sftp> put README.md /projects/README.md
Uploaded README.md -> /projects/README.md (17553 bytes)
sftp> ls /admin
remote: permission denied
```

### Interoperability with Standard OpenSSH Client

The server is fully interoperable with standard command-line tools like OpenSSH `sftp`:

```bash
sftp -P 2222 bob@127.0.0.1
sftp> ls
sftp> stat /projects
```

### Known Limitations
- No `rm` / recursive directory transfers.
- One request at a time (sequential execution, no pipelining).
- `get` overwrites an existing local destination file without prompting.
- Packet size is capped at 256 KB to prevent excessive memory usage.

---

## Access Control Design

The access control architecture checks multiple security layers together so that no single check can fail and expose files.

### 1. Operations Covered & Mapping
SFTP requests are mapped to authorization operations:
* `SSH_FXP_REALPATH` $\rightarrow$ `realpath`
* `SSH_FXP_STAT`, `SSH_FXP_LSTAT`, `SSH_FXP_FSTAT` $\rightarrow$ `stat`
* `SSH_FXP_OPENDIR` $\rightarrow$ `list`
* `SSH_FXP_MKDIR` $\rightarrow$ `mkdir`
* `SSH_FXP_OPEN` (with read flags) $\rightarrow$ `read`
* `SSH_FXP_OPEN` (with write/creat/trunc/append flags) $\rightarrow$ `write`
* `SSH_FXP_REMOVE` $\rightarrow$ `remove`

Any unrecognized operation triggers an immediate **default-deny**.

### 2. Enforcement Point
Authorization is checked strictly **after** jail canonicalization (`safe_join`) and **before** any OS filesystem call. This guarantees that:
1. All path traversal tricks (`../`, `\`, null bytes, colons) are caught and rejected first.
2. The authorization engine always operates on canonical, absolute POSIX paths rooted at the jail (`/`).
3. If authorization fails, the underlying file or directory is never touched.

### 3. Discretionary Access Control (DAC)
DAC follows standard Unix file permissions:
* Each path is associated with an `owner`, a `group`, and octal `mode` bits ($r=4, w=2, x=1$).
* If the user is the owner, owner bits apply; if in the same group, group bits apply; otherwise, "other" bits apply.
* **Directory Search Bit (`+x`):** To access any file or subfolder, the user **must** have the execute/search bit (`x`) on every single parent directory leading to it. If any ancestor directory lacks `+x`, traversal is denied.
* **Creation and Deletion:** Creating (`mkdir`, file creation) or removing an entry requires write ($w$) and search ($x$) permissions on the **parent directory**.

### 4. Mandatory Access Control (MAC)
MAC enforces user clearance levels and resource labels:
$$\text{public (0)} < \text{internal (1)} < \text{confidential (2)}$$

Every user has a clearance level, and resources have classification labels:
* **No Read Up:** A user cannot read, list, or stat any resource with a classification label higher than their clearance:
  $$\text{clearance}(u) \ge \text{label}(o)$$
* **No Write Down:** A user with high clearance cannot write, create, or delete resources labeled below their clearance, preventing sensitive or confidential data from leaking into lower-clearance files:
  $$\text{clearance}(u) \le \text{label}(o)$$

### 5. Role-Based Access Control (RBAC)
* Permissions are assigned to roles over path prefixes in `data/role_perms.csv`.
* **Union of Roles:** Users can have multiple roles (defined in `data/user_roles.json`). A user gets the combined permissions of all their assigned roles.
* **Conflict Resolution (Deny Overrides):** If any role specifies `deny`, it overrides any `allow`.

### 6. Combining the Models (DAC ∧ MAC ∧ RBAC)
The server evaluates all three models for every request:
$$\text{Final Decision} = \text{DAC} \wedge \text{MAC} \wedge \text{RBAC}$$

All three security models must agree and return `True`. If even one model says `False`, access is **denied** (default deny). An attacker who manages to satisfy one layer (e.g. finding a world-writable file) is still stopped by the remaining layers.

#### Example Outcomes Matrix (2x2)

| Scenario | DAC | MAC | RBAC | Final Outcome | Explanation |
|---|:---:|:---:|:---:|:---:|---|
| **Eve reading `/projects/internal/public_dac.txt`** | ALLOW (mode 666) | DENY (clearance 0 < label 1) | ALLOW (visitor role) | **DENY** | Blocked by MAC "No Read Up". |
| **Alice creating folder `/projects/new_dir`** | ALLOW (owner mode) | ALLOW (clearance 1) | DENY (analyst lacks mkdir) | **DENY** | Blocked by RBAC: role lacks mkdir grant. |
| **Bob writing to `/admin/flag.txt`** | DENY (mode 600 admin) | DENY (clearance 1 < label 2) | DENY (no admin role) | **DENY** | All three models deny access. |
| **Admin reading `/admin/flag.txt`** | ALLOW (owner mode 600) | ALLOW (clearance 2) | ALLOW (admin role) | **ALLOW** | All three models agree and allow access. |

### 7. Auditing
Every authorization check is recorded to `server/audit.jsonl` with structured fields:
`{"user": "...", "op": "...", "path": "...", "allowed": bool, "reason": "...", "timestamp": "..."}`

Example audit records:
```json
{"user":"bob","op":"read","path":"/admin/flag.txt","allowed":false,"reason":"DAC: other mode denies read (requires 4, has 0); MAC: no read up (clearance below resource label); RBAC: no role grants this operation on this path","timestamp":"2026-11-14T16:30:45.781965+00:00"}
{"user":"admin","op":"read","path":"/admin/flag.txt","allowed":true,"reason":"DAC: owner mode on /admin/flag.txt allows read; MAC: clearance permits operation; RBAC: granted by role(s) base, admin","timestamp":"2026-11-14T16:32:16.565472+00:00"}
```

---

## Predefined Users Directory

Plaintext passwords are never stored in the project files. Passwords are saved as salted `scrypt` hashes in `data/users.json`.

| Username | Assigned Roles | MAC Clearance | DAC Group | Description of Powers & Limits |
|---|---|---|---|---|
| **`admin`** | `admin`, `base` | `confidential` (2) | `admins` | Server administrator. Has full access across `/` and `/admin`, can create directories and manage files. Under MAC rules, cannot write down into public files. |
| **`alice`** | `analyst`, `base` | `internal` (1) | `students` | Project owner and data analyst. Can read and write under `/projects`, but cannot access confidential resources under `/admin`. |
| **`bob`** | `analyst`, `base` | `internal` (1) | `students` | Colleague analyst in `students` group. Can access group-readable files in `/projects`, but cannot access Alice's private files or `/admin`. |
| **`eve`** | `visitor`, `base` | `public` (0) | `guests` | Guest user. Restricted strictly to reading public files under `/projects/public`. Cannot write anywhere or view internal/confidential documents. |

---

## Automated Tests

Testing is implemented using `pytest`. The test suite contains **59 automated tests** in `tests/test_sftp.py`.

### Running the Tests

Ensure the virtual environment is active and `requirements.txt` is installed:

```bash
pytest
```

### Summary of Automated Tests
1. **DAC Tests (`TestDACPolicy`):** Owner read/write, group read access, other write/read denials, directory execute/search bit (+x) traversal, parent write verification on mkdir, and parent write verification on new file creation.
2. **MAC Tests (`TestMACPolicy`):** "No Read Up", "No Write Down", equal/lower classification reading, and unlabeled path defaults.
3. **RBAC Tests (`TestRBACPolicy`):** Role scoping, administrator prefix grants, multi-role union inheritance, and explicit deny overrides.
4. **Combined Policy Tests (`TestCompositeGate`):** Verification that access is granted if and only if all three models agree ($DAC \wedge MAC \wedge RBAC$), with default-deny on unrecognized ops, non-canonical paths, and unknown users.
5. **Audit Logging Tests (`TestAuditLogging`):** Validation of JSONL record fields, ISO 8601 UTC timestamps, and failure reason logging.
6. **Authentication & Lockout Tests (`TestAuthentication`):** Salted scrypt hashing, valid/invalid password verification, dummy user timing defense, 10-attempt lockout trigger, lockout reset on success, and configuration schema validation.
7. **Path and Jail Tests (`TestJailAndPaths`):** Relative path normalization, root clamping (`/../../../`), Windows backslash and colon (`:`) sanitization, null-byte rejection, and traversal escape audit logging.
8. **Handle Management Tests (`TestHandleManagement`):** Handle registration, invalid handle detection, `max_handles` limit, oversized packet rejection, and disconnect cleanup (`close_all()`).
9. **Configuration Loading Tests (`TestProductionData`):** Verifies that real configuration files in `data/` load cleanly on server startup.
10. **Protocol Tests (`TestSFTPWireProtocol`):** Validates SFTP packet handling: INIT/VERSION handshake, request ID matching, file open/write/read/close sequence, READDIR EOF, and status codes.

---

## Academic Integrity & Generative AI Disclosure

As required by the course guidelines, here is where Generative AI was consulted during our development:
- **Where AI assistance was consulted:** We consulted AI to look up SFTP v3 wire format specifications and binary `struct` pack/unpack formats from the IETF draft, suggest pytest edge cases, and help format tables.
- **What our team designed and implemented:** All core security architecture and design choices were made and implemented by our team: designing the combined policy logic ($\text{DAC} \wedge \text{MAC} \wedge \text{RBAC}$), MAC clearance levels, the directory execute bit (`+x`) traversal check, integrating salted `scrypt` auth and lockout management, designing and hiding the CTF flag, conducting manual penetration tests in the terminal, fixing handle leaks and path traversal traps, and writing all project documentation.
