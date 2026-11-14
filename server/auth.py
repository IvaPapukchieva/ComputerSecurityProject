"""
User authentication and password verification module using scrypt.
Gen AI was used to help with scrypt hashing configuration and the account lockout logic.
"""
import base64
import hashlib
import json
import secrets
import time
from collections import defaultdict
from typing import List

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32

MAX_ATTEMPTS = 10
LOCKOUT_DURATION_SECS = 10 * 60  # 10 minutes


class LockoutManager:
    """Tracks failed login attempts and manages temporary account lockouts."""
    def __init__(self, max_attempts: int = MAX_ATTEMPTS, lockout_duration: int = LOCKOUT_DURATION_SECS):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self._failures = defaultdict(int)
        self._locked_until = {}

    def is_locked(self, username: str) -> bool:
        """Check if a user is currently locked out."""
        lock_until = self._locked_until.get(username, 0)
        if time.time() < lock_until:
            return True
        if lock_until:
            # Lockout period has elapsed; clear the lock and reset attempts
            del self._locked_until[username]
            self._failures[username] = 0
        return False

    def failure_case(self, username: str):
        """Record a failed login attempt and apply lockout if threshold exceeded."""
        self._failures[username] += 1
        if self._failures[username] >= self.max_attempts:
            self._locked_until[username] = time.time() + self.lockout_duration

    def success_case(self, username: str):
        """Reset failed attempt counters upon successful authentication."""
        self._failures.pop(username, None)
        self._locked_until.pop(username, None)


LOCKOUT = LockoutManager()


def scrypt_hash(password: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R,
                p: int = SCRYPT_P, dklen: int = DKLEN) -> bytes:
    """Password hashing function using scrypt."""
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)


def verify_password(input_pw: str, stored_salt_b64: str, stored_hash_b64: str,
                    n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P,
                    dklen: int = DKLEN) -> bool:
    """Return True iff input_pw matches stored hash.
    - stored_salt_b64 and stored_hash_b64 are base64-encoded strings.
    - Use constant-time comparison via secrets.compare_digest.
    """
    salt = base64.b64decode(stored_salt_b64)
    stored_hash = base64.b64decode(stored_hash_b64)
    user_input = scrypt_hash(input_pw, salt, n=n, r=r, p=p, dklen=dklen)
    return secrets.compare_digest(user_input, stored_hash)


def verify_user_password(username: str, password: str, users: List[dict]) -> bool:
    """Authenticate user with constant-time comparison and lockout protection."""
    user = next((u for u in users if u["username"] == username), None)
    user_exists = user is not None

    # Create dummy user if we actually didn't find one (timing attack defense)
    eval_user = user if user_exists else (
        users[0] if users else {
            "salt": "ZHVtbXlzYWx0MTIzNDU2", "password_hash": "ZHVtbXloYXNoMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM=",
            "n": 16384, "r": 8, "p": 1, "dklen": 32
        }
    )

    # If the user is currently locked out, perform dummy hash to maintain constant time and return False
    if LOCKOUT.is_locked(username):
        _ = verify_password(
            password, eval_user["salt"], eval_user["password_hash"],
            eval_user["n"], eval_user["r"], eval_user["p"], eval_user["dklen"]
        )
        return False

    # We always perform password check in order to have consistent time
    password_matches = verify_password(
        password, eval_user["salt"], eval_user["password_hash"],
        eval_user["n"], eval_user["r"], eval_user["p"], eval_user["dklen"]
    )

    # Check validity and update lockout state accordingly
    if user_exists and password_matches:
        LOCKOUT.success_case(username)
        return True
    else:
        LOCKOUT.failure_case(username)
        return False


def load_users(path: str = "data/users.json") -> List[dict]:
    """Load and validate users database file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            users = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Missing required user configuration file: {path}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in {path}: {exc}")

    required_fields = {"username", "salt", "password_hash", "n", "r", "p", "dklen"}
    if not isinstance(users, list) or not users:
        raise ValueError(f"{path} must contain a non-empty list of user objects")
    for u in users:
        if not isinstance(u, dict) or not required_fields.issubset(u.keys()):
            raise ValueError(f"{path} contains invalid user object: missing required fields {required_fields}")
    return users
