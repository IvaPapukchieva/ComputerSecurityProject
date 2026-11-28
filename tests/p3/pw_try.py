# try a small list of candidate passwords against a users.json (local scrypt only)
import base64, hashlib, json, sys

users = json.loads(open(sys.argv[1], encoding="utf-8").read())
candidates = [
    "test", "test-password", "password", "Password1", "changeme",
    "bob", "alice", "eve", "admin", "123456", "sftp",
    "bob123", "alice123", "eve123", "admin123",
    "Bob2026!", "group6", "group5", "secret",
    "bob-TA-2026!", "alice-Prof-2026!", "eve-Student-2026!",
]

for u in users:
    name = u["username"]
    salt = base64.b64decode(u["salt"])
    want = base64.b64decode(u["password_hash"])
    found = None
    for c in candidates:
        h = hashlib.scrypt(c.encode(), salt=salt, n=u["n"], r=u["r"], p=u["p"], dklen=u["dklen"])
        if h == want:
            found = c
            break
    print(f"{name:8} -> {found!r}" if found else f"{name:8} -> (none of the candidates matched)")
