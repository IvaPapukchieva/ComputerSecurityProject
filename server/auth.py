import json
from collections.abc import Set
from typing import Dict
from typing import Optional
import base64
import hashlib
import secrets


# still working in this

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32

Permissions = Dict[str, Dict[str, Set[str]]]

# password hashing function 
def scrypt_hash(password: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R,
p: int = SCRYPT_P, dklen: int = DKLEN) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen)

def verify_user_password(username : str, password:str, users):
    user = next((u for u in users if u["username"] == username), None)
    if user is None: 
        return False
    else: 
        return verify_password(password, user["salt"], user["password_hash"], 
        user["n"], user["r"], user["p"], user['dklen'])


# verify the password 
def verify_password(input_pw: str, stored_salt_b64: str, stored_hash_b64: str,
n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P,
dklen: int = DKLEN) -> bool:
    """Return True iff input_pw matches stored hash.
    - stored_salt_b64 and stored_hash_b64 are base64-encoded strings.
    - Use constant-time comparison via secrets.compare_digest.
    """
    salt = base64.b64decode(stored_salt_b64)
    stored_hash = base64.b64decode(stored_hash_b64)
    user_input = scrypt_hash(input_pw, salt,n=n, r=r, p=p, dklen=dklen)

    return secrets.compare_digest(user_input, stored_hash)



def load_users(path: str =  "data/users.json"):
    users= json.load(open(path))
    
    return users

