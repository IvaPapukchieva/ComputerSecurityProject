# --- Password auth implemented on the server class (no keyword args needed) ---
def validate_user_password(username, password):
    # TODO: replace with Argon2 verify, lockout, rate-limits, audit, salted, peppered, perhaps, mfa?
    return username == "bob" and password == "test"