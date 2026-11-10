# server/auth.py — TEMPORARY
TEST_USERS = {"alice": "test", "bob": "test", "eve": "test", "admin": "admin"}   # use the usernames from your policy data

def load_users(path): pass

def validate_user_password(username, password):
    return TEST_USERS.get(username) == password