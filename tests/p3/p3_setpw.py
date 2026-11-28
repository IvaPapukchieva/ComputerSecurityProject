# Some groups ship only random/discarded password hashes, so to run the
# functional and authz tests set one known demo password for every user, then
# restore the original file afterwards.
#   set:     python p3_setpw.py <users.json>
#   restore: python p3_setpw.py <users.json> --restore
import base64, hashlib, json, os, shutil, sys

PATH = sys.argv[1]
BAK = PATH + ".p3bak"
DEMO = "p3testpw" # same demo password for every user


def set_passwords():
    if not os.path.exists(BAK):
        shutil.copyfile(PATH, BAK)
    users = json.loads(open(PATH, encoding="utf-8").read())
    for u in users:
        salt = os.urandom(16)
        digest = hashlib.scrypt(DEMO.encode(), salt=salt,
                                n=u["n"], r=u["r"], p=u["p"], dklen=u["dklen"])
        u["salt"] = base64.b64encode(salt).decode()
        u["password_hash"] = base64.b64encode(digest).decode()
    open(PATH, "w", encoding="utf-8").write(json.dumps(users, indent=2) + "\n")
    print(f"set demo password '{DEMO}' for: {', '.join(u['username'] for u in users)}")
    print(f"original backed up at {BAK}")


def restore():
    if not os.path.exists(BAK):
        sys.exit("no backup found, nothing to restore")
    shutil.copyfile(BAK, PATH)
    os.remove(BAK)
    print("original users.json restored")


restore() if "--restore" in sys.argv else set_passwords()
