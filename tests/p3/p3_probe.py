# generic functional + auth probe. run: python p3_probe.py <group>
# config per group lives in groups.json
import asyncio
import sys
import asyncssh
import p3_lib as lib


async def login(cfg, user, pw, kh):
    try:
        async with await asyncssh.connect(
            cfg["host"], port=cfg["port"], username=user, password=pw,
            known_hosts=kh, preferred_auth="password",
        ):
            return True
    except asyncssh.PermissionDenied:
        return False


async def do_op(sftp, kind, path):
    try:
        if kind == "list":
            await sftp.listdir(path)
        elif kind == "read":
            async with sftp.open(path, "r") as f:
                await f.read()
        elif kind == "write":
            async with sftp.open(path, "w") as f:
                await f.write("x")
        elif kind == "stat":
            await sftp.stat(path)
        elif kind == "mkdir":
            await sftp.mkdir(path)
        return "allow"
    except asyncssh.SFTPPermissionDenied:
        return "deny"
    except asyncssh.SFTPNoSuchFile:
        return "missing"   # authz let it through, the path just isn't on disk
    except Exception as e:
        return f"err:{type(e).__name__}"


async def main():
    group = sys.argv[1]
    cfg = lib.load(group)
    kh = lib.known_hosts(group, cfg)
    users = list(cfg["creds"])

    print("AuthN:")
    for u in users:
        ok = await login(cfg, u, cfg["creds"][u], kh)
        print(f"  {u:6} correct password -> {'OK' if ok else 'REJECTED'}")
    bad = await login(cfg, users[0], "wrong-password", kh)
    print(f"  {users[0]:6} wrong password -> {'OK(!)' if bad else 'rejected'}")

    print("\nAuthZ (expect = the group's own stated rule):")
    for p in cfg["authz_probes"]:
        async with await lib.connect(cfg, p["user"], kh) as c:
            s = await c.start_sftp_client()
            got = await do_op(s, p["op"], p["path"])
            s.exit()
        # a "missing" on an expected-allow means authz allowed but the folder is absent
        match = got == p["expect"] or (got == "missing" and p["expect"] == "allow")
        print(f"  {p['user']:6} {p['op']:5} {p['path']:35} -> {got:8} "
              f"(expect {p['expect']}) {'ok' if match else 'CHECK'}")

    lo = cfg.get("lockout")
    if lo:
        print("\nLockout:")
        v = lo["victim"]
        for i in range(lo["wrong_attempts"]):
            await login(cfg, v, f"wrong-{i}", kh)
        print(f"  flooded {lo['wrong_attempts']} wrong passwords for {v}")
        ok = await login(cfg, v, cfg["creds"][v], kh)
        print(f"  {v} correct password now -> "
              f"{'OK (no lockout)' if ok else 'REJECTED (lockout blocks the real user)'}")


asyncio.run(main())
