import base64, hashlib, json, sys
users = json.loads(open(sys.argv[1], encoding="utf-8").read())
cands = ["password","password1","password123","Password1","Passw0rd","passw0rd",
 "12345678","123456789","qwerty123","iloveyou","letmein1","changeme","trustno1",
 "alice123","bob12345","carol123","eve12345","alicealice","bobbobbob",
 "sftp2026","sftpsftp","group07","group007","group07!","groupseven",
 "confidential","internal1","analyst1","admin123","adminadmin","guest123",
 "flagflag","ctfctf","Welcome1","welcome1","secret12","p@ssw0rd","abcd1234",
 "11111111","00000000","password!","Spring2026","Autumn2026","sunshine1"]
for u in users:
    salt=base64.b64decode(u["salt"]); want=base64.b64decode(u["password_hash"]); f=None
    for c in cands:
        if hashlib.scrypt(c.encode(),salt=salt,n=u["n"],r=u["r"],p=u["p"],dklen=u["dklen"])==want:
            f=c; break
    print(f"{u['username']:8} -> {f!r}" if f else f"{u['username']:8} -> (no match)")
