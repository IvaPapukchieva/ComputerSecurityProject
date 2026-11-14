#!/usr/bin/env python3
"""
Usage: python client/client.py --host 127.0.0.1 --port 2222 --username bob
Gen AI was used for help with the implementation, starting from asyncssh doc and paramiko implementation on github.
"""
import argparse
import asyncio
import getpass
import os
import posixpath
import shlex
import stat
import struct
import sys
import time
import asyncssh

#SFTP constants
FXP_INIT, FXP_VERSION = 1, 2
FXP_OPEN, FXP_CLOSE, FXP_READ, FXP_WRITE = 3, 4, 5, 6
FXP_LSTAT, FXP_FSTAT = 7, 8
FXP_OPENDIR, FXP_READDIR = 11, 12
FXP_MKDIR = 14
FXP_REALPATH, FXP_STAT = 16, 17
FXP_STATUS, FXP_HANDLE, FXP_DATA, FXP_NAME, FXP_ATTRS = 101, 102, 103, 104, 105

FX_OK, FX_EOF, FX_NO_SUCH_FILE, FX_PERMISSION_DENIED, FX_FAILURE = 0, 1, 2, 3, 4
FX_BAD_MESSAGE, FX_NO_CONNECTION, FX_CONNECTION_LOST, FX_OP_UNSUPPORTED = 5, 6, 7, 8
STATUS_NAMES = {
    FX_OK: "ok", FX_EOF: "end of file", FX_NO_SUCH_FILE: "no such file",
    FX_PERMISSION_DENIED: "permission denied", FX_FAILURE: "failure",
    FX_BAD_MESSAGE: "bad message", FX_NO_CONNECTION: "no connection",
    FX_CONNECTION_LOST: "connection lost", FX_OP_UNSUPPORTED: "operation unsupported",
}

ATTR_SIZE, ATTR_UIDGID, ATTR_PERMISSIONS, ATTR_ACMODTIME = 0x1, 0x2, 0x4, 0x8
ATTR_EXTENDED = 0x80000000

PF_READ, PF_WRITE, PF_APPEND, PF_CREAT, PF_TRUNC, PF_EXCL = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20

SFTP_VERSION = 3
CHUNK = 32 * 1024  # bytes per READ/WRITE request
MAX_PACKET = 256 * 1024 # memory guard


class SFTPError(Exception):
    """The server answered with a non-OK STATUS."""
    def __init__(self, code, message=""):
        self.code, self.message = code, message
        name = STATUS_NAMES.get(code, f"status {code}")
        super().__init__(f"{name} ({message})" if message and message.lower() != name else name)


class SFTPProtocolError(Exception):
    """The server sent something that violates the protocol."""

# Wire encoding
def p_u32(n): return struct.pack(">I", n & 0xFFFFFFFF)
def p_u64(n): return struct.pack(">Q", n & 0xFFFFFFFFFFFFFFFF)
def p_str(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return p_u32(len(b)) + b


class Reader:
    def __init__(self, data):
        self.data, self.off = data, 0

    def _take(self, n):
        if self.off + n > len(self.data):
            raise SFTPProtocolError("truncated packet")
        b = self.data[self.off:self.off + n]
        self.off += n
        return b

    def remaining(self): return len(self.data) - self.off
    def u32(self): return struct.unpack(">I", self._take(4))[0]
    def u64(self): return struct.unpack(">Q", self._take(8))[0]
    def string(self): return self._take(self.u32())

    def attrs(self):
        flags = self.u32()
        a = {}
        if flags & ATTR_SIZE:
            a["size"] = self.u64()
        if flags & ATTR_UIDGID:
            a["uid"], a["gid"] = self.u32(), self.u32()
        if flags & ATTR_PERMISSIONS:
            a["permissions"] = self.u32()
        if flags & ATTR_ACMODTIME:
            a["atime"], a["mtime"] = self.u32(), self.u32()
        if flags & ATTR_EXTENDED:
            ext = {}
            for _ in range(self.u32()):
                k = self.string().decode("utf-8", "replace")
                ext[k] = self.string()
            a["extended"] = ext
        return a


# SFTP v3 protocol client
class SFTPClient:
    def __init__(self, reader, writer):
        self._r, self._w = reader, writer
        self._next_id = 1
        self._lock = asyncio.Lock()
        self.version = None

    def _send(self, ptype, payload):
        body = bytes([ptype]) + payload
        self._w.write(p_u32(len(body)) + body)

    async def _recv(self):
        try:
            n = struct.unpack(">I", await self._r.readexactly(4))[0]
            if n == 0 or n > MAX_PACKET:
                raise SFTPProtocolError(f"bad packet length {n}")
            body = await self._r.readexactly(n)
        except asyncio.IncompleteReadError:
            raise SFTPProtocolError("server closed the SFTP channel") from None
        return body[0], Reader(body[1:])

    async def init(self):
        self._send(FXP_INIT, p_u32(SFTP_VERSION))
        ptype, r = await self._recv()
        if ptype != FXP_VERSION:
            raise SFTPProtocolError(f"expected VERSION, got type {ptype}")
        self.version = r.u32()
        if self.version != SFTP_VERSION:
            raise SFTPProtocolError(f"server speaks SFTP v{self.version}, need v3")

    async def _call(self, ptype, payload, expect):
        async with self._lock:
            req_id = self._next_id
            self._next_id = (self._next_id + 1) & 0xFFFFFFFF or 1
            self._send(ptype, p_u32(req_id) + payload)
            rtype, r = await self._recv()

        rid = r.u32()
        if rid != req_id:
            raise SFTPProtocolError(f"reply id {rid} does not match request id {req_id}")
        if rtype == FXP_STATUS:
            code = r.u32()
            msg = r.string().decode("utf-8", "replace") if r.remaining() >= 4 else ""
            if code == FX_OK and expect == FXP_STATUS:
                return r
            raise SFTPError(code, msg)
        if rtype != expect:
            raise SFTPProtocolError(f"expected reply type {expect}, got {rtype}")
        return r

    async def realpath(self, path):
        r = await self._call(FXP_REALPATH, p_str(path), FXP_NAME)
        if r.u32() < 1:
            raise SFTPProtocolError("REALPATH returned no names")
        return r.string().decode("utf-8", "replace")

    async def stat(self, path):
        return (await self._call(FXP_STAT, p_str(path), FXP_ATTRS)).attrs()

    async def lstat(self, path):
        return (await self._call(FXP_LSTAT, p_str(path), FXP_ATTRS)).attrs()

    async def fstat(self, handle):
        return (await self._call(FXP_FSTAT, p_str(handle), FXP_ATTRS)).attrs()

    async def opendir(self, path):
        return (await self._call(FXP_OPENDIR, p_str(path), FXP_HANDLE)).string()

    async def readdir(self, handle):
        """Return a list of (name, longname, attrs), or None at end of directory."""
        try:
            r = await self._call(FXP_READDIR, p_str(handle), FXP_NAME)
        except SFTPError as e:
            if e.code == FX_EOF:
                return None
            raise
        out = []
        for _ in range(r.u32()):
            name = r.string().decode("utf-8", "replace")
            longname = r.string().decode("utf-8", "replace")
            out.append((name, longname, r.attrs()))
        return out

    async def close(self, handle):
        await self._call(FXP_CLOSE, p_str(handle), FXP_STATUS)

    async def mkdir(self, path):
        await self._call(FXP_MKDIR, p_str(path) + p_u32(0), FXP_STATUS)  # empty attrs

    async def open(self, path, pflags):
        return (await self._call(FXP_OPEN, p_str(path) + p_u32(pflags) + p_u32(0),
                                 FXP_HANDLE)).string()

    async def read(self, handle, offset, length):
        """Return bytes, or None at end of file."""
        try:
            r = await self._call(FXP_READ, p_str(handle) + p_u64(offset) + p_u32(length),
                                 FXP_DATA)
        except SFTPError as e:
            if e.code == FX_EOF:
                return None
            raise
        return r.string()

    async def write(self, handle, offset, data):
        await self._call(FXP_WRITE, p_str(handle) + p_u64(offset) + p_str(data), FXP_STATUS)

    #helpers
    async def listdir(self, path):
        handle = await self.opendir(path)
        entries = []
        try:
            while (batch := await self.readdir(handle)) is not None:
                entries.extend(batch)
        finally:
            await self._close_quietly(handle)
        return entries

    async def download(self, rpath, lpath):
        handle = await self.open(rpath, PF_READ)
        tmp = lpath + ".part"
        offset = 0
        try:
            with open(tmp, "wb") as f:
                while (data := await self.read(handle, offset, CHUNK)) is not None:
                    f.write(data)
                    offset += len(data)
            os.replace(tmp, lpath)
        except BaseException:
            try: os.remove(tmp)
            except OSError: pass
            raise
        finally:
            await self._close_quietly(handle)
        return offset

    async def upload(self, lpath, rpath):
        with open(lpath, "rb") as f: # open locally first: fail before touching the server
            handle = await self.open(rpath, PF_WRITE | PF_CREAT | PF_TRUNC)
            offset = 0
            try:
                while chunk := f.read(CHUNK):
                    await self.write(handle, offset, chunk)
                    offset += len(chunk)
            finally:
                await self._close_quietly(handle)
        return offset

    async def _close_quietly(self, handle):
        try:
            await self.close(handle)
        except (SFTPError, SFTPProtocolError):
            pass


#host key verification
def known_hosts_pattern(host, port):
    return host if port == 22 else f"[{host}]:{port}"


def host_is_known(path, host, port):
    pattern = known_hosts_pattern(host, port)
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and pattern in line.split()[0].split(","):
                    return True
    except FileNotFoundError:
        pass
    return False


async def ensure_host_key(host, port, known_hosts):
    """If the host is unknown, show its fingerprint and ask the user to trust it.

    For known hosts we do nothing here: asyncssh.connect(known_hosts=...) then
    rejects the connection if the server's key does not match the stored one.
    """
    if host_is_known(known_hosts, host, port):
        return
    key = await asyncssh.get_server_host_key(host, port)
    if key is None:
        raise SystemExit("error: server did not present a host key")
    pattern = known_hosts_pattern(host, port)
    print(f"The authenticity of host '{pattern}' can't be established.")
    print(f"{key.get_algorithm()} key fingerprint is {key.get_fingerprint('sha256')}.")
    answer = input("Are you sure you want to continue connecting (yes/no)? ").strip().lower()
    if answer != "yes":
        raise SystemExit("Host key verification failed.")
    algo, blob = key.export_public_key("openssh").decode().split()[:2]
    os.makedirs(os.path.dirname(os.path.abspath(known_hosts)), exist_ok=True)
    with open(known_hosts, "a", encoding="utf-8") as f:
        f.write(f"{pattern} {algo} {blob}\n")
    print(f"Warning: Permanently added '{pattern}' ({algo}) to {known_hosts}.")


#interactive shell
def format_attrs(path, a):
    lines = [f"  File: {path}"]
    perms = a.get("permissions")
    if perms is not None:
        kind = ("directory" if stat.S_ISDIR(perms) else
                "regular file" if stat.S_ISREG(perms) else
                "symlink" if stat.S_ISLNK(perms) else "other")
        lines.append(f"  Type: {kind}")
        lines.append(f"  Mode: {stat.filemode(perms)} ({perms & 0o7777:04o})")
    if "size" in a:
        lines.append(f"  Size: {a['size']}")
    if "uid" in a:
        lines.append(f"   Uid: {a['uid']}  Gid: {a['gid']}")
    if "mtime" in a:
        fmt = "%Y-%m-%d %H:%M:%S"
        lines.append(f"Access: {time.strftime(fmt, time.localtime(a['atime']))}")
        lines.append(f"Modify: {time.strftime(fmt, time.localtime(a['mtime']))}")
    return "\n".join(lines)


def split_args(line):
    # posix=False keeps Windows backslashes intact; strip surrounding quotes ourselves.
    out = []
    for tok in shlex.split(line, posix=False):
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
            tok = tok[1:-1]
        out.append(tok)
    return out


HELP = """Commands:
  pwd                     print the remote working directory
  cd <path>               change the remote working directory
  ls [path]               list a remote directory
  mkdir <path>            create a remote directory
  stat <path>             show remote file attributes
  get <rpath> [lpath]     download a file
  put <lpath> [rpath]     upload a file
  help                    show this help
  quit | exit             leave"""


class Shell:
    def __init__(self, sftp):
        self.sftp = sftp
        self.cwd = "/"

    def remote(self, p):
        return p if p.startswith("/") else posixpath.join(self.cwd, p)

    async def run(self):
        self.cwd = await self.sftp.realpath(".")
        loop = asyncio.get_running_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, input, "sftp> ")
            except (EOFError, KeyboardInterrupt):
                print()
                return
            try:
                args = split_args(line)
            except ValueError as e:
                print(f"error: {e}")
                continue
            if not args:
                continue
            cmd, rest = args[0].lower(), args[1:]
            if cmd in ("quit", "exit", "bye"):
                return
            handler = getattr(self, f"do_{cmd}", None)
            if handler is None:
                print(f"unknown command: {cmd} (try 'help')")
                continue
            try:
                await handler(*rest)
            except TypeError:
                print(f"usage error for '{cmd}' (try 'help')")
            except SFTPError as e:
                print(f"remote: {e}")
            except OSError as e:
                print(f"local: {e.strerror or e}: {e.filename or ''}".rstrip(": "))

    async def do_help(self):
        print(HELP)

    async def do_pwd(self):
        print(f"Remote working directory: {self.cwd}")

    async def do_cd(self, path):
        target = await self.sftp.realpath(self.remote(path))
        a = await self.sftp.stat(target)
        if not stat.S_ISDIR(a.get("permissions", 0)):
            print(f"not a directory: {target}")
            return
        self.cwd = target

    async def do_ls(self, path=None):
        entries = await self.sftp.listdir(self.remote(path) if path else self.cwd)
        for name, longname, _ in sorted(entries, key=lambda e: e[0]):
            if name in (".", ".."):
                continue
            print(longname or name)

    async def do_mkdir(self, path):
        await self.sftp.mkdir(self.remote(path))

    async def do_stat(self, path):
        rpath = self.remote(path)
        print(format_attrs(rpath, await self.sftp.stat(rpath)))

    async def do_get(self, rpath, lpath=None):
        rfull = self.remote(rpath)
        if lpath is None:
            lpath = posixpath.basename(rfull.rstrip("/"))
            if lpath in ("", ".", ".."):
                print("give a local file name: get <rpath> <lpath>")
                return
        elif os.path.isdir(lpath):
            lpath = os.path.join(lpath, posixpath.basename(rfull.rstrip("/")))
        n = await self.sftp.download(rfull, lpath)
        print(f"Fetched {rfull} -> {lpath} ({n} bytes)")

    async def do_put(self, lpath, rpath=None):
        rfull = self.remote(rpath if rpath else os.path.basename(lpath))
        n = await self.sftp.upload(lpath, rfull)
        print(f"Uploaded {lpath} -> {rfull} ({n} bytes)")



async def connect(host, port, username, password, known_hosts):
    """Open an SSH connection and an SFTP subsystem channel; return (conn, SFTPClient)."""
    conn = await asyncssh.connect(
        host, port,
        username=username,
        password=password,
        known_hosts=known_hosts, # strict check against the stored key
        client_keys=None,  # password auth only
        agent_path=None,
        preferred_auth="password",
        x509_trusted_certs=None
    )
    try:
        writer, reader, _ = await conn.open_session(subsystem="sftp", encoding=None)
        sftp = SFTPClient(reader, writer)
        await sftp.init()
    except BaseException:
        conn.close()
        raise
    return conn, sftp


async def main():
    ap = argparse.ArgumentParser(description="Minimal SFTP v3 client")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--username", "-u", required=True)
    ap.add_argument("--known-hosts",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_hosts"),
                    help="OpenSSH-format known_hosts file (default: client/known_hosts)")
    args = ap.parse_args()

    try:
        await ensure_host_key(args.host, args.port, args.known_hosts)
        password = getpass.getpass(f"{args.username}@{args.host}'s password: ")
        conn, sftp = await connect(args.host, args.port, args.username, password,
                                   args.known_hosts)
    except asyncssh.HostKeyNotVerifiable:
        sys.exit("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\n"
                 f"The host key for {known_hosts_pattern(args.host, args.port)} does not match "
                 f"{args.known_hosts}. Refusing to connect.")
    except asyncssh.PermissionDenied:
        sys.exit("Permission denied (wrong username or password).")
    except (OSError, asyncssh.Error, SFTPProtocolError) as e:
        sys.exit(f"Connection failed: {e}")

    print(f"Connected to {args.host}:{args.port} (SFTP v{sftp.version}).")
    try:
        async with conn:
            await Shell(sftp).run()
    except (SFTPProtocolError, asyncssh.Error) as e:
        sys.exit(f"Connection lost: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
