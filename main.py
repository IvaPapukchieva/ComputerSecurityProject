#!/usr/bin/env python3
import asyncio, asyncssh, os, struct, stat
import logging, traceback

# Console debug logging for AsyncSSH
logging.basicConfig(
    level=logging.DEBUG,  # or INFO
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logging.getLogger("asyncssh").setLevel(logging.DEBUG)
# Optional: quiet down noisy asyncio internals
logging.getLogger("asyncio").setLevel(logging.INFO)


HOST_KEY_PATH = './ssh_host_ed25519_key'
LISTEN_HOST, LISTEN_PORT = '', 2222
SFTP_SUBSYSTEM_NAME = 'sftp'
JAIL_ROOT = os.path.abspath('./sftp_root')

# --- SFTP constants (subset for INIT/REALPATH/OPENDIR/READDIR/CLOSE) ---
SSH_FXP_INIT, SSH_FXP_VERSION = 1, 2
SSH_FXP_OPENDIR, SSH_FXP_READDIR = 11, 12
SSH_FXP_REALPATH = 16
SSH_FXP_STATUS, SSH_FXP_HANDLE, SSH_FXP_NAME = 101, 102, 104
SSH_FX_OK, SSH_FX_EOF, SSH_FX_NO_SUCH_FILE, SSH_FX_PERMISSION_DENIED, SSH_FX_FAILURE = 0, 1, 2, 3, 4
ATTR_SIZE, ATTR_PERMISSIONS, ATTR_ACMODTIME = 0x1, 0x4, 0x8

SSH_FXP_OPEN, SSH_FXP_CLOSE = 3, 4
SSH_FXP_WRITE               = 6
SSH_FXP_MKDIR               = 14
SSH_FXP_DATA = 103
SSH_FXP_READ = 5

# pflags
PF_READ, PF_WRITE, PF_APPEND, PF_CREAT, PF_TRUNC, PF_EXCL = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20

SSH_FXP_LSTAT   = 7
SSH_FXP_FSTAT   = 8
SSH_FXP_STAT    = 17
SSH_FXP_ATTRS   = 105


def parse_attrs_ignore(buf, off):
    ATTR_SIZE, ATTR_UIDGID, ATTR_PERMISSIONS, ATTR_ACMODTIME, ATTR_EXTENDED = 0x1, 0x2, 0x4, 0x8, 0x80000000
    flags, off = u32(buf, off)
    if flags & ATTR_SIZE: off += 8
    if flags & ATTR_UIDGID: off += 8
    if flags & ATTR_PERMISSIONS: off += 4
    if flags & ATTR_ACMODTIME: off += 8
    if flags & ATTR_EXTENDED:
        n, off = u32(buf, off)
        for _ in range(n):
            _, off = ustr(buf, off)  # type
            _, off = ustr(buf, off)  # data
    return off


# Add this helper near your other helpers
def canon_sftp_path(path_bs: bytes) -> str:
    """Return a canonical SFTP path (POSIX-style) relative to jail root."""
    s = path_bs.decode(errors="strict").replace("\\", "/")
    if not s or s == ".":
        return "/"
    if s.startswith("/"):
        rel = os.path.normpath(s.lstrip("/"))
    else:
        rel = os.path.normpath(s)
    rel = rel.replace("\\", "/").strip("/")
    return "/" if rel in ("", ".") else "/" + rel



def p_u32(n): return struct.pack(">I", n & 0xffffffff)
def p_u64(n): return struct.pack(">Q", n & 0xffffffffffffffff)
def p_byte(b): return struct.pack("B", b)
def p_str(bs): return p_u32(len(bs)) + bs
def pack_pkt(ptype, payload): body = bytes([ptype]) + payload; return p_u32(len(body)) + body

def u32(b, off): return struct.unpack_from(">I", b, off)[0], off+4
def u64(b, off): return struct.unpack_from(">Q", b, off)[0], off+8
def ustr(b, off): ln, off = u32(b, off); return b[off:off+ln], off+ln

def sftp_attrs_from_stat(st):
    perms = stat.S_IFMT(st.st_mode) | (st.st_mode & 0o777)
    return p_u32(ATTR_SIZE | ATTR_PERMISSIONS | ATTR_ACMODTIME) + p_u64(st.st_size) + p_u32(perms) + p_u32(int(st.st_atime)) + p_u32(int(st.st_mtime))

class DirHandle:
    def __init__(self, entries): self.entries, self.idx = entries, 0

class Handles:
    def __init__(self): self._n, self._map = 1, {}
    def add(self, obj): hid = str(self._n).encode(); self._n += 1; self._map[hid] = obj; return p_str(hid)
    def get(self, h): return self._map.get(h)
    def close(self, h): self._map.pop(h, None)

def safe_join(jroot, path_bs):
    # Treat absolute path as relative to the jail root
    s = path_bs.decode(errors="strict").replace("\\", "/")
    rel = s.lstrip("/")
    rel = os.path.normpath(rel)
    if rel in ("", ".", os.curdir):
        full = os.path.realpath(jroot)
    else:
        full = os.path.realpath(os.path.join(jroot, rel))
    jail = os.path.realpath(jroot)
    if not (full == jail or full.startswith(jail + os.sep)):
        raise PermissionError("path escape")
    return full


class SFTPSession(asyncssh.SSHServerSession):
    def __init__(self):
        self.buf = b""
        self.handles = Handles()
        self.initialized = False
        self._sftp_ok = False

    # Ensure the channel uses *binary* I/O from the start
    def connection_made(self, chan):
        self._chan = chan
        # Disable any text encoding so data_received gets bytes
        try:
            self._chan.set_encoding(None)           # newer AsyncSSH
        except AttributeError:
            try:
                self._chan.set_write_encoding(None) # older AsyncSSH fallback
            except Exception:
                pass

    # Accept only the SFTP subsystem
    def subsystem_requested(self, name: str) -> bool:
        if name == SFTP_SUBSYSTEM_NAME:   # usually "sftp"
            self._sftp_ok = True
            return True
        return False

    # Explicitly reject shell/exec so we don't get a line editor wrapper
    def shell_requested(self) -> bool:
        return False

    def exec_requested(self, command: str) -> bool:
        return False

    def session_started(self):
        if not self._sftp_ok:
            self._chan.close()
            return

    def data_received(self, data, datatype):
        # After set_encoding(None), data should be bytes
        if isinstance(data, str):                     # safety net
            data = data.encode('utf-8', 'surrogatepass')

        self.buf += data
        while len(self.buf) >= 4:
            n, = struct.unpack(">I", self.buf[:4])
            if len(self.buf) < 4 + n:
                break
            pkt = self.buf[4:4+n]
            self.buf = self.buf[4+n:]
            self._handle(pkt)

    def _send_status(self, req_id, code, msg=b""):
        self._chan.write(pack_pkt(
            SSH_FXP_STATUS,
            p_u32(req_id) + p_u32(code) + p_str(msg) + p_str(b"")
        ))

    def _handle(self, pkt: bytes):
        ptype = pkt[0]
        payload = pkt[1:]

        # debug every packet type
        try:
            name = {
                1: "INIT", 2: "VERSION", 3: "OPEN", 4: "CLOSE", 5: "READ", 6: "WRITE", 7: "LSTAT",
                8: "FSTAT", 11: "OPENDIR", 12: "READDIR", 14: "MKDIR", 16: "REALPATH", 17: "STAT",
                101: "STATUS", 102: "HANDLE", 103: "DATA", 104: "NAME", 105: "ATTRS"
            }.get(ptype, f"PTYPE_{ptype}")
            print(f"[PKT] type={name} len={len(payload)}")
        except Exception:
            pass

        # Expect INIT first; reply VERSION=3
        if not self.initialized:
            if ptype != SSH_FXP_INIT:
                self._send_status(0, SSH_FX_FAILURE, b"expected INIT")
                self._chan.close()
                return
            self._chan.write(pack_pkt(SSH_FXP_VERSION, p_u32(3)))
            self.initialized = True
            return

        req_id, off = u32(payload, 0)
        try:
            if ptype == SSH_FXP_REALPATH:
                path, off = ustr(payload, off)
                canon = canon_sftp_path(path)  # "./telnet.txt" -> "/telnet.txt"
                try:
                    full = safe_join(JAIL_ROOT, path)
                    # Debug every REALPATH, not just "."
                    print(f"[REALPATH] request: {path!r} -> canon: {canon} -> full: {safe_join(JAIL_ROOT, path)}")

                    st = os.stat(full)
                    attrs = sftp_attrs_from_stat(st)
                except FileNotFoundError:
                    attrs = p_u32(0)  # return empty attrs when not found


                resp = (
                        p_u32(req_id) + p_u32(1) +
                        p_str(canon.encode()) +  # filename
                        p_str(canon.encode()) +  # longname
                        attrs
                )
                self._chan.write(pack_pkt(SSH_FXP_NAME, resp))

            elif ptype in (SSH_FXP_STAT, SSH_FXP_LSTAT):
                path, off = ustr(payload, off)
                full = safe_join(JAIL_ROOT, path)
                try:
                    st = os.lstat(full) if ptype == SSH_FXP_LSTAT else os.stat(full)
                except FileNotFoundError:
                    self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"no such file")
                    return
                # optional debug
                print(f"[{'LSTAT' if ptype == SSH_FXP_LSTAT else 'STAT'}] {path!r} -> {full}")
                self._chan.write(pack_pkt(SSH_FXP_ATTRS, p_u32(req_id) + sftp_attrs_from_stat(st)))

            elif ptype == SSH_FXP_OPENDIR:
                path, off = ustr(payload, off)
                full = safe_join(JAIL_ROOT, path)
                entries = list(os.scandir(full))
                handle = self.handles.add(DirHandle(entries))
                self._chan.write(pack_pkt(SSH_FXP_HANDLE, p_u32(req_id) + handle))

            elif ptype == SSH_FXP_READDIR:
                handle_bs, off = ustr(payload, off)
                dh = self.handles.get(handle_bs)
                if not isinstance(dh, DirHandle):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad dir handle")
                    return

                batch = dh.entries[dh.idx: dh.idx + 64]
                dh.idx += len(batch)
                if not batch:
                    self._send_status(req_id, SSH_FX_EOF, b"EOF")
                    return

                out = p_u32(req_id) + p_u32(len(batch))
                for e in batch:
                    name = e.name.encode()
                    try:
                        attrs = sftp_attrs_from_stat(e.stat(follow_symlinks=False))
                    except Exception:
                        attrs = p_u32(0)
                    out += p_str(name) + p_str(name) + attrs
                self._chan.write(pack_pkt(SSH_FXP_NAME, out))

            elif ptype == SSH_FXP_MKDIR:
                path, off = ustr(payload, off)
                off = parse_attrs_ignore(payload, off)  # ignore attrs (mode, etc.)
                try:
                    full = safe_join(JAIL_ROOT, path)  # map "/demo" -> <jail>\demo
                    # Debug (optional): print to console so you can see the resolved path
                    print(f"[MKDIR] request: {path!r} -> full: {full}")
                    os.makedirs(full, exist_ok=False)  # create exactly one dir
                except FileExistsError:
                    self._send_status(req_id, SSH_FX_FAILURE, b"already exists")
                except FileNotFoundError:
                    # parent doesn't exist (e.g., mkdir /a/b without /a)
                    self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"parent missing")
                except PermissionError:
                    self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"permission denied")
                except OSError as e:
                    # Map a few common errnos if you want, else generic failure
                    self._send_status(req_id, SSH_FX_FAILURE, str(e).encode())
                else:
                    self._send_status(req_id, SSH_FX_OK, b"OK")
            elif ptype == SSH_FXP_OPEN:
                print("[FXP_OPEN] request started")
                filename, off = ustr(payload, off)
                pflags, off = u32(payload, off)
                off = parse_attrs_ignore(payload, off)  # ignore attrs

                full = safe_join(JAIL_ROOT, filename)


                print(f"[FXP_OPEN] request: {filename!r} -> full: {full}")
                # Map SFTP pflags to Python open() modes
                # Default to read-only; adjust based on flags
                mode = "rb"
                if pflags & PF_WRITE and pflags & PF_READ:
                    mode = "r+b"
                elif pflags & PF_WRITE:
                    mode = "r+b"
                elif pflags & PF_READ:
                    mode = "rb"

                if pflags & PF_CREAT:
                    mode = "r+b" if os.path.exists(full) else "w+b"
                if pflags & PF_TRUNC:
                    mode = "w+b"
                if (pflags & PF_EXCL) and os.path.exists(full):
                    raise FileExistsError("exists")

                f = open(full, mode)
                if pflags & PF_APPEND:
                    f.seek(0, os.SEEK_END)

                handle = self.handles.add(f)  # we can store file objects in Handles, too
                self._chan.write(pack_pkt(SSH_FXP_HANDLE, p_u32(req_id) + handle))

            elif ptype == SSH_FXP_WRITE:
                handle_bs, off = ustr(payload, off)
                offset, off = u64(payload, off)
                data, off = ustr(payload, off)

                f = self.handles.get(handle_bs)
                if not f or not hasattr(f, "write"):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return

                f.seek(offset)
                f.write(data)
                f.flush()
                self._send_status(req_id, SSH_FX_OK, b"OK")

            elif ptype == SSH_FXP_READ:
                handle_bs, off = ustr(payload, off)
                offset, off = u64(payload, off)
                length, off = u32(payload, off)  # how many bytes client wants

                f = self.handles.get(handle_bs)
                if not f or not hasattr(f, "read"):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return

                f.seek(offset)
                data = f.read(length)
                if data is None or len(data) == 0:
                    self._send_status(req_id, SSH_FX_EOF, b"EOF")
                else:
                    # Send DATA packet
                    payload = p_u32(req_id) + p_str(data)
                    self._chan.write(pack_pkt(SSH_FXP_DATA, payload))
            elif ptype == SSH_FXP_CLOSE:
                handle_bs, off = ustr(payload, off)
                self.handles.close(handle_bs)
                self._send_status(req_id, SSH_FX_OK, b"OK")
            else:
                self._send_status(req_id, SSH_FX_FAILURE, b"unsupported")

        except FileNotFoundError:
            self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"no such file")
        except PermissionError:
            self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"permission denied")
        except Exception as e:
            self._send_status(req_id, SSH_FX_FAILURE, str(e).encode())


# --- Password auth implemented on the server class (no keyword args needed) ---
def validate_user_password(username, password):
    # TODO: replace with Argon2 verify, lockout, rate-limits, audit, salted, peppered, perhaps, mfa?
    return username == "bob" and password == "test"

class Server(asyncssh.SSHServer):
    # Tell AsyncSSH we will do user auth:
    def begin_auth(self, username):  # called when a new user starts auth
        return True  # start authentication

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return validate_user_password(username, password)

    def session_requested(self):
        return SFTPSession()

async def main():
    os.makedirs(JAIL_ROOT, exist_ok=True)
    print(f"Jail root: {JAIL_ROOT}")
    await asyncssh.listen(
        LISTEN_HOST, LISTEN_PORT,
        server_host_keys=[HOST_KEY_PATH],  # server identity key
        server_factory=Server              # our auth & session handler
    )
    print(f"SFTP listening on {LISTEN_HOST or '0.0.0.0'}:{LISTEN_PORT} (subsystem '{SFTP_SUBSYSTEM_NAME}')")
    await asyncio.Event().wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
