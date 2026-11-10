#!/usr/bin/env python3
import asyncio, asyncssh, os, struct, stat, sys, time, posixpath
import logging, traceback

# Logging must be set up BEFORE importing policy, so its "Loaded ..." lines are shown
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("asyncssh").setLevel(logging.INFO)

import auth
try:
    import policy      # policy.py loads and checks all its data files on import
except Exception as e:
    sys.exit(f"[STARTUP] could not load policy files: {e}")


BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # .../server
HOST_KEY_PATH = os.path.join(BASE_DIR, 'ssh_host_ed25519_key')
LISTEN_HOST, LISTEN_PORT = '', 2222
SFTP_SUBSYSTEM_NAME = 'sftp'
JAIL_ROOT = os.path.join(BASE_DIR, 'sftp_root')
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), 'data') # repo/data
MAX_READ = 64 * 1024

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
    s = path_bs.decode("utf-8", errors="strict").replace("\\", "/")
    if "\x00" in s:
        raise PermissionError("bad path")
    p = posixpath.normpath("/" + s) # leading '/' means '..' can't go above root
    return "/" + p.lstrip("/") # normpath may keep '//' at the start



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

class FileHandle:
    """An open file plus what it was authorized for."""
    def __init__(self, fd, vpath, can_read, can_write):
        self.fd, self.vpath = fd, vpath
        self.can_read, self.can_write = can_read, can_write
    def close(self):
        os.close(self.fd)

def ls_longname(name, st):
    """'ls -l' style line; OpenSSH shows this for 'ls -l'."""
    mtime = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
    return (f"{stat.filemode(st.st_mode)} {st.st_nlink:>3} {st.st_uid:<8} {st.st_gid:<8} "
            f"{st.st_size:>8} {mtime} {name}").encode()

class DirHandle:
    def __init__(self, entries): self.entries, self.idx = entries, 0

class Handles:
    def __init__(self): self._n, self._map = 1, {}
    def add(self, obj): 
        hid = str(self._n).encode()
        self._n += 1
        self._map[hid] = obj
        return p_str(hid)
    
    def get(self, h): 
        return self._map.get(h)
    
    def close(self, h): 
        obj = self._map.pop(h, None)
        if obj is None:
            return False # handle didn't exist
        if hasattr(obj, "close"):
            obj.close() # actually close the file
        return True
    
    def close_all(self):
        for obj in self._map.values():
            if hasattr(obj, "close"):
                try: obj.close()
                except Exception: pass
        self._map.clear()
        
def safe_join(jroot, path_bs):
    """Map an SFTP path to a real OS path inside the jail. Raises PermissionError on escape."""
    vpath = canon_sftp_path(path_bs)
    jail = os.path.realpath(jroot)
    parts = [p for p in vpath.split("/") if p]
    full = os.path.realpath(os.path.join(jail, *parts))   # resolves symlinks
    if not (full == jail or full.startswith(jail + os.sep)):
        raise PermissionError("path escape")
    return full

def to_vpath(jroot, full):
    """Turn a real OS path inside the jail back into an SFTP path like '/projects/a.txt'."""
    rel = os.path.relpath(full, os.path.realpath(jroot))
    return "/" if rel == "." else "/" + rel.replace(os.sep, "/")


class SFTPSession(asyncssh.SSHServerSession):
    def __init__(self, username):
        self.username = username
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
        
    def eof_received(self):
        """Client is done (sftp 'exit'/'quit'): close the session cleanly."""
        self._chan.exit(0)
        return False
    
    def connection_lost(self, exc):
        """Called by asyncssh when the client disconnects (normally or not)."""
        print(f"[SESSION] {self.username} disconnected, closing {len(self.handles._map)} handle(s)")
        self.handles.close_all()

    def _resolve(self, path_bs):
        """Jail check. Returns (sftp_path, os_path)."""
        full = safe_join(JAIL_ROOT, path_bs)
        return to_vpath(JAIL_ROOT, full), full

    def _authorize(self, op, vpath):
        """Raises PermissionError -> STATUS(PERMISSION_DENIED)."""
        allowed, reason = policy.authorize(self.username, op, vpath)
        if not allowed:
            raise PermissionError(reason)

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
        if not pkt:
            return
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

        if len(payload) < 4:
            self._send_status(0, SSH_FX_FAILURE, b"malformed packet")
            return
        req_id, off = u32(payload, 0)
        try:
            if ptype == SSH_FXP_REALPATH:
                path, off = ustr(payload, off)
                canon = canon_sftp_path(path)
                vpath, full = self._resolve(path)
                self._authorize("realpath", vpath)
                try:
                    attrs = sftp_attrs_from_stat(os.stat(full))
                except FileNotFoundError:
                    attrs = p_u32(0)
                resp = (p_u32(req_id) + p_u32(1) +
                        p_str(canon.encode()) + p_str(canon.encode()) + attrs)
                self._chan.write(pack_pkt(SSH_FXP_NAME, resp))

            elif ptype in (SSH_FXP_STAT, SSH_FXP_LSTAT):
                path, off = ustr(payload, off)
                vpath, full = self._resolve(path)
                self._authorize("stat", vpath)
                try:
                    st = os.lstat(full) if ptype == SSH_FXP_LSTAT else os.stat(full)
                except FileNotFoundError:
                    self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"no such file")
                    return
                # optional debug
                print(f"[{'LSTAT' if ptype == SSH_FXP_LSTAT else 'STAT'}] {path!r} -> {full}")
                self._chan.write(pack_pkt(SSH_FXP_ATTRS, p_u32(req_id) + sftp_attrs_from_stat(st)))

            elif ptype == SSH_FXP_FSTAT:
                h = self.handles.get(handle_bs)
                if not isinstance(h, FileHandle):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return
                st = os.fstat(h.fd)
                self._chan.write(pack_pkt(SSH_FXP_ATTRS, p_u32(req_id) + sftp_attrs_from_stat(st)))

            elif ptype == SSH_FXP_OPENDIR:
                path, off = ustr(payload, off)
                vpath, full = self._resolve(path)
                self._authorize("list", vpath)
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
                        st = e.stat(follow_symlinks=False)
                        attrs, longname = sftp_attrs_from_stat(st), ls_longname(e.name, st)
                    except OSError:
                        attrs, longname = p_u32(0), name
                    out += p_str(name) + p_str(longname) + attrs
                self._chan.write(pack_pkt(SSH_FXP_NAME, out))

            elif ptype == SSH_FXP_MKDIR:
                path, off = ustr(payload, off)
                off = parse_attrs_ignore(payload, off) # ignore attrs (mode, etc.)
                try:
                    vpath, full = self._resolve(path)
                    self._authorize("mkdir", vpath)
                    print(f"[MKDIR] {self.username}: {vpath}")
                    os.mkdir(full) # exactly one dir, no parents
                except FileExistsError:
                    self._send_status(req_id, SSH_FX_FAILURE, b"already exists")
                except FileNotFoundError:
                    # parent doesn't exist (e.g., mkdir /a/b without /a)
                    self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"parent missing")
                except PermissionError:
                    self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"permission denied")
                except OSError as e:
                    # Map a few common errnos if you want, else generic failure
                    self._send_status(req_id, SSH_FX_FAILURE, b"failure")
                else:
                    self._send_status(req_id, SSH_FX_OK, b"OK")
            elif ptype == SSH_FXP_OPEN:
                filename, off = ustr(payload, off)
                pflags, off = u32(payload, off)
                off = parse_attrs_ignore(payload, off)
                vpath, full = self._resolve(filename)

                want_read = bool(pflags & PF_READ)
                want_write = bool(pflags & (PF_WRITE | PF_APPEND | PF_CREAT | PF_TRUNC))
                if not (want_read or want_write):
                    want_read = True
                if want_read:
                    self._authorize("read", vpath)
                if want_write:
                    self._authorize("write", vpath)

                if want_read and want_write: flags = os.O_RDWR
                elif want_write:             flags = os.O_WRONLY
                else:                        flags = os.O_RDONLY
                if pflags & PF_CREAT:  flags |= os.O_CREAT
                if pflags & PF_CREAT and pflags & PF_EXCL: flags |= os.O_EXCL   # atomic, no race
                if pflags & PF_TRUNC:  flags |= os.O_TRUNC
                if pflags & PF_APPEND: flags |= os.O_APPEND
                flags |= getattr(os, "O_BINARY", 0)      # Windows: no newline conversion
                flags |= getattr(os, "O_NOFOLLOW", 0)    # refuse a symlink swapped in after the check

                fd = os.open(full, flags, 0o644)
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    os.close(fd)
                    raise IsADirectoryError(vpath)

                print(f"[OPEN] {self.username}: {vpath} read={want_read} write={want_write}")
                handle = self.handles.add(FileHandle(fd, vpath, want_read, want_write))
                self._chan.write(pack_pkt(SSH_FXP_HANDLE, p_u32(req_id) + handle))

            elif ptype == SSH_FXP_WRITE:
                handle_bs, off = ustr(payload, off)
                offset, off = u64(payload, off)
                data, off = ustr(payload, off)

                h = self.handles.get(handle_bs)
                if not isinstance(h, FileHandle):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return
                if not h.can_write:
                    self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"not opened for writing")
                    return
                os.lseek(h.fd, offset, os.SEEK_SET)
                view = memoryview(data)
                while view:
                    view = view[os.write(h.fd, view):]
                self._send_status(req_id, SSH_FX_OK, b"OK")

            elif ptype == SSH_FXP_READ:
                handle_bs, off = ustr(payload, off)
                offset, off = u64(payload, off)
                length, off = u32(payload, off)  # how many bytes client wants

                h = self.handles.get(handle_bs)
                if not isinstance(h, FileHandle):
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad file handle")
                    return
                if not h.can_read:
                    self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"not opened for reading")
                    return
                os.lseek(h.fd, offset, os.SEEK_SET)
                data = os.read(h.fd, min(length, MAX_READ))
                if not data:
                    self._send_status(req_id, SSH_FX_EOF, b"EOF")
                else:
                    self._chan.write(pack_pkt(SSH_FXP_DATA, p_u32(req_id) + p_str(data)))
                    
            elif ptype == SSH_FXP_CLOSE:
                handle_bs, off = ustr(payload, off)
                if self.handles.close(handle_bs):
                    self._send_status(req_id, SSH_FX_OK, b"OK")
                else:
                    self._send_status(req_id, SSH_FX_FAILURE, b"bad handle")
            else:
                self._send_status(req_id, SSH_FX_FAILURE, b"unsupported")

        except FileNotFoundError:
            self._send_status(req_id, SSH_FX_NO_SUCH_FILE, b"no such file")
        except PermissionError:
            self._send_status(req_id, SSH_FX_PERMISSION_DENIED, b"permission denied")
        except FileExistsError:
            self._send_status(req_id, SSH_FX_FAILURE, b"already exists")
        except Exception as e:
            print(f"[ERROR] user={self.username} type={ptype}: {e!r}")   # details stay on the server
            self._send_status(req_id, SSH_FX_FAILURE, b"failure")

class Server(asyncssh.SSHServer):
    # Tell AsyncSSH we will do user auth:
    def begin_auth(self, username):  # called when a new user starts auth
        self.username = username
        return True  # start authentication

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return auth.validate_user_password(username, password)

    def session_requested(self):
        return SFTPSession(self.username)

async def main():
    if not os.path.exists(HOST_KEY_PATH):
        sys.exit(f"[STARTUP] host key missing: {HOST_KEY_PATH}\n"
                 f"Generate it once with: ssh-keygen -t ed25519 -N '' -f server/ssh_host_ed25519_key")
    try:
        auth.load_users(os.path.join(DATA_DIR, "users.json"))
        print("[STARTUP] loaded data/users.json")
    except FileNotFoundError as e:
        sys.exit(f"[STARTUP] missing data file: {e.filename}")
    except Exception as e:
        sys.exit(f"[STARTUP] could not load data files: {e}")
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
    except KeyboardInterrupt:
        pass
