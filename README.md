-- fill in the other documentation
>TODO
---

## Client

`client/client.py` is an SFTP v3 client. asyncssh provides the SSH connection;
the client builds and parses all SFTP packets itself.

### Running

With the server running:

```
python client/client.py --host 127.0.0.1 --port 2222 --username bob
```

The password is asked for interactively and is never echoed or stored.

### Host key verification

On first connect the client shows the server's fingerprint and asks to trust it
(TOFU). Check it against `ssh-keygen -lf server/ssh_host_ed25519_key`, then type `yes`.
The key is saved to `client/known_hosts`; if it ever changes, the client refuses
to connect. Alternatively, a known_hosts file can be prepared in advance and passed
with `--known-hosts`.

### Commands

| Command | Description |
|---|---|
| `pwd` | Print remote working directory |
| `cd <path>` | Change remote directory |
| `ls [path]` | List a directory |
| `mkdir <path>` | Create a directory |
| `stat <path>` | Show file attributes |
| `get <rpath> [lpath]` | Download a file |
| `put <lpath> [rpath]` | Upload a file |
| `quit` | Disconnect |

Server errors are shown as e.g. `remote: permission denied` and the session continues.

### Example

```
sftp> ls
-rw-rw-rw-   0 0        0               0 Nov 11 12:09 Test.txt
drwxrwxrwx   0 0        0               0 Nov 11 12:09 admin
drwxrwxrwx   0 0        0               0 Nov 11 12:09 projects
sftp> put client/client.py /projects/c.py
Uploaded client/client.py -> /projects/c.py (17553 bytes)
sftp> ls /admin
remote: permission denied
```

### Known limitations

- No `rm`, `rename` or recursive transfers.
- One request at a time (no pipelining).
- `get` overwrites an existing local file without asking.

---

## Tests

> TODO 

## Access Control Design

>TODO 
## Users

>TODO
