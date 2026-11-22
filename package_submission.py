#!/usr/bin/env python3
"""
Packaging script to generate the final submission ZIP file.
Enforces course repository structure: server/sftp_root/ is included as an initially empty directory.
Baseline workspace directories and files are generated at runtime by server/server.py.
Excludes .venv, .git, __pycache__, and temporary test caches.
"""
import os
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT_ZIP = ROOT / "DSAI_Computer_Security_Group06.zip"

EXCLUDE_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".vscode", "images"}
EXCLUDE_FILES = {
    "DSAI_Computer_Security_Group_Project_2026-1.pdf",
    "DSAI_Computer_Security_Group06.zip",
    "package_submission.py",
    "stolen_flag.txt",
    "CTF_writeup.md",
    ".gitignore",
    "ssh_host_ed25519_key",
    "ssh_host_ed25519_key.pub",
    "known_hosts",
    "audit.jsonl",
}

def build_zip():
    print(f"[PACKAGING] Building submission ZIP: {OUTPUT_ZIP.name}")
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Walk repository and add project files
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file in EXCLUDE_FILES or file.endswith((".pyc", ".part", ".tmp")):
                    continue
                full_path = Path(root) / file
                rel_path = full_path.relative_to(ROOT).as_posix()

                # Exclude any pre-existing runtime files inside sftp_root (strictly initially empty)
                if rel_path.startswith("server/sftp_root/"):
                    continue

                zinfo = zipfile.ZipInfo.from_file(full_path, arcname=rel_path)
                # Ensure readable Unix permissions (0o644 for files, 0o755 for scripts)
                perms = 0o755 if file.endswith((".py", ".sh")) else 0o644
                zinfo.external_attr = perms << 16
                with open(full_path, "rb") as f:
                    zf.writestr(zinfo, f.read())
                print(f"  + Added file: {rel_path}")

        # 2. Add server/sftp_root/ as an initially empty directory entry
        jail_info = zipfile.ZipInfo("server/sftp_root/")
        jail_info.create_system = 3  # Unix platform
        jail_info.external_attr = (0o755 | 0o40000) << 16  # Directory mode
        zf.writestr(jail_info, b"")
        print("  + Added directory: server/sftp_root/ (initially empty)")

    size_kb = OUTPUT_ZIP.stat().st_size / 1024
    print(f"[DONE] Created {OUTPUT_ZIP.name} ({size_kb:.1f} KB). Ready for submission!")

if __name__ == "__main__":
    build_zip()
