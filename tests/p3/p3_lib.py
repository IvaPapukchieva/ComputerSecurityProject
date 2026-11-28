# shared helpers: config + host key + connecting
import json
import pathlib
import asyncssh

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def load(group):
    return json.loads((HERE / "groups.json").read_text())[group]


def known_hosts(group, cfg):
    # pin the target's own key so connecting is not TOFU
    pub = (ROOT / cfg["hostkey_pub"]).read_text().strip()
    kh = HERE / f"{group}_known_hosts"
    kh.write_text(f"[{cfg['host']}]:{cfg['port']} {pub}\n")
    return str(kh)


async def connect(cfg, user, kh):
    return await asyncssh.connect(
        cfg["host"], port=cfg["port"], username=user,
        password=cfg["creds"][user], known_hosts=kh, preferred_auth="password",
    )
