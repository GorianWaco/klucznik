from __future__ import annotations

import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "klucznik"
DATA_DIR = Path.home() / ".local" / "share" / "klucznik"
DEVICE_FILE = CONFIG_DIR / "device.json"
VAULT_FILE = DATA_DIR / "vault.enc"
U2F_KEYS = CONFIG_DIR / "u2f_keys"
PAM_BACKUP = DATA_DIR / "pam-backup"
AUTOSTART = Path.home() / ".config" / "autostart" / "klucznik-unlock.desktop"
BRAVE_PREPARE_AUTOSTART = Path.home() / ".config" / "autostart" / "klucznik-prepare-brave.desktop"


def ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)
    os.chmod(DATA_DIR, 0o700)
