from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import crypto
from .paths import VAULT_FILE, ensure_dirs


@dataclass
class Entry:
    id: str
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    system: bool = False

    @classmethod
    def new(cls, title: str, **kwargs: Any) -> "Entry":
        return cls(id=str(uuid.uuid4()), title=title, **kwargs)


@dataclass
class Vault:
    unix_password: str = ""
    keyring_password: str = ""
    entries: list[Entry] = field(default_factory=list)
    login_secrets: list[dict[str, Any]] = field(default_factory=list)
    updated_at: str = ""

    def to_json(self) -> bytes:
        payload = {
            "version": 2,
            "unix_password": self.unix_password,
            "keyring_password": self.keyring_password,
            "updated_at": self.updated_at,
            "entries": [asdict(e) for e in self.entries],
            "login_secrets": self.login_secrets,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> "Vault":
        data = json.loads(raw.decode("utf-8"))
        entries = [Entry(**e) for e in data.get("entries") or []]
        secrets = data.get("login_secrets") or []
        if not isinstance(secrets, list):
            secrets = []
        return cls(
            unix_password=str(data.get("unix_password") or ""),
            keyring_password=str(data.get("keyring_password") or ""),
            entries=entries,
            login_secrets=[s for s in secrets if isinstance(s, dict)],
            updated_at=str(data.get("updated_at") or ""),
        )

    def gnome_unlock_password(self) -> str:
        return self.keyring_password or self.unix_password

    def save(self, key: bytes) -> None:
        ensure_dirs()
        self.updated_at = datetime.now(timezone.utc).isoformat()
        blob = crypto.encrypt(key, self.to_json())
        tmp = VAULT_FILE.with_suffix(".enc.tmp")
        tmp.write_bytes(blob)
        os.chmod(tmp, 0o600)
        tmp.replace(VAULT_FILE)

    @classmethod
    def load(cls, key: bytes) -> "Vault":
        blob = VAULT_FILE.read_bytes()
        return cls.from_json(crypto.decrypt(key, blob))

    def wipe(self) -> None:
        self.unix_password = ""
        self.keyring_password = ""
        self.entries.clear()
        self.login_secrets.clear()
