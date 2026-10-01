from __future__ import annotations

import base64
import os
import shutil
import signal
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

LOGIN_COLLECTION = "/org/freedesktop/secrets/collection/login"
SECRETS_NAME = "org.freedesktop.secrets"
SECRETS_PATH = "/org/freedesktop/secrets"
GUILT_IFACE = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
COLLECTION_IFACE = "org.freedesktop.Secret.Collection"
SERVICE_IFACE = "org.freedesktop.Secret.Service"
BROWSER_BINS = {"brave", "brave-browser", "brave-bin"}
BROWSER_SCHEMAS = {
    "chrome_libsecret_os_crypt_password_v2",
    "chrome_libsecret_os_crypt_password",
    "_chrome_dummy_schema_for_unlocking",
    "org.freedesktop.portal.Secret",
}


def _log(msg: str) -> None:
    from .paths import DATA_DIR, ensure_dirs

    ensure_dirs()
    line = msg.rstrip() + "\n"
    try:
        with (DATA_DIR / "klucznik.log").open("a", encoding="utf-8") as fh:
            from datetime import datetime

            fh.write(f"{datetime.now().isoformat(timespec='seconds')} {line}")
    except OSError:
        pass


def _kill_stray_unlock_daemons() -> None:
    """Drugi gnome-keyring-daemon --unlock nie odblokowuje systemdowego sejfu."""
    uid = os.getuid()
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        parts = [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]
        if not parts:
            continue
        if os.path.basename(parts[0]) != "gnome-keyring-daemon":
            continue
        if "--unlock" not in parts:
            continue
        if "--foreground" in parts or "--control-directory" in parts:
            continue
        try:
            os.kill(int(entry.name), signal.SIGTERM)
            _log(f"KEYRING: zabijam zbędny daemon --unlock pid={entry.name}")
        except OSError:
            pass


def _gi_secret():
    import gi

    gi.require_version("Secret", "1")
    from gi.repository import Gio, GLib, Secret

    return Secret, Gio, GLib


def _service():
    Secret, _, _ = _gi_secret()
    return Secret.Service.get_sync(
        Secret.ServiceFlags.OPEN_SESSION | Secret.ServiceFlags.LOAD_COLLECTIONS,
        None,
    )


def _service_retry(attempts: int = 10):
    last: Exception | None = None
    for _ in range(attempts):
        try:
            return _service()
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(0.25)
    if last:
        raise last
    return _service()


def _login_collection(service):
    for col in service.get_collections() or []:
        path = col.get_object_path() or ""
        if path.rstrip("/").endswith("/login") or (col.get_label() or "") == "Login":
            return col
    try:
        Secret, _, _ = _gi_secret()
        return Secret.Collection.for_alias_sync(
            service, "login", Secret.CollectionFlags.NONE, None
        )
    except Exception:
        return None


def _dbus_call(service, path: str, iface: str, method: str, params, reply_type: str | None, timeout_ms: int = 12_000):
    Secret, Gio, GLib = _gi_secret()
    conn = service.get_connection()
    vt = GLib.VariantType(reply_type) if reply_type else None
    return conn.call_sync(
        service.get_name() or SECRETS_NAME,
        path,
        iface,
        method,
        params,
        vt,
        Gio.DBusCallFlags.NONE,
        timeout_ms,
        None,
    )


def _locked_dbus(service, collection_path: str) -> bool | None:
    _, _, GLib = _gi_secret()
    try:
        variant = _dbus_call(
            service,
            collection_path,
            "org.freedesktop.DBus.Properties",
            "Get",
            GLib.Variant("(ss)", (COLLECTION_IFACE, "Locked")),
            "(v)",
            4000,
        )
        return bool(variant.unpack()[0])
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: Locked property: {exc}")
        return None


def is_login_locked() -> bool | None:
    try:
        service = _service()
        col = _login_collection(service)
        if col is None:
            return None
        path = col.get_object_path() or LOGIN_COLLECTION
        locked = _locked_dbus(service, path)
        if locked is not None:
            return locked
        return bool(col.get_locked())
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: status: {exc}")
        return None


def _encode_secret(service, password: str):
    Secret, _, _ = _gi_secret()
    value = Secret.Value.new(password, -1, "text/plain")
    return service.encode_dbus_secret(value)


def dismiss_unlock_prompts() -> int:
    """Zamyka wiszące okno „Authentication required” bez wpisywania hasła."""
    n = 0
    try:
        Secret, Gio, GLib = _gi_secret()
        service = Secret.Service.get_sync(Secret.ServiceFlags.NONE, None)
        conn = service.get_connection()
        xml_v = conn.call_sync(
            service.get_name() or SECRETS_NAME,
            SECRETS_PATH + "/prompt",
            "org.freedesktop.DBus.Introspectable",
            "Introspect",
            None,
            GLib.VariantType("(s)"),
            Gio.DBusCallFlags.NONE,
            4000,
            None,
        )
        xml = xml_v.unpack()[0]
        root = ET.fromstring(xml)
        for node in root.findall("node"):
            name = node.get("name")
            if not name:
                continue
            path = f"{SECRETS_PATH}/prompt/{name}"
            try:
                conn.call_sync(
                    service.get_name() or SECRETS_NAME,
                    path,
                    "org.freedesktop.Secret.Prompt",
                    "Dismiss",
                    None,
                    None,
                    Gio.DBusCallFlags.NONE,
                    4000,
                    None,
                )
                n += 1
            except Exception as exc:  # noqa: BLE001
                _log(f"KEYRING: dismiss {path}: {exc}")
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: dismiss: {exc}")
    if n:
        _log(f"KEYRING: zamknięto promptów: {n}")
    return n


def _unlock_with_master(service, collection_path: str, password: str) -> None:
    _, _, GLib = _gi_secret()
    encoded = _encode_secret(service, password)
    params = GLib.Variant.new_tuple(GLib.Variant("o", collection_path), encoded)
    _dbus_call(
        service,
        SECRETS_PATH,
        GUILT_IFACE,
        "UnlockWithMasterPassword",
        params,
        "()",
    )


def unlock_gnome_keyring(password: str) -> tuple[bool, str]:
    """Odblokowuje login keyring w już działającym daemonie (bez drugiego procesu)."""
    _kill_stray_unlock_daemons()
    if not password:
        return False, "Brak hasła Linuksa w sejfie Klucznika."
    try:
        if is_login_locked() is False:
            dismiss_unlock_prompts()
            return True, "Sejf GNOME już był odblokowany."
        service = _service()
        col = _login_collection(service)
        path = (col.get_object_path() if col is not None else None) or LOGIN_COLLECTION
        _log(f"KEYRING: UnlockWithMasterPassword path={path} len={len(password)}")
        _unlock_with_master(service, path, password)
        locked = is_login_locked()
        if locked is False:
            dismiss_unlock_prompts()
            _log("KEYRING: odblokowany przez D-Bus")
            return True, "Sejf GNOME odblokowany."
        _log("KEYRING: D-Bus wrócił, ale login nadal zablokowany")
        return False, "Hasło nie odblokowało sejfu GNOME."
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: {exc}")
        if is_login_locked() is False:
            dismiss_unlock_prompts()
            return True, "Sejf GNOME odblokowany."
        return False, str(exc)


def _item_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    attrs = item.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}
    return (
        str(attrs.get("xdg:schema") or ""),
        str(attrs.get("application") or ""),
        str(attrs.get("app_id") or ""),
        str(item.get("label") or ""),
    )


def is_browser_secret(item: dict[str, Any]) -> bool:
    attrs = item.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}
    schema = str(attrs.get("xdg:schema") or "")
    app = str(attrs.get("application") or "").lower()
    label = str(item.get("label") or "")
    if schema in BROWSER_SCHEMAS:
        return True
    if app in {"brave", "chrome", "chromium", "discord"}:
        return True
    return "Safe Storage" in label


def secret_labels(secrets: list[dict[str, Any]]) -> list[str]:
    labels = []
    for item in secrets:
        label = str(item.get("label") or "").strip()
        if label:
            labels.append(label)
    return labels


def export_login_secrets() -> list[dict[str, Any]]:
    """Kopia pozycji z odblokowanego login keyring (w tym Brave Safe Storage)."""
    Secret, _, _ = _gi_secret()
    service = _service()
    try:
        service.load_collections_sync(None)
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: load_collections: {exc}")
    col = _login_collection(service)
    if col is None:
        return []
    if col.get_locked():
        return []
    try:
        col.load_items_sync(None)
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: load_items: {exc}")
    out: list[dict[str, Any]] = []
    for item in col.get_items() or []:
        try:
            item.load_secret_sync(None)
        except Exception as exc:  # noqa: BLE001
            _log(f"KEYRING: load_secret {item.get_label()!r}: {exc}")
            continue
        value = item.get_secret()
        if value is None:
            continue
        raw = value.get()
        if isinstance(raw, str):
            raw_b = raw.encode("utf-8")
        else:
            raw_b = bytes(raw or b"")
        if not raw_b:
            continue
        attrs = dict(item.get_attributes() or {})
        rec = {
            "label": item.get_label() or "",
            "attributes": {str(k): str(v) for k, v in attrs.items()},
            "secret_b64": base64.b64encode(raw_b).decode("ascii"),
            "content_type": value.get_content_type() or "text/plain",
        }
        out.append(rec)
    _log("KEYRING: snapshot " + ", ".join(secret_labels(out) or ["(pusto)"]))
    return out


def _schema_for(attrs: dict[str, str]):
    Secret, _, _ = _gi_secret()
    name = attrs.get("xdg:schema") or "org.freedesktop.Secret.Generic"
    fields = {k: Secret.SchemaAttributeType.STRING for k in attrs if k != "xdg:schema"}
    if not fields:
        fields = {"xdg:schema": Secret.SchemaAttributeType.STRING}
    return Secret.Schema.new(name, Secret.SchemaFlags.DONT_MATCH_NAME, fields)


def _value_from_record(rec: dict[str, Any]):
    Secret, _, _ = _gi_secret()
    raw = base64.b64decode(str(rec.get("secret_b64") or "").encode("ascii"))
    content_type = str(rec.get("content_type") or "text/plain")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
        content_type = content_type or "application/octet-stream"
    return Secret.Value.new(text, -1, content_type)


def restore_login_secrets(secrets: list[dict[str, Any]], *, replace: bool = True) -> int:
    """Dopisuje brakujące (albo nadpisuje) sekrety w odblokowanym login keyring."""
    if not secrets:
        return 0
    Secret, _, _ = _gi_secret()
    service = _service()
    col = _login_collection(service)
    if col is None or col.get_locked():
        return 0
    existing = set()
    if not replace:
        existing = {_item_key(s) for s in export_login_secrets()}
    flags = Secret.ItemCreateFlags.REPLACE if replace else Secret.ItemCreateFlags(0)
    n = 0
    for rec in secrets:
        attrs = rec.get("attributes") or {}
        if not isinstance(attrs, dict):
            continue
        clean = {str(k): str(v) for k, v in attrs.items()}
        key = _item_key({"attributes": clean, "label": rec.get("label")})
        if not replace and key in existing:
            continue
        try:
            schema = _schema_for(clean)
            store_attrs = {k: v for k, v in clean.items() if k != "xdg:schema"} or clean
            Secret.Item.create_sync(
                col,
                schema,
                store_attrs,
                str(rec.get("label") or "secret"),
                _value_from_record(rec),
                flags,
                None,
            )
            n += 1
        except Exception as exc:  # noqa: BLE001
            _log(f"KEYRING: restore {rec.get('label')!r}: {exc}")
    if n:
        _log(f"KEYRING: przywrócono pozycji: {n}")
    return n


def _keyring_file() -> Path:
    return Path.home() / ".local/share/keyrings/login.keyring"


def _backup_keyring_file() -> None:
    from .paths import DATA_DIR, ensure_dirs

    ensure_dirs()
    src = _keyring_file()
    if not src.is_file():
        return
    bak = DATA_DIR / "login.keyring.bak"
    shutil.copy2(src, bak)
    os.chmod(bak, 0o600)
    _log(f"KEYRING: kopia pliku {bak}")


def _systemctl_user(*args: str) -> None:
    subprocess.run(
        ["systemctl", "--user", *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _reset_keyring_file() -> None:
    """Usuwa zablokowany login.keyring i restartuje systemdowy daemon."""
    _backup_keyring_file()
    src = _keyring_file()
    _systemctl_user("stop", "gnome-keyring-daemon.service")
    time.sleep(0.2)
    if src.is_file():
        src.unlink()
        _log("KEYRING: usunięto zablokowany login.keyring")
    _systemctl_user("start", "gnome-keyring-daemon.service")
    time.sleep(0.6)


def _set_alias(service, alias: str, path: str) -> None:
    _, _, GLib = _gi_secret()
    try:
        _dbus_call(
            service,
            SECRETS_PATH,
            SERVICE_IFACE,
            "SetAlias",
            GLib.Variant("(so)", (alias, path)),
            "()",
            8000,
        )
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: SetAlias {alias}: {exc}")


def _create_login_with_password(password: str) -> str:
    _, _, GLib = _gi_secret()
    service = _service_retry()
    encoded = _encode_secret(service, password)
    props = GLib.Variant(
        "a{sv}",
        {"org.freedesktop.Secret.Collection.Label": GLib.Variant("s", "Login")},
    )
    result = _dbus_call(
        service,
        SECRETS_PATH,
        GUILT_IFACE,
        "CreateWithMasterPassword",
        GLib.Variant.new_tuple(props, encoded),
        "(o)",
        15_000,
    )
    path = result.unpack()[0]
    _set_alias(service, "login", path)
    _set_alias(service, "default", path)
    _log(f"KEYRING: nowa kolekcja Login {path}")
    return path


def recreate_login_keyring(password: str, secrets: list[dict[str, Any]]) -> tuple[bool, str]:
    """Tworzy login keyring z hasłem z sejfu i wgrywa kopię Brave/Discord/portalu."""
    if not password:
        return False, "Brak hasła do nowego sejfu GNOME."
    if not secrets:
        return False, "Brak kopii haseł Brave w sejfie Klucznika."
    _log("KEYRING: odtwarzam login keyring z kopii w Kluczniku")
    try:
        _reset_keyring_file()
        try:
            _create_login_with_password(password)
        except Exception as exc:  # noqa: BLE001
            _log(f"KEYRING: create login: {exc}")
            if is_login_locked() is True:
                unlock_gnome_keyring(password)
            if is_login_locked() is True:
                raise
        restored = restore_login_secrets(secrets, replace=True)
        locked = is_login_locked()
        if locked is True:
            unlock_gnome_keyring(password)
            locked = is_login_locked()
            if locked is False:
                restore_login_secrets(secrets, replace=True)
        if locked is True:
            return False, "Nowy sejf GNOME powstał, ale nadal jest zablokowany."
        labels = ", ".join(secret_labels(secrets)) or "hasła"
        return True, f"Odtworzono sejf GNOME ({labels})."
    except Exception as exc:  # noqa: BLE001
        _log(f"KEYRING: recreate: {exc}")
        return False, str(exc)


def _brave_main_pids() -> list[int]:
    uid = os.getuid()
    pids: list[int] = []
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        parts = [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]
        if not parts:
            continue
        if os.path.basename(parts[0]) not in BROWSER_BINS:
            continue
        if any(p.startswith("--type=") for p in parts):
            continue
        pids.append(int(entry.name))
    return pids


def restart_brave() -> str:
    from . import brave_session

    pids = _brave_main_pids()
    if not pids:
        return ""
    _log(f"KEYRING: restart Brave pid={pids}")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 8
    while time.time() < deadline:
        if not any(Path(f"/proc/{p}").exists() for p in pids):
            break
        time.sleep(0.2)
    else:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.3)
    brave_session.prepare_brave_session(mark_clean=True)
    launched = brave_session.launch_brave()
    return (
        "Zrestartowano Brave z poprzednią sesją (bez pytania)."
        if launched
        else "Brave był otwarty — zamknij i otwórz go ponownie."
    )


def sync_session(password: str, saved_secrets: list[dict[str, Any]] | None = None) -> tuple[bool, str, list[dict[str, Any]]]:
    """Odblokuj sejf GNOME, zapisz/przywróć Brave Safe Storage, ewentualnie zrestartuj Brave.

    Zwraca (ok, komunikat, aktualna kopia sekretów do zapisania w sejfie).
    """
    saved = list(saved_secrets or [])
    _kill_stray_unlock_daemons()
    was_locked = is_login_locked() is True
    notes: list[str] = []
    exported: list[dict[str, Any]] = []

    if was_locked:
        if password:
            ok, msg = unlock_gnome_keyring(password)
            notes.append(msg)
            if not ok and saved:
                rec_ok, rec_msg = recreate_login_keyring(password, saved)
                notes.append(rec_msg)
                if rec_ok:
                    was_locked = True
        elif saved:
            rec_ok, rec_msg = recreate_login_keyring(password, saved)
            notes.append(rec_msg)
        else:
            notes.append("Sejf GNOME zablokowany i brak hasła w Kluczniku.")
    else:
        notes.append("Sejf GNOME już był odblokowany.")

    locked = is_login_locked()
    if locked is False:
        live = export_login_secrets()
        have = {_item_key(s) for s in live}
        missing = [s for s in saved if _item_key(s) not in have]
        if missing:
            restore_login_secrets(missing, replace=False)
            live = export_login_secrets()
            notes.append("Przywrócono brakujące hasła Brave/GNOME z kopii Klucznika.")
        exported = live or saved
        if not any(is_browser_secret(s) for s in exported) and any(is_browser_secret(s) for s in saved):
            restore_login_secrets([s for s in saved if is_browser_secret(s)], replace=True)
            exported = export_login_secrets() or saved
        if was_locked:
            dismiss_unlock_prompts()
            restart_msg = restart_brave()
            if restart_msg:
                notes.append(restart_msg)
        elif not _brave_main_pids():
            from . import brave_session

            notes.append(brave_session.prepare_brave_session(mark_clean=True))
        labels = [lab for lab in secret_labels(exported) if "Safe Storage" in lab or "Brave" in lab or "portal" in lab.lower() or "Application key" in lab]
        if any(is_browser_secret(s) for s in exported):
            shown = ", ".join(labels or secret_labels(exported)[:4])
            notes.append(f"Zapisano w sejfie Klucznika: {shown}.")
        return True, " ".join(notes), exported

    if saved and password:
        rec_ok, rec_msg = recreate_login_keyring(password, saved)
        notes.append(rec_msg)
        if rec_ok and is_login_locked() is False:
            exported = export_login_secrets() or saved
            restart_msg = restart_brave()
            if restart_msg:
                notes.append(restart_msg)
            return True, " ".join(notes), exported

    return False, " ".join(notes) or "Nie udało się odblokować sejfu GNOME.", exported
