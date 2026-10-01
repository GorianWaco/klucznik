from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

USER_DATA = Path.home() / ".config" / "BraveSoftware" / "Brave-Browser"
PREFS = USER_DATA / "Default" / "Preferences"
LOCAL_STATE = USER_DATA / "Local State"
RESTORE_ON_STARTUP = 1  # kontynuuj od miejsca, w którym skończyłeś
LAUNCH_FLAGS = ("--restore-last-session", "--hide-crash-restore-bubble")


def _log(msg: str) -> None:
    from .keyring import _log as keyring_log

    keyring_log(msg)


def _atomic_write(path: Path, data: dict) -> None:
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    tmp = path.with_name(path.name + ".klucznik.tmp")
    tmp.write_bytes(raw)
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log(f"BRAVE: {path.name}: {exc}")
        return None
    return data if isinstance(data, dict) else None


def _brave_running() -> bool:
    from .keyring import _brave_main_pids

    return bool(_brave_main_pids())


def prepare_brave_session(*, mark_clean: bool | None = None) -> str:
    """Brave ma sam przywracać karty, bez okna „Restore pages?”."""
    if mark_clean is None:
        mark_clean = not _brave_running()
    notes: list[str] = []
    prefs = _load_json(PREFS)
    if prefs is not None:
        session = prefs.setdefault("session", {})
        if not isinstance(session, dict):
            session = {}
            prefs["session"] = session
        changed = False
        if session.get("restore_on_startup") != RESTORE_ON_STARTUP:
            session["restore_on_startup"] = RESTORE_ON_STARTUP
            session["restore_pref_changed"] = True
            changed = True
            notes.append("ustawiono przywracanie ostatniej sesji")
        profile = prefs.setdefault("profile", {})
        if not isinstance(profile, dict):
            profile = {}
            prefs["profile"] = profile
        if mark_clean:
            if profile.get("exit_type") != "Normal":
                profile["exit_type"] = "Normal"
                changed = True
            if profile.get("exited_cleanly") is not True:
                profile["exited_cleanly"] = True
                changed = True
            notes.append("bez pytania o awarię")
        if changed:
            try:
                _atomic_write(PREFS, prefs)
            except OSError as exc:
                _log(f"BRAVE: zapis Preferences: {exc}")
                return f"Nie zapisano ustawień Brave: {exc}"

    if mark_clean:
        local = _load_json(LOCAL_STATE)
        if local is not None and local.get("exited_cleanly") is False:
            local["exited_cleanly"] = True
            try:
                _atomic_write(LOCAL_STATE, local)
            except OSError as exc:
                _log(f"BRAVE: zapis Local State: {exc}")

    if notes:
        _log("BRAVE: " + ", ".join(notes))
        return "Brave: " + ", ".join(notes) + "."
    return "Brave: sesja już ustawiona na przywracanie bez pytania."


def brave_binary() -> str | None:
    for name in ("brave", "brave-browser", "brave-browser-stable"):
        found = shutil.which(name)
        if found:
            return found
    for path in (Path("/opt/brave-bin/brave"), Path("/usr/bin/brave"), Path("/usr/bin/brave-browser")):
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def launch_brave() -> bool:
    binary = brave_binary()
    if not binary:
        _log("BRAVE: brak binarki")
        return False
    try:
        subprocess.Popen(  # noqa: S603
            [binary, *LAUNCH_FLAGS],
            env=os.environ.copy(),
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _log(f"BRAVE: start {binary} {' '.join(LAUNCH_FLAGS)}")
        return True
    except OSError as exc:
        _log(f"BRAVE: start: {exc}")
        return False


def write_prepare_autostart(enabled: bool) -> None:
    from .paths import BRAVE_PREPARE_AUTOSTART

    BRAVE_PREPARE_AUTOSTART.parent.mkdir(parents=True, exist_ok=True)
    if not enabled:
        if BRAVE_PREPARE_AUTOSTART.exists():
            BRAVE_PREPARE_AUTOSTART.unlink()
        return
    exe = os.path.expanduser("~/.local/bin/klucznik")
    BRAVE_PREPARE_AUTOSTART.write_text(
        "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                "Name=Klucznik — sesja Brave",
                "Comment=Przed startem Brave: przywróć karty, bez pytania o awarię",
                f"Exec={exe} --prepare-brave",
                "OnlyShowIn=GNOME;",
                "X-GNOME-Autostart-enabled=true",
                "X-GNOME-Autostart-Phase=Initialization",
                "X-GNOME-Autostart-Delay=0",
                "Hidden=false",
                "NoDisplay=true",
                "",
            ]
        ),
        encoding="utf-8",
    )
