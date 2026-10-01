from __future__ import annotations

import os
import subprocess
from pathlib import Path

from . import RP_ID
from .paths import PAM_BACKUP, U2F_KEYS

PAM_FILES = (
    Path("/etc/pam.d/gdm-password"),
    Path("/etc/pam.d/sudo"),
    Path("/etc/pam.d/polkit-1"),
)
PAM_U2F_SO = Path("/usr/lib/security/pam_u2f.so")
MARKER = "# klucznik-fido2"


def pam_u2f_installed() -> bool:
    return PAM_U2F_SO.is_file()


def pam_line(authfile: Path | None = None) -> str:
    path = authfile or U2F_KEYS
    # origin w pam_u2f to RP ID (np. localhost), NIE URL https://...
    return (
        f"auth       sufficient    pam_u2f.so authfile={path} "
        f"origin={RP_ID} appid={RP_ID} cue "
        f"userpresence=1 pinverification=0 userverification=0"
    )


def is_enabled() -> bool:
    for pam in PAM_FILES:
        if not pam.is_file():
            continue
        text = pam.read_text(encoding="utf-8", errors="replace")
        if "pam_u2f.so" in text and str(U2F_KEYS) in text:
            return True
    return False


def helper_path() -> Path:
    candidates = [
        Path(__file__).resolve().parents[2] / "share" / "klucznik-pam-install",
        Path.home() / ".local" / "share" / "klucznik" / "klucznik-pam-install",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return candidates[0]


def apply_with_pkexec() -> tuple[bool, str]:
    helper = helper_path()
    if not helper.is_file():
        return False, f"Brak skryptu PAM: {helper}"
    if not U2F_KEYS.is_file():
        return False, "Najpierw zarejestruj klucz FIDO2."
    cmd = [
        "pkexec",
        str(helper),
        "apply",
        str(U2F_KEYS),
        os.environ.get("USER") or os.getlogin(),
        str(PAM_BACKUP),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, out.strip() or ("OK" if proc.returncode == 0 else "pkexec nie powiodło się")


def revert_with_pkexec() -> tuple[bool, str]:
    helper = helper_path()
    cmd = ["pkexec", str(helper), "revert", str(PAM_BACKUP)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, out.strip() or ("OK" if proc.returncode == 0 else "pkexec nie powiodło się")


def write_autostart(exec_cmd: str, enabled: bool) -> None:
    from .paths import AUTOSTART

    AUTOSTART.parent.mkdir(parents=True, exist_ok=True)
    if not enabled:
        if AUTOSTART.exists():
            AUTOSTART.unlink()
        return
    AUTOSTART.write_text(
        "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                "Name=Klucznik — odblokuj sejf GNOME",
                "Comment=Po logowaniu FIDO2 odblokowuje GNOME Keyring (Brave, YouTube, Wi‑Fi)",
                "Exec=" + exec_cmd,
                "OnlyShowIn=GNOME;",
                "X-GNOME-Autostart-enabled=true",
                "X-GNOME-Autostart-Delay=1",
                "Hidden=false",
                "NoDisplay=true",
                "",
            ]
        ),
        encoding="utf-8",
    )
