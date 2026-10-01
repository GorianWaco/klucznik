from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="klucznik", description="Klucznik — FIDO2 zamiast haseł")
    parser.add_argument("--unlock-session", action="store_true", help="Okno odblokowania po zalogowaniu")
    parser.add_argument(
        "--prepare-brave",
        action="store_true",
        help="Ustaw Brave: przywróć poprzednią sesję bez pytania",
    )
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)

    if args.version:
        from . import APP_NAME, VERSION

        print(f"{APP_NAME} {VERSION}")
        return 0

    if args.prepare_brave:
        from . import brave_session

        print(brave_session.prepare_brave_session())
        return 0

    if args.status:
        from . import fido
        from .paths import U2F_KEYS, VAULT_FILE
        from . import pamcfg

        try:
            keys = fido.list_keys()
        except fido.FidoError as exc:
            print("fido:", exc)
            keys = []
        for k in keys:
            print(f"klucz: {k.product} {k.path} vid={k.vid:04x} pid={k.pid:04x}")
        print("zarejestrowany:", bool(fido.load_device()))
        print("sejf:", VAULT_FILE)
        print("u2f_keys:", U2F_KEYS, "istnieje" if U2F_KEYS.is_file() else "brak")
        print("pam_u2f.so:", pamcfg.pam_u2f_installed())
        print("pam włączony:", pamcfg.is_enabled())
        return 0

    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw

    from .gui import KlucznikApp

    Adw.init()
    app = KlucznikApp()
    app._unlock_only = bool(args.unlock_session)
    return app.run(None)


if __name__ == "__main__":
    sys.exit(main())
