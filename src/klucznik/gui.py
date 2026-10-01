from __future__ import annotations

import os
import threading
from getpass import getuser

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")

from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

from . import APP_ID, APP_NAME, VERSION
from . import fido, keyring, pamcfg
from .crypto import derive_vault_key
from .paths import AUTOSTART, U2F_KEYS, VAULT_FILE, ensure_dirs
from .vault import Entry, Vault


def _css() -> None:
    provider = Gtk.CssProvider()
    provider.load_from_data(
        b"""
        .klucznik-hero {
            font-size: 18pt;
            font-weight: 700;
        }
        .klucznik-ok { color: #3fb950; }
        .klucznik-bad { color: #f85149; }
        """
    )
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )


class KlucznikApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)
        self.connect("activate", self._on_activate)
        self._unlock_only = False

    def _on_activate(self, _app) -> None:
        win = KlucznikWindow(application=self, unlock_only=self._unlock_only)
        win.present()


class KlucznikWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        self.unlock_only = kwargs.pop("unlock_only", False)
        super().__init__(**kwargs)
        self.set_title(f"{APP_NAME} {VERSION}")
        self.set_default_size(520, 320) if self.unlock_only else self.set_default_size(860, 640)
        ensure_dirs()
        _css()

        self.vault: Vault | None = None
        self.vault_key: bytes | None = None
        self._pin_cache: str | None = None
        self._busy = False
        self._snapshotted = False
        self._closing = False

        self.toasts = Adw.ToastOverlay()
        self.set_content(self.toasts)

        self.banner = Adw.Banner(title="")
        self.banner.set_revealed(False)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        header.set_title_widget(
            Adw.WindowTitle(
                title=APP_NAME,
                subtitle="Odblokuj sejf GNOME" if self.unlock_only else "FIDO2 zamiast haseł",
            )
        )
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(self.banner)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        outer.set_margin_top(16)
        outer.set_margin_bottom(16)
        outer.set_margin_start(20)
        outer.set_margin_end(20)

        self.status_label = Gtk.Label(xalign=0)
        self.status_label.add_css_class("klucznik-hero")
        outer.append(self.status_label)

        self.device_label = Gtk.Label(xalign=0, wrap=True)
        self.device_label.add_css_class("dim-label")
        outer.append(self.device_label)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.btn_unlock = Gtk.Button(label="Odblokuj kluczem FIDO2")
        self.btn_unlock.add_css_class("suggested-action")
        self.btn_unlock.add_css_class("pill")
        self.btn_unlock.connect("clicked", lambda *_: self._run_bg(self._do_unlock))
        self.btn_lock = Gtk.Button(label="Zablokuj sejf")
        self.btn_lock.connect("clicked", lambda *_: self._lock())
        self.btn_enroll = Gtk.Button(label="Zarejestruj klucz")
        self.btn_enroll.connect("clicked", lambda *_: self._confirm_enroll())
        btn_row.append(self.btn_unlock)
        btn_row.append(self.btn_lock)
        btn_row.append(self.btn_enroll)
        outer.append(btn_row)

        self.stack = Adw.ViewStack()
        switcher = Adw.ViewSwitcher()
        switcher.set_stack(self.stack)
        switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
        outer.append(switcher)

        self.stack.add_titled(self._build_vault_page(), "vault", "Sejf haseł")
        self.stack.add_titled(self._build_system_page(), "system", "Logowanie")
        outer.append(self.stack)
        if self.unlock_only:
            self.stack.set_visible(False)
            switcher.set_visible(False)
            self.btn_enroll.set_visible(False)
            self.btn_lock.set_visible(False)

        scroller = Gtk.ScrolledWindow()
        scroller.set_child(outer)
        scroller.set_vexpand(True)
        toolbar.set_content(scroller)
        self.toasts.set_child(toolbar)

        GLib.timeout_add_seconds(2, self._poll)
        self._ensure_autostart()
        self._refresh_status()
        if self.unlock_only and fido.load_device() and self.vault is None:
            GLib.timeout_add(700, lambda: self._run_bg(self._do_unlock) or False)

    # ── pages ────────────────────────────────────────────────
    def _build_vault_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(8)
        hint = Gtk.Label(
            xalign=0,
            wrap=True,
            label="Hasła trzymane w zaszyfrowanym sejfie. Klucz AES pochodzi z hmac-secret Twojego FIDO2 — bez klucza USB plik nic nie daje.",
        )
        hint.add_css_class("dim-label")
        box.append(hint)

        add = Gtk.Button(label="Dodaj hasło")
        add.set_halign(Gtk.Align.START)
        add.connect("clicked", lambda *_: self._add_entry_dialog())
        box.append(add)

        self.vault_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.append(self.vault_list)
        return box

    def _build_system_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        page.set_margin_top(8)

        warn = Gtk.Label(
            xalign=0,
            wrap=True,
            label="Logowanie, sudo i pkexec: zostaw pole hasła puste i tapnij klucz FIDO2. Nic nie wpisuj — ExcelSecu udaje klawiaturę i potrafi wkleić śmieciowe hasło. Gdy klucza nie ma w USB, zwykłe hasło nadal działa.",
        )
        warn.add_css_class("dim-label")
        page.append(warn)

        self.pam_status = Gtk.Label(xalign=0, wrap=True)
        page.append(self.pam_status)

        row = Gtk.Box(spacing=8)
        self.btn_pam_on = Gtk.Button(label="Włącz logowanie kluczem")
        self.btn_pam_on.add_css_class("suggested-action")
        self.btn_pam_on.connect("clicked", lambda *_: self._pam_apply())
        self.btn_pam_off = Gtk.Button(label="Wyłącz (przywróć PAM)")
        self.btn_pam_off.connect("clicked", lambda *_: self._pam_revert())
        row.append(self.btn_pam_on)
        row.append(self.btn_pam_off)
        page.append(row)

        self.gnome_status = Gtk.Label(xalign=0, wrap=True)
        page.append(self.gnome_status)

        self.auto_unlock = Gtk.CheckButton(
            label="Po zalogowaniu tapnij FIDO2: odblokuj sejf GNOME i przywróć sesję Brave (karty, YouTube) bez pytania"
        )
        enrolled = fido.load_device() is not None
        self.auto_unlock.set_active(AUTOSTART.is_file() or enrolled)
        self.auto_unlock.connect("toggled", lambda *_: self._sync_autostart())
        page.append(self.auto_unlock)

        pkg = Gtk.Label(
            xalign=0,
            wrap=True,
            label="Do PAM potrzeba pakietów: pam-u2f libfido2 (skrypt zapyta o hasło przez pkexec).",
        )
        pkg.add_css_class("dim-label")
        page.append(pkg)
        return page

    # ── status ───────────────────────────────────────────────
    def _poll(self) -> bool:
        if not self._busy:
            self._refresh_status()
            self._maybe_snapshot_unlocked_keyring()
        return True

    def _refresh_status(self) -> None:
        try:
            keys = fido.list_keys()
            fido_err = ""
        except fido.FidoError as exc:
            keys = []
            fido_err = str(exc)

        enrolled = fido.load_device() is not None
        unlocked = self.vault is not None

        if keys:
            names = ", ".join(f"{k.product} ({k.path})" for k in keys)
            self.device_label.set_text(f"Podłączony: {names}")
        elif fido_err:
            self.device_label.set_text(fido_err)
        else:
            self.device_label.set_text("Brak klucza FIDO2 w USB — wepnij ExcelSecu / YubiKey / Nitrokey.")

        if unlocked:
            self.status_label.set_text("Sejf otwarty")
            self.status_label.add_css_class("klucznik-ok")
            self.status_label.remove_css_class("klucznik-bad")
        elif enrolled:
            self.status_label.set_text("Klucz zarejestrowany — dotknij, żeby otworzyć sejf")
            self.status_label.remove_css_class("klucznik-ok")
            self.status_label.remove_css_class("klucznik-bad")
        else:
            self.status_label.set_text("Klucz jeszcze nie zarejestrowany")
            self.status_label.remove_css_class("klucznik-ok")
            self.status_label.add_css_class("klucznik-bad")

        locked = keyring.is_login_locked()
        keyring_locked = locked is True
        self.btn_unlock.set_sensitive(
            not self._busy
            and bool(keys)
            and (
                (enrolled and not unlocked)
                or (unlocked and keyring_locked)
            )
        )
        self.btn_lock.set_sensitive(unlocked)
        self.btn_enroll.set_sensitive(bool(keys) and not self._busy)
        self.stack.set_sensitive(unlocked or not enrolled)

        pam_on = pamcfg.is_enabled()
        so = "tak" if pamcfg.pam_u2f_installed() else "nie (doinstaluje się przy włączaniu)"
        mapping = "tak" if U2F_KEYS.is_file() else "nie"
        self.pam_status.set_text(
            f"pam_u2f w systemie: {so}\n"
            f"Plik mapowania: {mapping} ({U2F_KEYS})\n"
            f"Logowanie/sudo kluczem: {'włączone' if pam_on else 'wyłączone'}"
        )
        self.btn_pam_on.set_sensitive(enrolled)
        if locked is None:
            gkr = "GNOME Keyring: brak danych"
        elif locked:
            gkr = "GNOME Keyring: zablokowany — tapnij FIDO2, nie wpisuj hasła w oknie Brave/YouTube"
        else:
            gkr = "GNOME Keyring: odblokowany (Brave, YouTube, Wi‑Fi)"
        if self.vault is not None:
            labels = keyring.secret_labels(self.vault.login_secrets)
            brave = [x for x in labels if "Brave" in x or "Safe Storage" in x or "Application key" in x]
            if brave:
                gkr += "\nKopia w sejfie Klucznika: " + ", ".join(brave)
            elif labels:
                gkr += "\nKopia w sejfie Klucznika: " + ", ".join(labels)
            else:
                gkr += "\nBrak kopii haseł Brave — odblokuj sejf GNOME, Klucznik je zapisze."
        if hasattr(self, "gnome_status"):
            self.gnome_status.set_text(gkr)
        self._rebuild_vault_list()

    def _toast(self, text: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=text, timeout=6))

    def _error_dialog(self, text: str) -> None:
        dlg = Adw.AlertDialog()
        dlg.set_heading("Klucznik")
        dlg.set_body(text)
        dlg.add_response("ok", "OK")
        dlg.present(self)

    def _set_banner(self, text: str | None) -> None:
        if text:
            self.banner.set_title(text)
            self.banner.set_revealed(True)
        else:
            self.banner.set_revealed(False)

    # ── background jobs ──────────────────────────────────────
    def _run_bg(self, fn) -> None:
        if self._busy:
            return
        self._busy = True
        self._refresh_status()

        def work():
            err = None
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                err = exc

            def done():
                self._busy = False
                self._set_banner(None)
                if err:
                    msg = fido.format_error(err) if not isinstance(err, fido.FidoError) else str(err)
                    self._error_dialog(msg)
                    fido.log("GUI: " + msg)
                self._refresh_status()
                self._maybe_close_unlock_only()

            GLib.idle_add(done)

        threading.Thread(target=work, daemon=True).start()

    def _ask_pin_blocking(self) -> str | None:
        if self._pin_cache:
            return self._pin_cache
        pin = self._ask_text_blocking(
            "PIN klucza FIDO2",
            "To PIN samego klucza USB (nie hasło do Linuksa). Potem klucz powinien migać — wtedy go dotknij.",
        )
        if pin:
            self._pin_cache = pin
        return pin

    def _on_touch(self) -> None:
        GLib.idle_add(self._set_banner, "Dotknij teraz klucza FIDO2 (przycisk na pendrive, gdy miga)…")

    def _ask_text_blocking(self, heading: str, body: str) -> str | None:
        holder: dict = {}
        ev = threading.Event()

        def show():
            win = Gtk.Window(transient_for=self, modal=True, title=heading)
            win.set_default_size(440, 200)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            box.set_margin_top(16)
            box.set_margin_bottom(16)
            box.set_margin_start(16)
            box.set_margin_end(16)
            lab = Gtk.Label(label=body, wrap=True, xalign=0)
            box.append(lab)
            entry = Gtk.PasswordEntry()
            entry.set_show_peek_icon(True)
            entry.set_hexpand(True)
            box.append(entry)
            btn = Gtk.Button(label="OK")
            btn.add_css_class("suggested-action")
            btn.set_halign(Gtk.Align.END)
            done = {"n": False}

            def finish(_w=None, *_a):
                if done["n"]:
                    return False
                done["n"] = True
                holder["text"] = entry.get_text()
                ev.set()
                win.destroy()
                return True

            btn.connect("clicked", finish)
            entry.connect("activate", finish)
            win.connect("close-request", finish)
            box.append(btn)
            win.set_child(box)
            win.present()
            entry.grab_focus()
            return False

        GLib.idle_add(show)
        ev.wait(timeout=180)
        return holder.get("text") or None

    # ── enroll / unlock ──────────────────────────────────────
    def _confirm_enroll(self) -> None:
        dlg = Adw.AlertDialog()
        dlg.set_heading("Zarejestrować ten klucz?")
        dlg.set_body(
            "1) PIN klucza USB (nie hasło do Linuksa)\n"
            "2) Gdy klucz miga — dotknij go (może dwa razy)\n"
            "3) Na końcu raz hasło do Linuksa, do sejfu GNOME\n\n"
            "Hasło logowania NIE znika — zostaje jako zapas."
        )
        dlg.add_response("cancel", "Anuluj")
        dlg.add_response("ok", "Rejestruj")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(_d, response):
            if response == "ok":
                self._pin_cache = None
                self._run_bg(self._do_enroll)

        dlg.connect("response", on_resp)
        dlg.present(self)

    def _do_enroll(self) -> None:
        GLib.idle_add(self._set_banner, "PIN klucza USB, potem dotknij FIDO2 gdy miga…")
        secret, meta = fido.enroll(self._ask_pin_blocking, self._on_touch)
        unix_pw = self._ask_text_blocking(
            "Hasło logowania Linuksa",
            "Raz, do sejfu. Potem Klucznik odblokuje nim GNOME Keyring po tapnięciu FIDO2. Możesz zostawić puste i uzupełnić później.",
        ) or ""
        key = derive_vault_key(secret, meta["username"])
        vault = Vault(unix_password=unix_pw, keyring_password=unix_pw)
        if unix_pw:
            vault.entries.append(
                Entry.new("Hasło logowania / sudo", username=getuser(), password=unix_pw, system=True)
            )
        vault.save(key)
        self.vault = vault
        self.vault_key = key
        GLib.idle_add(self._sync_autostart)
        GLib.idle_add(self._toast, f"Zarejestrowano: {meta.get('product') or 'klucz FIDO2'}")
        msg = self._unlock_gnome_from_vault(vault)
        GLib.idle_add(self._toast, msg)

    def _do_unlock(self) -> None:
        if self.vault is None or self.vault_key is None:
            GLib.idle_add(self._set_banner, "PIN, potem dotknij klucza FIDO2…")
            secret = fido.get_hmac_secret(ask_pin=self._ask_pin_blocking, on_touch=self._on_touch)
            user = (fido.load_device() or {}).get("username") or getuser()
            key = derive_vault_key(secret, user)
            vault = Vault.load(key)
            self.vault = vault
            self.vault_key = key
            GLib.idle_add(self._sync_autostart)
        else:
            vault = self.vault
        msg = self._unlock_gnome_from_vault(vault)
        GLib.idle_add(self._toast, msg)

    def _ensure_autostart(self) -> None:
        if fido.load_device() is None:
            return
        if not hasattr(self, "auto_unlock"):
            return
        if self.auto_unlock.get_active() and not AUTOSTART.is_file():
            self._sync_autostart()

    def _save_login_secrets(self, vault: Vault, secrets: list) -> None:
        if not self.vault_key:
            return
        vault.login_secrets = list(secrets or [])
        vault.save(self.vault_key)
        if any(keyring.is_browser_secret(s) for s in vault.login_secrets):
            self._snapshotted = True

    def _maybe_snapshot_unlocked_keyring(self) -> None:
        if self.vault is None or self.vault_key is None or self._busy or self._snapshotted:
            return
        if keyring.is_login_locked() is not False:
            return
        try:
            secrets = keyring.export_login_secrets()
        except Exception as exc:  # noqa: BLE001
            fido.log(f"GUI snapshot: {exc}")
            return
        if not secrets:
            return
        self._save_login_secrets(self.vault, secrets)
        self._toast("Zapisano hasła Brave/GNOME w sejfie Klucznika.")
        self._maybe_close_unlock_only()

    def _maybe_close_unlock_only(self) -> None:
        if not self.unlock_only or self.vault is None or self._closing:
            return
        if keyring.is_login_locked() is False:
            self._closing = True
            GLib.timeout_add(900, self.close)

    def _unlock_gnome_from_vault(self, vault: Vault) -> str:
        pw = vault.gnome_unlock_password()
        if not pw:
            pw = (
                self._ask_text_blocking(
                    "Hasło logowania Linuksa",
                    "Raz, do odblokowania sejfu GNOME (Brave, YouTube). Zapiszę je w sejfie Klucznika. Potem wystarczy tapnięcie FIDO2.",
                )
                or ""
            )
            if pw and self.vault_key:
                vault.unix_password = pw
                vault.keyring_password = pw
                if not any(e.system for e in vault.entries):
                    vault.entries.append(
                        Entry.new(
                            "Hasło logowania / sudo",
                            username=getuser(),
                            password=pw,
                            system=True,
                        )
                    )
                vault.save(self.vault_key)
        ok, msg, secrets = keyring.sync_session(pw, vault.login_secrets)
        if secrets:
            self._save_login_secrets(vault, secrets)
        if ok:
            return "Sejf otwarty. " + msg
        pw2 = (
            self._ask_text_blocking(
                "Hasło do sejfu GNOME",
                "To hasło z okna Brave „Authentication required” (zwykle hasło logowania). Wpisz raz — Klucznik zapisze je i po restarcie sam odblokuje Brave.",
            )
            or ""
        )
        if not pw2:
            return "Sejf otwarty. " + msg
        vault.keyring_password = pw2
        if not vault.unix_password:
            vault.unix_password = pw2
        if self.vault_key:
            vault.save(self.vault_key)
        ok, msg, secrets = keyring.sync_session(pw2, vault.login_secrets)
        if secrets:
            self._save_login_secrets(vault, secrets)
        return "Sejf otwarty. " + msg

    def _lock(self) -> None:
        if self.vault:
            self.vault.wipe()
        self.vault = None
        self.vault_key = None
        self._pin_cache = None
        self._snapshotted = False
        self._closing = False
        self._toast("Sejf zablokowany.")
        self._refresh_status()

    # ── vault UI ─────────────────────────────────────────────
    def _rebuild_vault_list(self) -> None:
        child = self.vault_list.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self.vault_list.remove(child)
            child = nxt
        if self.vault is None:
            lab = Gtk.Label(xalign=0, label="Odblokuj sejf, żeby zobaczyć hasła.")
            lab.add_css_class("dim-label")
            self.vault_list.append(lab)
            return
        if not self.vault.entries:
            self.vault_list.append(Gtk.Label(xalign=0, label="Pusto — dodaj pierwsze hasło."))
            return
        for entry in self.vault.entries:
            self.vault_list.append(self._entry_row(entry))

    def _entry_row(self, entry: Entry) -> Gtk.Widget:
        row = Adw.ActionRow()
        row.set_title(entry.title)
        sub = entry.username
        if entry.url:
            sub = f"{sub}  ·  {entry.url}" if sub else entry.url
        row.set_subtitle(sub or ("hasło systemowe" if entry.system else ""))
        copy = Gtk.Button(label="Kopiuj")
        copy.set_valign(Gtk.Align.CENTER)
        copy.connect("clicked", lambda *_e, e=entry: self._copy(e.password, f"Skopiowano: {e.title}"))
        row.add_suffix(copy)
        if not entry.system:
            rm = Gtk.Button(label="Usuń")
            rm.set_valign(Gtk.Align.CENTER)
            rm.connect("clicked", lambda *_e, e=entry: self._delete_entry(e))
            row.add_suffix(rm)
        return row

    def _copy(self, text: str, toast: str) -> None:
        display = Gdk.Display.get_default()
        if display is None:
            return
        display.get_clipboard().set(text)
        self._toast(toast)
        GLib.timeout_add_seconds(30, lambda: display.get_clipboard().set("") or False)

    def _delete_entry(self, entry: Entry) -> None:
        if not self.vault or not self.vault_key:
            return
        self.vault.entries = [e for e in self.vault.entries if e.id != entry.id]
        self.vault.save(self.vault_key)
        self._rebuild_vault_list()

    def _add_entry_dialog(self) -> None:
        if not self.vault or not self.vault_key:
            self._toast("Najpierw odblokuj sejf.")
            return
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        title = Gtk.Entry(placeholder_text="Nazwa (GitHub, Discord, Wi‑Fi…)")
        user = Gtk.Entry(placeholder_text="Login")
        pw = Gtk.PasswordEntry()
        pw.set_show_peek_icon(True)
        url = Gtk.Entry(placeholder_text="URL (opcjonalnie)")
        for w in (title, user, pw, url):
            w.set_hexpand(True)
            box.append(w)
        dlg = Adw.AlertDialog()
        dlg.set_heading("Nowe hasło")
        dlg.set_extra_child(box)
        dlg.add_response("cancel", "Anuluj")
        dlg.add_response("ok", "Zapisz")
        dlg.set_default_response("ok")

        def on_resp(_d, response):
            if response != "ok" or not self.vault or not self.vault_key:
                return
            if not title.get_text().strip() or not pw.get_text():
                self._toast("Potrzebna nazwa i hasło.")
                return
            self.vault.entries.append(
                Entry.new(
                    title.get_text().strip(),
                    username=user.get_text().strip(),
                    password=pw.get_text(),
                    url=url.get_text().strip(),
                )
            )
            self.vault.save(self.vault_key)
            self._rebuild_vault_list()
            self._toast("Zapisano.")

        dlg.connect("response", on_resp)
        dlg.present(self)

    # ── PAM ──────────────────────────────────────────────────
    def _pam_apply(self) -> None:
        dlg = Adw.AlertDialog()
        dlg.set_heading("Włączyć logowanie kluczem?")
        dlg.set_body(
            "Zapiszę pam_u2f w /etc/pam.d/gdm-password i sudo.\n"
            "Kolejność: najpierw FIDO2 (10 s na tapnięcie), jak nie — zwykłe hasło.\n"
            "Kopia zapasowa PAM trafi do ~/.local/share/klucznik/pam-backup.\n\n"
            "pkexec zapyta o hasło administratora."
        )
        dlg.add_response("cancel", "Anuluj")
        dlg.add_response("ok", "Włącz")
        dlg.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(_d, response):
            if response != "ok":
                return
            self._sync_autostart()
            ok, msg = pamcfg.apply_with_pkexec()
            self._toast("PAM włączony." if ok else msg)
            self._refresh_status()

        dlg.connect("response", on_resp)
        dlg.present(self)

    def _pam_revert(self) -> None:
        ok, msg = pamcfg.revert_with_pkexec()
        self._toast("Przywrócono hasła PAM." if ok else msg)
        self._refresh_status()

    def _sync_autostart(self) -> None:
        exe = os.path.expanduser("~/.local/bin/klucznik")
        on = self.auto_unlock.get_active()
        pamcfg.write_autostart(f"{exe} --unlock-session", on)
        from . import brave_session

        brave_session.write_prepare_autostart(on)
