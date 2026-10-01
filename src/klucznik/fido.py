from __future__ import annotations

import base64
import json
import os
import pwd
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from . import ORIGIN, RP_ID
from .paths import DATA_DIR, DEVICE_FILE, U2F_KEYS, ensure_dirs

PinCallback = Callable[[], str | None]
TouchCallback = Callable[[], None]


class FidoError(Exception):
    pass


@dataclass
class HidKey:
    path: str
    product: str
    vid: int
    pid: int


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def log(msg: str) -> None:
    ensure_dirs()
    path = DATA_DIR / "klucznik.log"
    line = f"{datetime.now().isoformat(timespec='seconds')} {msg}\n"
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def format_error(exc: BaseException) -> str:
    try:
        from fido2.client import ClientError, PinRequiredError
        from fido2.ctap import CtapError
    except ImportError:
        ClientError = PinRequiredError = CtapError = tuple()  # type: ignore

    cause = getattr(exc, "cause", None) or exc
    if CtapError and isinstance(cause, CtapError):
        code = getattr(cause, "code", None)
        names = {
            0x22: "Za długo — nie zdążyłeś dotknąć klucza.",
            0x27: "Klucz odrzucił operację. Dotknij przycisku na kluczu, gdy miga.",
            0x2E: "Ten klucz nie obsługuje hmac-secret przy tej operacji.",
            0x31: "Zły PIN klucza FIDO2.",
            0x32: "PIN zablokowany na chwilę — wyjmij klucz z USB i wetknij znowu.",
            0x33: "Za dużo złych PIN-ów. Wyjmij i wetknij klucz.",
            0x34: "PIN trwale zablokowany. Trzeba zresetować klucz.",
            0x35: "PIN jest wymagany.",
            0x36: "PIN nie jest ustawiony na kluczu.",
        }
        if code in names:
            return names[code]
        return f"Błąd klucza FIDO2: {cause}"
    if PinRequiredError and isinstance(exc, PinRequiredError):
        return "Klucz wymaga PIN-u — wpisz PIN samego klucza USB."
    if ClientError and isinstance(exc, ClientError):
        if cause is not exc:
            return format_error(cause)
        return f"FIDO2: {exc}"
    text = str(exc).strip() or exc.__class__.__name__
    return text


def list_keys() -> list[HidKey]:
    try:
        from fido2.hid import CtapHidDevice
    except ImportError as exc:
        raise FidoError("Brak biblioteki python-fido2. Uruchom install.sh.") from exc
    out: list[HidKey] = []
    for dev in CtapHidDevice.list_devices():
        desc = dev.descriptor
        out.append(
            HidKey(
                path=str(desc.path),
                product=desc.product_name or "Klucz FIDO2",
                vid=int(desc.vid),
                pid=int(desc.pid),
            )
        )
    return out


class _Interaction:
    def __init__(self, ask_pin: PinCallback, on_touch: TouchCallback | None = None):
        from fido2.client import UserInteraction

        class Impl(UserInteraction):
            def prompt_up(self_inner) -> None:
                log("FIDO: czekam na dotknięcie klucza")
                if on_touch:
                    on_touch()

            def request_pin(self_inner, permissions, rp_id) -> str | None:
                log(f"FIDO: prośba o PIN (rp={rp_id})")
                pin = ask_pin()
                if not pin:
                    raise FidoError("Nie wpisano PIN-u klucza FIDO2.")
                return pin

            def request_uv(self_inner, permissions, rp_id) -> bool:
                return True

        self.impl = Impl()


def _open_client(ask_pin: PinCallback, on_touch: TouchCallback | None = None):
    from fido2.client import DefaultClientDataCollector, Fido2Client
    from fido2.ctap2.extensions import HmacSecretExtension
    from fido2.hid import CtapHidDevice

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise FidoError("Nie widzę klucza FIDO2. Wepnij go do USB.")
    last_err: BaseException | None = None
    for dev in devices:
        try:
            client = Fido2Client(
                dev,
                client_data_collector=DefaultClientDataCollector(ORIGIN),
                user_interaction=_Interaction(ask_pin, on_touch).impl,
                # Tylko hmac-secret — inne rozszerzenia (credProtect) wywalają ExcelSecu.
                extensions=[HmacSecretExtension(allow_hmac_secret=True)],
            )
            exts = list(client.info.extensions or [])
            log(f"FIDO: {dev.product_name} extensions={exts}")
            if "hmac-secret" not in exts:
                last_err = FidoError(f"{dev.product_name} nie ma hmac-secret")
                continue
            return client, dev
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            log("FIDO: nie otworzyłem " + getattr(dev, "product_name", "?") + ": " + format_error(exc))
    raise FidoError(format_error(last_err) if last_err else "Brak klucza FIDO2 z hmac-secret.")


def _es256_uncompressed(cose_key) -> bytes:
    x = cose_key[-2]
    y = cose_key[-3]
    if len(x) != 32 or len(y) != 32:
        raise FidoError("Klucz nie jest ES256 — pam_u2f tego nie weźmie.")
    return b"\x04" + x + y


def _username() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER") or "user"


def load_device() -> dict | None:
    if not DEVICE_FILE.is_file():
        return None
    return json.loads(DEVICE_FILE.read_text(encoding="utf-8"))


def save_device(data: dict) -> None:
    ensure_dirs()
    DEVICE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(DEVICE_FILE, 0o600)
    line = data.get("pam_u2f_line")
    if line:
        U2F_KEYS.write_text(line + "\n", encoding="utf-8")
        os.chmod(U2F_KEYS, 0o600)


def _hmac_from_ext(ext) -> bytes | None:
    if ext is None:
        return None
    got = getattr(ext, "hmac_get_secret", None)
    if got is None and hasattr(ext, "get"):
        got = ext.get("hmacGetSecret")
    if got is None:
        return None
    output1 = getattr(got, "output1", None)
    if output1 is None and isinstance(got, dict):
        output1 = got.get("output1")
    if not output1:
        return None
    if isinstance(output1, str):
        pad = "=" * ((4 - len(output1) % 4) % 4)
        return base64.urlsafe_b64decode(output1 + pad)
    return bytes(output1)


def _assert_hmac(client, credential_id: bytes, salt: bytes) -> bytes:
    request_options = {
        "rpId": RP_ID,
        "challenge": os.urandom(32),
        "allowCredentials": [{"type": "public-key", "id": credential_id}],
        "userVerification": "discouraged",
        "extensions": {"hmacGetSecret": {"salt1": salt}},
        "timeout": 60_000,
    }
    log("FIDO: get_assertion hmac-secret")
    selection = client.get_assertion(request_options)
    assertion = selection.get_response(0)
    secret = _hmac_from_ext(assertion.client_extension_results)
    if not secret:
        log(f"FIDO: brak hmac w odpowiedzi: {assertion.client_extension_results!r}")
        raise FidoError(
            "Klucz nie zwrócił hmac-secret. Dotknij przycisku na kluczu, gdy miga."
        )
    return secret


def enroll(ask_pin: PinCallback, on_touch: TouchCallback | None = None) -> tuple[bytes, dict]:
    """Rejestruje credential z hmac-secret. Zwraca (hmac_secret, device_meta)."""
    try:
        client, dev = _open_client(ask_pin, on_touch)
        user = _username()
        from fido2.server import Fido2Server

        server = Fido2Server({"id": RP_ID, "name": "Klucznik"}, attestation="none")
        user_ent = {"id": os.urandom(16), "name": user, "displayName": user}
        create_options, _state = server.register_begin(
            user_ent,
            resident_key_requirement="discouraged",
            user_verification="discouraged",
            authenticator_attachment="cross-platform",
        )
        options = {
            **create_options["publicKey"],
            # Tanie klucze (ExcelSecu) padają na długiej liście algorytmów.
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "extensions": {"hmacCreateSecret": True},
            "timeout": 60_000,
        }
        log("FIDO: make_credential start")
        result = client.make_credential(options)
        att = result.response.attestation_object
        cred = att.auth_data.credential_data
        if cred is None:
            raise FidoError("Klucz nie zwrócił credential_id.")
        ext = result.client_extension_results or {}
        hmac_on = False
        if hasattr(ext, "get"):
            hmac_on = bool(ext.get("hmacCreateSecret"))
        log(f"FIDO: credential ok, hmacCreateSecret={hmac_on} ext={ext!r}")

        salt = os.urandom(32)
        secret = _assert_hmac(client, cred.credential_id, salt)
        pk = _es256_uncompressed(cred.public_key)
        pam_line = f"{user}:{_b64(cred.credential_id)},{_b64(pk)},es256,+presence"
        desc = dev.descriptor
        meta = {
            "username": user,
            "credential_id": _b64(cred.credential_id),
            "user_id": _b64(bytes(user_ent["id"])),
            "hmac_salt": _b64(salt),
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "product": desc.product_name,
            "vid": desc.vid,
            "pid": desc.pid,
            "path": str(desc.path),
            "pam_u2f_line": pam_line,
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
        }
        save_device(meta)
        log("FIDO: rejestracja zapisana")
        return secret, meta
    except FidoError:
        raise
    except Exception as exc:  # noqa: BLE001
        log("FIDO enroll crash:\n" + traceback.format_exc())
        raise FidoError(format_error(exc)) from exc


def get_hmac_secret(
    credential_id: bytes | None = None,
    salt: bytes | None = None,
    ask_pin: PinCallback | None = None,
    on_touch: TouchCallback | None = None,
    client=None,
) -> bytes:
    meta = load_device()
    if credential_id is None:
        if not meta:
            raise FidoError("Najpierw zarejestruj klucz w Kluczniku.")
        credential_id = _unb64(meta["credential_id"])
    if salt is None:
        if not meta:
            raise FidoError("Brak soli hmac-secret.")
        salt = _unb64(meta["hmac_salt"])
    if ask_pin is None and client is None:
        raise FidoError("Potrzebny PIN klucza FIDO2.")
    try:
        if client is None:
            client, _dev = _open_client(ask_pin, on_touch)
        return _assert_hmac(client, bytes(credential_id), bytes(salt))
    except FidoError:
        raise
    except Exception as exc:  # noqa: BLE001
        log("FIDO assert crash:\n" + traceback.format_exc())
        raise FidoError(format_error(exc)) from exc
