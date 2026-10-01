#!/usr/bin/env bash
# Klucznik — native (venv) instalacja dla użytkownika.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

APP_ID="pl.gorian.Klucznik"
NO_DEPS="${NO_DEPS:-0}"

echo "=========================================="
echo "  Klucznik 1.2.1"
echo "=========================================="

if [[ "$NO_DEPS" != "1" ]]; then
  if command -v pacman >/dev/null 2>&1; then
    if [[ "$(id -u)" -eq 0 ]]; then
      pacman -S --needed --noconfirm python python-gobject gtk4 libadwaita python-cairo
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
      sudo -n pacman -S --needed --noconfirm python python-gobject gtk4 libadwaita python-cairo
    else
      echo "GTK4/Adwaita powinny już być. pam-u2f doinstaluje się przy włączaniu logowania."
    fi
  fi
fi

echo "==> venv + python-fido2"
python3 -m venv --system-site-packages .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -r requirements.txt
python3 -c "from fido2.hid import CtapHidDevice; print('OK fido2, kluczy USB:', len(list(CtapHidDevice.list_devices())))"

mkdir -p "$HOME/.local/bin" \
  "$HOME/.local/share/applications" \
  "$HOME/.local/share/icons/hicolor/scalable/apps" \
  "$HOME/.local/share/klucznik"

install -m755 "$ROOT/share/klucznik-pam-install" "$HOME/.local/share/klucznik/klucznik-pam-install"

cat > "$HOME/.local/bin/klucznik" << EOF
#!/usr/bin/env bash
export PYTHONPATH="${ROOT}/src\${PYTHONPATH:+:\$PYTHONPATH}"
if [[ -f "${ROOT}/.venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT}/.venv/bin/activate"
fi
exec python3 -m klucznik "\$@"
EOF
chmod 755 "$HOME/.local/bin/klucznik"

install -m644 "$ROOT/data/klucznik.desktop" "$HOME/.local/share/applications/klucznik.desktop"
sed -i "s|^Exec=.*|Exec=${HOME}/.local/bin/klucznik|" "$HOME/.local/share/applications/klucznik.desktop"
install -m644 "$ROOT/icons/klucznik.svg" "$HOME/.local/share/icons/hicolor/scalable/apps/klucznik.svg"

if [[ -f "$HOME/.config/klucznik/device.json" ]]; then
  mkdir -p "$HOME/.config/autostart"
  cat > "$HOME/.config/autostart/klucznik-unlock.desktop" << AUTOSTART
[Desktop Entry]
Type=Application
Name=Klucznik — odblokuj sejf GNOME
Comment=Po logowaniu FIDO2 odblokowuje GNOME Keyring (Brave, YouTube, Wi‑Fi)
Exec=${HOME}/.local/bin/klucznik --unlock-session
OnlyShowIn=GNOME;
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=1
Hidden=false
NoDisplay=true
AUTOSTART
  cat > "$HOME/.config/autostart/klucznik-prepare-brave.desktop" << AUTOSTART
[Desktop Entry]
Type=Application
Name=Klucznik — sesja Brave
Comment=Przed startem Brave: przywróć karty, bez pytania o awarię
Exec=${HOME}/.local/bin/klucznik --prepare-brave
OnlyShowIn=GNOME;
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Phase=Initialization
X-GNOME-Autostart-Delay=0
Hidden=false
NoDisplay=true
AUTOSTART
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
fi

echo
echo "✓ Klucznik"
echo "  Uruchom:  klucznik"
echo "  Status:   klucznik --status"
echo "  Menu:     Klucznik"
echo
echo "1) Wepnij klucz FIDO2"
echo "2) Zarejestruj go w aplikacji (PIN klucza + tapnięcie)"
echo "3) Opcjonalnie włącz logowanie GDM/sudo — hasło zostaje jako zapas"
echo
