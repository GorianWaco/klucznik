#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "Odinstalowuję skróty Klucznika (sejf w ~/.local/share/klucznik zostawiam)."
if [[ -x "$HOME/.local/share/klucznik/klucznik-pam-install" ]]; then
  echo "Jeśli włączałeś logowanie kluczem, przywróć PAM z aplikacji albo:"
  echo "  pkexec $HOME/.local/share/klucznik/klucznik-pam-install revert $HOME/.local/share/klucznik/pam-backup"
fi
rm -f "$HOME/.local/bin/klucznik"
rm -f "$HOME/.local/share/applications/klucznik.desktop"
rm -f "$HOME/.local/share/icons/hicolor/scalable/apps/klucznik.svg"
rm -f "$HOME/.config/autostart/klucznik-unlock.desktop"
echo "Gotowe. Źródła: $ROOT"
