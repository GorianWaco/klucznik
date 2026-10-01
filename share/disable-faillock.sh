#!/usr/bin/env bash
# Wyłącza pam_faillock (blokada konta po złych hasłach, domyślnie 10 min).
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Potrzebny root (pkexec)." >&2
  exit 1
fi

CONF=/etc/security/faillock.conf
TS="$(date -Iseconds)"
cp -a "$CONF" "${CONF}.bak-klucznik-${TS}"

# Usuń poprzedni blok Klucznika, dopisz deny = 0 na końcu.
tmp="$(mktemp)"
awk '
  BEGIN { skip=0 }
  /^# --- klucznik faillock ---/ { skip=1; next }
  skip && /^deny = 0/ { skip=0; next }
  skip { next }
  { print }
' "$CONF" > "$tmp"
cat >> "$tmp" <<'EOF'

# --- klucznik faillock ---
# Blokada po błędnych hasłach wyłączona (było: 3 próby / 10 minut).
deny = 0
EOF

chmod --reference="$CONF" "$tmp" 2>/dev/null || chmod 644 "$tmp"
mv "$tmp" "$CONF"

# Zdejmij aktualne blokady
faillock --reset 2>/dev/null || true
faillock --user gorian --reset 2>/dev/null || true
faillock --user root --reset 2>/dev/null || true
rm -f /run/faillock/* /var/run/faillock/* 2>/dev/null || true

echo "OK: deny=0 w $CONF, liczniki wyzerowane."
grep -n '^deny' "$CONF" || true
