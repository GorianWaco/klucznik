# Klucznik

Logowanie do systemu i hasła — **tapnięcie klucza FIDO2 na USB** zamiast wpisywania.

Działa z ExcelSecu, YubiKey, Nitrokey i innymi FIDO2 z rozszerzeniem `hmac-secret`.

## Co robi

- Wykrywa klucz FIDO2 na USB
- Rejestruje credential z **hmac-secret** — z tego powstaje klucz AES sejfu
- Sejf haseł (logowanie Linuksa + Twoje wpisy)
- Po tapnięciu odblokowuje **GNOME Keyring** (Brave, YouTube, Wi‑Fi) w już działającym daemonie — bez wpisywania hasła w oknie „Authentication required”
- Zapisuje w sejfie **Brave Safe Storage** (i inne wpisy logowania GNOME). Po restarcie odtwarza je i w razie potrzeby restartuje Brave, żeby sesja YouTube wróciła sama
- Brave **przywraca poprzednie karty bez pytania** („Continue where you left off”, bez okna Restore pages)
- Opcjonalnie **GDM i sudo** przez `pam_u2f` (hasło uniksowe zostaje jako zapas, 10 s)

Bez fizycznego klucza plik sejfu jest bezużyteczny.

## Instalacja

```bash
cd ~/Projekty/klucznik
./install.sh
klucznik
```

## Pierwsze uruchomienie

1. Wepnij klucz FIDO2
2. **Zarejestruj klucz** — PIN samego klucza USB, tapnięcie, raz hasło do Linuksa
3. Opcjonalnie **Włącz logowanie kluczem** (pkexec zapyta o hasło admina)
4. Na ekranie logowania: wepnij klucz i tapnij. Jak nie zdążysz w 10 s — wpisz hasło jak zawsze
5. Po zalogowaniu Klucznik poprosi o **ponowne tapnięcie** (nie o hasło Linuksa) i sam odblokuje sejf GNOME. Okna „Authentication required” nie wypełniaj — Anuluj albo poczekaj na Klucznika.
6. **Raz**, gdy sejf GNOME jest już odblokowany, otwórz Klucznika i tapnij klucz — zapisze hasło Brave. Od następnego restartu wystarczy tapnięcie po zalogowaniu.

## Bezpieczeństwo

- PAM jest `sufficient`, nigdy `required` — bez klucza nadal wejdziesz hasłem
- Kopia `/etc/pam.d/gdm-password` i `sudo` ląduje w `~/.local/share/klucznik/pam-backup`
- PIN FIDO2 nie jest zapisywany na dysku
- Sejf: AES-256-GCM, katalogi `0700`

## Odinstalowanie logowania kluczem

W aplikacji: **Wyłącz (przywróć PAM)** albo:

```bash
pkexec ~/.local/share/klucznik/klucznik-pam-install revert ~/.local/share/klucznik/pam-backup
```
