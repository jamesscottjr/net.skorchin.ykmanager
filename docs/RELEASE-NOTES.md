# Release notes

Each `## vX.Y` section is copied into the GitHub Release body by `.github/workflows/release.yml`.

## v2.27 (versionCode 29)

- Security review: SCA (OSV), SAST (Semgrep) and Android Lint; see `docs/SECURITY-REVIEW.md`
- Bouncy Castle 1.78.1 → 1.86 (7 advisories closed); dependency lockfile added
- Backup/device-transfer exclusion rules for the encrypted OATH key store
- Copied codes and passwords are marked sensitive on the clipboard
- NFC "open link" accepts only http(s) URLs
- GitHub Actions: security scans, Dependabot, CI and release pipelines

## v2.26 (versionCode 28)

- NFC taps no longer leave YK Manager for the system NDEF handler
- Slots: "Show NFC output" and an opt-in switch to let the phone handle taps

## v2.25 (versionCode 27)

- "Remember on this phone" for OATH passwords now persists (Android Keystore, AES-GCM)
- "Forget password" button; remembered keys survive key removal

## v2.24 (versionCode 26)

- "QR from image" import fixed; clearer error messages

## v2.23 (versionCode 25)

- Static passwords delivered over NDEF are decoded from HID scan codes

## v2.22 (versionCode 24)

- QR scanning via the Google code scanner with ZXing fallback
- Import from Google Authenticator export QR codes
