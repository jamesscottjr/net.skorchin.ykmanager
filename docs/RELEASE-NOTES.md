# Release notes

Each `## vX.Y` section is copied into the GitHub Release body by `.github/workflows/release.yml`.

## v2.31 (versionCode 33)

- OTP slots → OTP decoder: decrypt a Yubico OTP with the slot's AES key to see the private ID,
  usage and session counters, timer and random field; the checksum confirms the key is right
- Capture the OTP by touching the key (USB), Read over NFC, or paste an OTP or my.yubico.com link
- Optional expected private ID check; serial number shown when the public ID is serial-based
- Runs entirely on the phone; the key and results are never stored

## v2.30 (versionCode 32)

- Show NFC output: static passwords are now decoded correctly. Scan codes for digits 3–0,
  space, Tab, Enter and most punctuation are also printable bytes (some equal '#', '/', '='),
  so passwords containing them were split from the prefix in the wrong place and shown garbled
- The prefix is matched exactly when it is Yubico's default or one this app wrote; otherwise
  a stricter check is used
- Backslash and pipe are programmed with the standard US scan code (0x31); passwords
  written by older versions (0x32) still decode correctly
- The dialog lists the raw scan codes so the translation can be checked

## v2.29 (versionCode 31)

- Settings → OTP output: the Settings tab of the Windows YubiKey Personalization Tool —
  Tab before/after first part/after OTP, Enter, 0.5 s delays, output speed throttling
  (10/20/30 ms pacing), numeric keypad, fast trigger, send reference string, serial number
  visibility (button at startup, USB descriptor, API), invert LED and allow update
- Live preview of what a touch types; settings apply to every Yubico OTP, OATH-HOTP and static
  password slot the app programs
- OTP slots: "Update settings" rewrites a programmed keyboard slot's output settings without
  replacing its credential (requires Allow update, firmware 2.3+)
- Recipes: each slot step stores the output settings in effect when it was added
- Toolchain: AGP 9.5.1 with built-in Kotlin, Gradle 9.9, Compose BOM 2026.09, compileSdk 37
  (targetSdk stays 36); YubiKit 3.1.0 → 3.3.0 (new "FIDO over smart card" capability shown)

## v2.28 (versionCode 30)

- Passkeys: tap a passkey to see everything the YubiKey stores about it — relying party
  (ID, name, RP ID hash), user account (name, display name, user handle in hex/base64url/text),
  credential ID (hex and WebAuthn base64url), transports, credProtect policy, large-blob key
  presence, and the public key (algorithm, curve, coordinates, SHA-256 fingerprint)
- Each value can be copied individually or all at once; delete is available from the details view
- Credential enumeration now reads the full CTAP 2.1 response (credProtect, largeBlobKey)
- Dependency updates merged via Dependabot: Kotlin 2.4.21, coroutines 1.11.0, GitHub Actions

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
