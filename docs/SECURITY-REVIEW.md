# YK Manager – security review and scan results

Version reviewed: **2.27 (versionCode 29)**, commit on `main`, 2026-11-10.
Scope: the Android app in this repository (`app/`). Reviewer: automated scans
plus a manual read-through of the security-relevant code paths, performed by
Perplexity Computer at the request of the project owner. This is **not** an
independent third-party audit or a penetration test.

## Summary

| Area | Tool / method | Result |
|---|---|---|
| Software composition analysis (SCA) | OSV.dev query of all 137 artifacts on the locked release runtime classpath (`app/gradle.lockfile`) | **Before:** Bouncy Castle 1.78.1 had 7 advisories (CVE-2025-8916, CVE-2025-14813, CVE-2026-0636, CVE-2026-5588, CVE-2026-5598, CVE-2026-8763, CVE-2026-13506). **After upgrading to 1.86: 0 known advisories.** |
| Static analysis (SAST) | Semgrep rulesets `p/kotlin`, `p/secrets`, `p/mobsfscan` on `app/src/main` | 5 findings, all reviewed as expected behaviour and annotated in code (see below); 0 secrets. |
| Android Lint | `./gradlew :app:lintRelease` (54 issues total) | 2 security-category warnings: `DataExtractionRules` (fixed: backup/transfer rules added) and `TrustAllX509TrustManager` inside the Bouncy Castle jar (library code for EST enrolment, not used by the app). No errors. |
| Manual review | Read-through of manifest, intent handling, NFC/NDEF parsing, QR/import parsing, secret storage, clipboard, network, passkey provider | 3 hardenings applied (below); residual items listed at the end. |

## Changes made as a result (v2.27)

1. **Bouncy Castle 1.78.1 → 1.86** (`bcprov`, `bcpkix`; `bcutil` follows). Clears all SCA findings.
2. **Backup / device transfer rules**: `android:fullBackupContent` and `android:dataExtractionRules` now exclude all app data (shared preferences incl. the encrypted OATH keys, files, databases) from cloud backup and device-to-device transfer, in addition to `allowBackup="false"`.
3. **Clipboard**: every copy (OTP codes, static passwords, NDEF output, exported values) is flagged `ClipDescription.EXTRA_IS_SENSITIVE`, so Android 13+ hides the value in the clipboard preview overlay.
4. **NFC "open link" action** only launches `http`/`https` URIs. A crafted tag could previously have supplied another scheme to `ACTION_VIEW`.
5. **Dependency locking** for the release runtime classpath (`app/gradle.lockfile`) so SCA results are reproducible and match what ships.
6. **Continuous scanning**: `.github/workflows/security.yml` runs OSV-Scanner (SCA), Semgrep (SAST) and Android Lint on every push/PR and weekly; `.github/dependabot.yml` opens update PRs for Gradle dependencies and GitHub Actions weekly. Dependabot vulnerability alerts should also be switched on in the repository settings (Settings → Advanced Security) by the owner.

## Semgrep findings and disposition

| Rule | Location | Disposition |
|---|---|---|
| `android_kotlin_sha1` | `OathFeature.accessKey` | Expected. HMAC-SHA1 is mandated by the YubiKey OATH protocol (YKOATH VALIDATE challenge). Annotated with `nosemgrep` and a comment. |
| `android_kotlin_pending_intent_not_immutable` (×2) | `YubiKeyPasskeyService` | Expected. Credential Manager requires a mutable PendingIntent to attach the provider request; the intent is explicit (own activity) and unique per entry, per Android's documented pattern. Annotated. |
| `android_kotlin_logging` (×2) | `AccessKeyStore` | Logs the OATH device ID (a public identifier) and an exception when a remembered key cannot be read or written. No key material or passwords are logged anywhere in the app. Annotated. |

## Manual review notes

**Attack surface / components**
- `MainActivity` is exported (launcher; NDEF intent filters for `my.yubico.com`). NFC tags arriving via intent are handled exactly like reader-mode taps; nothing from the tag is trusted beyond a bounds-checked NDEF parse.
- `YubiKeyPasskeyService` is exported but protected by `android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE` (system-only). `PasskeyActivity` is not exported. No content providers or broadcast receivers.
- Permissions: `NFC`, `CAMERA` (only the ZXing fallback scanner; the Google code scanner needs none), `INTERNET` (passkey provider only), `READ_USER_DICTIONARY` (declared because Chrome checks for it to detect a third-party passkey provider; the app never reads the dictionary).

**Secrets and local data**
- Remembered OATH passwords are stored as the protocol's derived key, encrypted with a 256-bit AES-GCM key held in the Android Keystore (`AccessKeyStore`); never the password itself. Removable via "Forget password", "Remove password", OATH reset, or uninstall.
- Slot programming secrets (Yubico OTP keys, static passwords, HMAC secrets) are sent to the key and discarded; only non-secret metadata is persisted.
- No analytics, crash reporting, or logging of credential material. Release build is not debuggable.

**Parsers of untrusted input**
- `NdefReader`: record header/length fields are bounds-checked; truncated records raise `IOException`. Static-password scan-code translation operates on a byte table with range checks.
- `QrCodes`: images are decoded on-device; the Google Authenticator export parser is a minimal protobuf reader with explicit truncation checks; resulting URIs are still validated by YubiKit's `CredentialData.parseUri` before anything is written to the key.
- Device/application responses are parsed by YubiKit 3.3.0 (Yubico's library) and, for OpenPGP, by a tolerant reader in `OpenPgpFeature` that converts parse failures into user-facing errors.

**Network**
- Only `passkey/CallerVerifier` uses the network: HTTPS GET of a relying party's `/.well-known/assetlinks.json` and Google's privileged-browser list on `gstatic.com`, with 8 s timeouts, redirects disabled (as the Asset Links spec requires), an 8 KB/response cap, system CA trust, and caching. Cleartext traffic is blocked by platform default (targetSdk 36).

**Build**
- Signed release with a dedicated keystore kept outside the repository (`keystore.properties` is git-ignored). R8/ProGuard minification is off (no obfuscation; this is a transparency trade-off, not a vulnerability).

## Residual items / recommendations

- **Independent review**: this was a tool-assisted self-review. Before relying on the app for high-value credentials, an external security review of the passkey provider (`passkey/`) and of the FIDO PIN/UV handling is advisable.
- **YubiKit 3.1.0 → 3.3.0**: done in v2.29 (no known advisories; adds the FIDO-over-CCID capability). A hardware regression pass on real keys is still recommended.
- **Unit tests** exist for the passkey package only. Adding tests for `NdefReader.parse`, `ScanCodes.decode` and the `otpauth-migration` parser would guard the untrusted-input paths.
- **Clipboard**: copied codes stay on the clipboard until replaced; a timed clear (e.g. 30–60 s) could be added.
- Re-run the scans on every release (the GitHub workflow does this automatically) and review Dependabot alerts.

## How to reproduce the scans locally

```bash
# SCA – refresh the lockfile, then query OSV
./gradlew :app:dependencies --configuration releaseRuntimeClasspath --write-locks
osv-scanner --lockfile=app/gradle.lockfile          # or use the GitHub workflow

# SAST
pip install semgrep
semgrep scan --config p/kotlin --config p/secrets --config p/mobsfscan app/src/main

# Android Lint
./gradlew :app:lintRelease   # report in app/build/reports/lint-results-release.html
```
