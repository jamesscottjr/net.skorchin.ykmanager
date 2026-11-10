# CI/CD for YK Manager

All pipelines run on GitHub Actions from `.github/workflows/`.

| Workflow | File | Trigger | Output |
|---|---|---|---|
| Android CI | `android-ci.yml` | push to `main`, pull requests, manual | debug APK, unit-test report (as workflow artifacts and a check) |
| Release build | `release.yml` | tag `v*`, manual | signed AAB + APK + SHA-256 sums attached to a GitHub Release; optional Play upload |
| Security scans | `security.yml` | push, PR, Mondays 12:30 UTC | OSV-Scanner SCA, Semgrep SAST, Android Lint report |
| Dependabot | `../dependabot.yml` | weekly | dependency and Actions update PRs (CI runs on each) |

## One-time setup: signing secrets

The release pipeline signs with the same upload keystore used locally (`keystore.jks`, alias `ykmanager`). Add these **repository secrets** under Settings → Secrets and variables → Actions:

| Secret | Value |
|---|---|
| `KEYSTORE_BASE64` | `base64 -w0 keystore.jks` |
| `KEYSTORE_PASSWORD` | keystore password |
| `KEY_ALIAS` | `ykmanager` |
| `KEY_PASSWORD` | key password |

With the GitHub CLI:

```bash
gh secret set KEYSTORE_BASE64   --body "$(base64 -w0 keystore.jks)"
gh secret set KEYSTORE_PASSWORD --body "<password>"
gh secret set KEY_ALIAS         --body ykmanager
gh secret set KEY_PASSWORD      --body "<password>"
```

`app/build.gradle.kts` reads `keystore.properties` locally and falls back to the `YK_KEYSTORE_FILE`, `YK_KEYSTORE_PASSWORD`, `YK_KEY_ALIAS`, `YK_KEY_PASSWORD` environment variables that the workflow exports. If neither exists the release variant is signed with the debug key; the release workflow fails a tagged build in that case (a manual dry run only warns).

## Cutting a release

1. Bump `versionCode` (must increase on every Play upload) and `versionName` in `app/build.gradle.kts`.
2. Add a `## vX.Y` section to `docs/RELEASE-NOTES.md` (optional; it becomes the release body).
3. Commit, then tag and push:

   ```bash
   git tag v2.28
   git push origin main v2.28
   ```

4. The **Release build** workflow verifies the tag equals `versionName`, builds, checks the signature and `applicationId`, and publishes a GitHub Release `v2.28` with:
   - `YKManager-v2.28-playstore.aab` – upload this to Play Console
   - `YKManager-v2.28-release.apk` – side-loadable APK
   - `YKManager-v2.28-SHA256SUMS.txt`

   Tags containing a hyphen (e.g. `v2.28-rc1`) are published as pre-releases.

A manual run (Actions → Release build → Run workflow) from any branch builds the same artifacts without creating a release unless *publish_release* is ticked.

## Optional: automatic Google Play upload

1. In Play Console create a service account with *Release manager* access to the app and download its JSON key.
2. Add the secret `PLAY_SERVICE_ACCOUNT_JSON` (full JSON) — ideally in an environment named `google-play` so you can require manual approval.
3. Either set the repository **variable** `PLAY_TRACK` (`internal`, `alpha`, `beta` or `production`) to upload on every tag, or pick the track in the manual run form.

Uploads are created in **draft** status so nothing goes live without a review in Play Console. The first upload of a brand-new app still has to be done by hand in Play Console; after that the API works.

## Build environment

- `ubuntu-latest` runner with Temurin JDK 17 and the pre-installed Android SDK (AGP downloads platform 36 / build-tools on demand).
- Gradle wrapper 8.14.2, validated by `gradle/actions/setup-gradle` (`validate-wrappers: true`); build cache is written only from `main`.
- The release runtime classpath is locked (`app/gradle.lockfile`), so CI builds exactly what was scanned.
