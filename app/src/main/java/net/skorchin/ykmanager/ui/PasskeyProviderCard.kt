package net.skorchin.ykmanager.ui

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.credentials.CredentialManager
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import kotlinx.coroutines.launch
import net.skorchin.ykmanager.passkey.PASSKEY_SELF_TEST_OK
import net.skorchin.ykmanager.passkey.PASSKEY_SELF_TEST_RP_ID
import net.skorchin.ykmanager.passkey.PasskeyStore
import net.skorchin.ykmanager.passkey.YubiKeyPasskeyService

/** Whether YK Manager is currently an enabled passkey provider (Android 14+). */
fun isPasskeyProviderEnabled(context: Context): Boolean? {
    if (Build.VERSION.SDK_INT < 34) return null
    val cm = context.getSystemService(android.credentials.CredentialManager::class.java) ?: return null
    return runCatching {
        cm.isEnabledCredentialProviderService(ComponentName(context, YubiKeyPasskeyService::class.java))
    }.getOrNull()
}

private fun openProviderSettings(context: Context) {
    if (Build.VERSION.SDK_INT >= 34) {
        val ok = runCatching {
            CredentialManager.create(context).createSettingsPendingIntent().send()
        }.isSuccess
        if (ok) return
    }
    runCatching {
        context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

/**
 * Card on the Passkeys screen: turn YK Manager on as the phone's passkey
 * provider so sign-ins in browsers and apps go straight to the YubiKey.
 */
@Composable
fun PasskeyProviderCard() {
    val context = LocalContext.current
    val store = remember { PasskeyStore(context) }
    var enabled by remember { mutableStateOf(isPasskeyProviderEnabled(context)) }
    var askPinFirst by remember { mutableStateOf(store.askPinFirst) }
    var remember by remember { mutableStateOf(store.rememberAccounts) }
    var remembered by remember { mutableIntStateOf(store.accounts().size) }
    var logCount by remember { mutableIntStateOf(store.logCount()) }
    var showLog by remember { mutableStateOf(false) }
    var chrome by remember { mutableStateOf(BrowserPasskeySetup.status(context)) }
    var testResult by remember { mutableStateOf<String?>(null) }
    var testing by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LifecycleResumeEffect(Unit) {
        enabled = isPasskeyProviderEnabled(context)
        chrome = BrowserPasskeySetup.status(context)
        remembered = store.accounts().size
        logCount = store.logCount()
        onPauseOrDispose { }
    }

    SectionCard {
        SectionTitle("Use YubiKey for passkeys on this phone")
        Spacer(Modifier.height(4.dp))
        if (Build.VERSION.SDK_INT < 34) {
            Hint("Needs Android 14 or newer. On this version, sign-ins use Android's built-in security key support.")
            return@SectionCard
        }
        Hint(
            "Android's built-in security key support often can't use a PIN or stored passkeys over NFC. " +
                "With YK Manager as a passkey provider, the YubiKey shows up in the passkey sheet of Chrome, " +
                "other browsers and apps, and YK Manager handles the tap, PIN, fingerprint and account choice."
        )
        Spacer(Modifier.height(4.dp))
        InfoRow("Status", when (enabled) { true -> "On"; false -> "Off"; null -> "Unknown" })
        Spacer(Modifier.height(4.dp))
        ButtonRow {
            SmallButton(if (enabled == true) "Provider settings" else "Turn on") { openProviderSettings(context) }
        }
        if (enabled != true) {
            Hint("In the list that opens, switch on \"YubiKey (YK Manager)\". Some phones call it Additional services.")
        }
        Spacer(Modifier.height(8.dp))
        if (chrome.isEmpty()) {
            Hint("Chrome: Settings > Autofill services > \"Autofill using another service\", then restart Chrome.")
        }
        chrome.forEach { st ->
            InfoRow(st.browser.label, when (st.usesAnotherService) {
                true -> "Uses another service (good)"
                false -> "Google Password Manager only"
                null -> "Unknown (update Chrome)"
            })
            if (st.usesAnotherService != true) {
                Hint("${st.browser.label} won't show YK Manager until you pick \"Autofill using another service\" " +
                    "under Settings > Autofill services, then restart ${st.browser.label}. Clearing Chrome's data resets this.")
                ButtonRow {
                    SmallButton("Open ${st.browser.label} setting") {
                        BrowserPasskeySetup.openChromeSettings(context, st.browser.packageName)
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        SectionTitle("Test")
        Hint("Opens Android's passkey sheet with a test request. If YK Manager is set up, a \"YK Manager test\" entry appears.")
        ButtonRow {
            SmallButton(if (testing) "Testing..." else "Test passkey sheet", enabled = !testing) {
                val activity = context.findActivity() ?: return@SmallButton
                testing = true; testResult = null
                val started = System.currentTimeMillis()
                scope.launch {
                    val outcome: String = try {
                        CredentialManager.create(activity).getCredential(activity, GetCredentialRequest(listOf(
                            GetPublicKeyCredentialOption(selfTestRequestJson())
                        )))
                        "Unexpected answer from the sheet."
                    } catch (e: GetCredentialException) {
                        val asked = store.asked().any {
                            it.optString("site") == PASSKEY_SELF_TEST_RP_ID &&
                                runCatching { java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
                                    .parse(it.optString("time"))!!.time >= started - 2_000 }.getOrDefault(false)
                        }
                        when {
                            e.errorMessage?.toString()?.contains(PASSKEY_SELF_TEST_OK) == true ->
                                "Working: Android showed YK Manager and you picked it. If a site still doesn't list it, the browser is the cause (see the Chrome setting above)."
                            asked && e is GetCredentialCancellationException ->
                                "Working: Android asked YK Manager and showed it. The sheet was closed before picking the test entry."
                            asked ->
                                "Android asked YK Manager, but the sheet did not open (${e.type}). Copy the log below and share it."
                            e is NoCredentialException || !asked ->
                                "Not working: Android never asked YK Manager. Turn it on with the button above (as the preferred or an additional service), then try again."
                            else -> "Test failed: ${e.type}"
                        }
                    }
                    testResult = outcome; testing = false; logCount = store.logCount()
                }
            }
        }
        testResult?.let { Hint(it) }

        Spacer(Modifier.height(8.dp))
        ToggleRow("Ask for the PIN before the NFC tap", askPinFirst) {
            askPinFirst = it; store.askPinFirst = it
        }
        Hint("Enter the PIN first and a single tap is enough.")
        ToggleRow("Remember accounts in the passkey sheet", remember) {
            remember = it; store.rememberAccounts = it; remembered = store.accounts().size
        }
        Hint("Only the site and user name are kept on this phone; passkeys stay on the YubiKey.")
        if (remembered > 0) {
            ButtonRow {
                SmallButton("Forget $remembered remembered ${if (remembered == 1) "account" else "accounts"}") {
                    store.clearAccounts(); remembered = 0
                }
            }
        }

        Spacer(Modifier.height(8.dp))
        SectionTitle("Diagnostics")
        Hint(
            if (logCount == 0) "Each time Android asks YK Manager for a passkey, and the last 15 sign-ins (what the site asked for and what was sent back), are listed here. " +
                "No PINs, challenges, signatures or keys are recorded."
            else "$logCount recent passkey ${if (logCount == 1) "request" else "requests"} recorded. " +
                "If a site rejects a sign-in, copy this and share it so the cause can be found. No PINs, signatures or keys are included."
        )
        if (logCount > 0) {
            ButtonRow {
                SmallButton("Copy log") {
                    val cm = context.getSystemService(android.content.ClipboardManager::class.java)
                    cm?.setPrimaryClip(android.content.ClipData.newPlainText("YK Manager passkey log", store.logText()))
                }
                SmallButton(if (showLog) "Hide" else "Show") { showLog = !showLog }
                SmallButton("Clear") { store.clearLog(); logCount = 0; showLog = false }
            }
            if (showLog) {
                Text(store.logText(), style = MaterialTheme.typography.bodySmall.copy(fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace))
            }
        }
    }
}

private fun selfTestRequestJson(): String {
    val challenge = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
    val b64 = android.util.Base64.encodeToString(challenge,
        android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
    return org.json.JSONObject()
        .put("challenge", b64)
        .put("rpId", PASSKEY_SELF_TEST_RP_ID)
        .put("allowCredentials", org.json.JSONArray())
        .put("userVerification", "discouraged")
        .put("timeout", 60_000)
        .toString()
}

private fun Context.findActivity(): android.app.Activity? {
    var c: Context? = this
    while (c is android.content.ContextWrapper) {
        if (c is android.app.Activity) return c
        c = c.baseContext
    }
    return null
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 2.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
