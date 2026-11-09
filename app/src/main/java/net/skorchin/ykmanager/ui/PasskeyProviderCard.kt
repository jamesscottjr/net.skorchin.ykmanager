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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.credentials.CredentialManager
import androidx.lifecycle.compose.LifecycleResumeEffect
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

    LifecycleResumeEffect(Unit) {
        enabled = isPasskeyProviderEnabled(context)
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
        Spacer(Modifier.height(4.dp))
        Hint("Chrome: Settings > Autofill services > \"Autofill using another service\", then restart Chrome.")

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
            if (logCount == 0) "The last 15 passkey requests will be listed here: what the site asked for and what was sent back. " +
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

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 2.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
