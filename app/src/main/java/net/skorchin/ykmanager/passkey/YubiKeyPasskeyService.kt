package net.skorchin.ykmanager.passkey

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.Uri
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import net.skorchin.ykmanager.R
import org.json.JSONObject
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

/**
 * Makes YK Manager a passkey provider in Android's Credential Manager
 * (Settings > Passwords, passkeys & accounts), Android 14+.
 *
 * Android's built-in security-key path is limited (no PIN or discoverable
 * passkeys over NFC on many devices, double PIN prompts over USB, sites
 * that only offer the phone's own passkey). As a provider, YK Manager gets
 * the request itself and talks CTAP2 to the YubiKey directly over NFC or
 * USB, including PIN, fingerprint (Bio) and multiple accounts per site.
 *
 * This service only answers "what can you offer?" quickly, without
 * touching the key. The real work happens in [PasskeyActivity] once the
 * user picks a YubiKey entry.
 */
@RequiresApi(34)
class YubiKeyPasskeyService : CredentialProviderService() {

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onResult(BeginCreateCredentialResponse())
            return
        }
        val entry = CreateEntry.Builder("YubiKey", pendingIntent(create = true, credentialId = null))
            .setDescription("Save this passkey on your YubiKey. Tap it on the phone or plug it in.")
            .setIcon(icon())
            .build()
        callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val store = PasskeyStore(this)
        val entries = mutableListOf<CredentialEntry>()
        for (option in request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()) {
            val json = runCatching { JSONObject(option.requestJson) }.getOrNull() ?: continue
            val rpId = json.optString("rpId").ifBlank { null }
            val allowed = PasskeyJson.allowedIds(option.requestJson)

            // Accounts this YubiKey has been used with before on this site.
            val known = rpId?.let { store.accountsFor(it) }.orEmpty()
                .filter { allowed.isEmpty() || it.credentialId in allowed }
                .take(5)
            known.forEach { a ->
                val name = a.userName ?: a.displayName ?: "Passkey on YubiKey"
                entries += PublicKeyCredentialEntry.Builder(this, name, pendingIntent(false, a.credentialId), option)
                    .setDisplayName(listOfNotNull(a.displayName?.takeIf { it != name }, "YubiKey").joinToString(" · "))
                    .setIcon(icon())
                    .setLastUsedTime(Instant.ofEpochMilli(a.lastUsed))
                    .build()
            }

            // Always offer the key itself, for accounts not seen on this phone yet.
            entries += PublicKeyCredentialEntry.Builder(this,
                if (known.isEmpty()) "Use YubiKey" else "Another passkey on YubiKey",
                pendingIntent(create = false, credentialId = null), option)
                .setDisplayName("Tap your security key on the phone or plug it in")
                .setIcon(icon())
                .build()
        }
        callback.onResult(BeginGetCredentialResponse.Builder().setCredentialEntries(entries).build())
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // Nothing session-like is kept; passkeys live on the YubiKey.
        callback.onResult(null)
    }

    private fun icon(): Icon = Icon.createWithResource(this, R.drawable.ic_passkey_key)

    private fun pendingIntent(create: Boolean, credentialId: String?): PendingIntent {
        val code = requestCodes.incrementAndGet()
        val intent = Intent(this, PasskeyActivity::class.java)
            .setAction(if (create) PasskeyActivity.ACTION_CREATE else PasskeyActivity.ACTION_GET)
            // A unique data URI keeps entries from sharing one PendingIntent.
            .setData(Uri.parse("ykmanager-passkey://entry/$code"))
            .putExtra(PasskeyActivity.EXTRA_CREDENTIAL_ID, credentialId)
        return PendingIntent.getActivity(
            this, code, intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private companion object {
        val requestCodes = AtomicInteger((System.currentTimeMillis() % 100_000).toInt())
    }
}
