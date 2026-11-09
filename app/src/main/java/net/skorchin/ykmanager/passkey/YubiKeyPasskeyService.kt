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
            recordAsked("create", request.callingAppInfo?.packageName, null, null, 0, "not a passkey request")
            callback.onResult(BeginCreateCredentialResponse())
            return
        }
        val rp = runCatching { JSONObject(request.requestJson).optJSONObject("rp")?.optString("id") }.getOrNull()
        recordAsked("create", request.callingAppInfo?.packageName, rp, null, 1, null)
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
        val caller = request.callingAppInfo?.packageName
        var rpSeen: String? = null
        var allowSeen: Int? = null
        try {
        for (option in request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()) {
            val json = runCatching { JSONObject(option.requestJson) }.getOrNull() ?: continue
            val rpId = json.optString("rpId").ifBlank { null }
            val allowed = PasskeyJson.allowedIds(option.requestJson)
            rpSeen = rpId; allowSeen = allowed.size

            // "Test passkey sheet" in YK Manager: answer with a marker entry only.
            if (caller == packageName && rpId == PASSKEY_SELF_TEST_RP_ID) {
                entries += PublicKeyCredentialEntry.Builder(this, "YK Manager test", selfTestIntent(), option)
                    .setDisplayName("YK Manager is working. Pick this to finish the test.")
                    .setIcon(icon())
                    .build()
                continue
            }

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
        } catch (e: Exception) {
            // Never fail silently: a crash here would just hide YK Manager from the sheet.
            recordAsked("get", caller, rpSeen, allowSeen, entries.size, "${e.javaClass.simpleName}: ${e.message}")
            callback.onResult(BeginGetCredentialResponse.Builder().setCredentialEntries(entries).build())
            return
        }
        val options = request.beginGetCredentialOptions.size
        val passkeyOptions = request.beginGetCredentialOptions.count { it is BeginGetPublicKeyCredentialOption }
        recordAsked("get", caller, rpSeen, allowSeen, entries.size,
            if (passkeyOptions == 0) "no passkey option in request ($options other)" else null)
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

    private fun recordAsked(kind: String, caller: String?, rpId: String?, allow: Int?, entries: Int, note: String?) {
        runCatching {
            PasskeyStore(this).addAsked(JSONObject().apply {
                put("time", java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date()))
                put("kind", kind)
                put("caller", caller ?: "(hidden)")
                rpId?.let { put("site", it) }
                allow?.let { put("allowCredentials", it) }
                put("entries_offered", entries)
                note?.let { put("note", it) }
            })
        }
    }

    private fun selfTestIntent(): PendingIntent {
        val code = requestCodes.incrementAndGet()
        val intent = Intent(this, PasskeyActivity::class.java)
            .setAction(PasskeyActivity.ACTION_SELF_TEST)
            .setData(Uri.parse("ykmanager-passkey://selftest/$code"))
        return PendingIntent.getActivity(this, code, intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
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

    companion object {
        private val requestCodes = AtomicInteger((System.currentTimeMillis() % 100_000).toInt())
    }
}
