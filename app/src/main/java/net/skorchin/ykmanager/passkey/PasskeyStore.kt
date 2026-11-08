package net.skorchin.ykmanager.passkey

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * Small local store for the passkey provider:
 *
 * - user settings (ask for the PIN before the tap)
 * - remembered accounts, so the Android passkey sheet can show
 *   "jane@example.com · YubiKey" instead of only a generic entry
 *
 * Only non-secret metadata is kept (site, user name, credential ID). The
 * private keys never leave the YubiKey, and nothing here is backed up.
 */
class PasskeyStore(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences("passkey_provider", Context.MODE_PRIVATE)

    /** Ask for the FIDO2 PIN before the NFC tap, so a single tap is enough. */
    var askPinFirst: Boolean
        get() = prefs.getBoolean(KEY_ASK_PIN_FIRST, true)
        set(value) { prefs.edit().putBoolean(KEY_ASK_PIN_FIRST, value).apply() }

    /** Show remembered accounts in the Android passkey sheet. */
    var rememberAccounts: Boolean
        get() = prefs.getBoolean(KEY_REMEMBER, true)
        set(value) {
            prefs.edit().putBoolean(KEY_REMEMBER, value).apply()
            if (!value) clearAccounts()
        }

    data class Account(
        val rpId: String,
        val credentialId: String,
        val userName: String?,
        val displayName: String?,
        val lastUsed: Long,
    )

    @Synchronized
    fun accounts(): List<Account> {
        val raw = prefs.getString(KEY_ACCOUNTS, null) ?: return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Account(
                    rpId = o.getString("rp"),
                    credentialId = o.getString("id"),
                    userName = o.optString("name").ifBlank { null },
                    displayName = o.optString("display").ifBlank { null },
                    lastUsed = o.optLong("used"),
                )
            }
        }.getOrDefault(emptyList())
    }

    fun accountsFor(rpId: String): List<Account> =
        accounts().filter { it.rpId.equals(rpId, ignoreCase = true) }.sortedByDescending { it.lastUsed }

    /** Remember (or refresh) an account. A known name is never replaced by an unknown one. */
    @Synchronized
    fun remember(rpId: String, credentialId: String, userName: String?, displayName: String?) {
        if (!rememberAccounts) return
        val all = accounts().toMutableList()
        val old = all.firstOrNull { it.rpId.equals(rpId, true) && it.credentialId == credentialId }
        all.remove(old)
        all.add(
            Account(
                rpId = rpId,
                credentialId = credentialId,
                userName = userName ?: old?.userName,
                displayName = displayName ?: old?.displayName,
                lastUsed = System.currentTimeMillis(),
            )
        )
        save(all.sortedByDescending { it.lastUsed }.take(MAX_ACCOUNTS))
    }

    @Synchronized
    fun forget(rpId: String, credentialId: String) {
        save(accounts().filterNot { it.rpId.equals(rpId, true) && it.credentialId == credentialId })
    }

    @Synchronized
    fun clearAccounts() { prefs.edit().remove(KEY_ACCOUNTS).apply() }

    private fun save(list: List<Account>) {
        val arr = JSONArray()
        list.forEach { a ->
            arr.put(JSONObject().apply {
                put("rp", a.rpId)
                put("id", a.credentialId)
                a.userName?.let { put("name", it) }
                a.displayName?.let { put("display", it) }
                put("used", a.lastUsed)
            })
        }
        prefs.edit().putString(KEY_ACCOUNTS, arr.toString()).apply()
    }

    private companion object {
        const val KEY_ASK_PIN_FIRST = "ask_pin_first"
        const val KEY_REMEMBER = "remember_accounts"
        const val KEY_ACCOUNTS = "accounts"
        const val MAX_ACCOUNTS = 200
    }
}
