package net.skorchin.ykmanager.passkey

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import androidx.core.content.edit

/** Site name used by the in-app "Test passkey sheet" button; never a real domain. */
const val PASSKEY_SELF_TEST_RP_ID = "selftest.ykmanager.invalid"
const val PASSKEY_SELF_TEST_OK = "YK Manager self-test entry picked"

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
        set(value) { prefs.edit { putBoolean(KEY_ASK_PIN_FIRST, value) } }

    /** Show remembered accounts in the Android passkey sheet. */
    var rememberAccounts: Boolean
        get() = prefs.getBoolean(KEY_REMEMBER, true)
        set(value) {
            prefs.edit { putBoolean(KEY_REMEMBER, value) }
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
    fun clearAccounts() { prefs.edit { remove(KEY_ACCOUNTS) } }

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
        prefs.edit { putString(KEY_ACCOUNTS, arr.toString()) }
    }

    // ------------------------------------------------------------------
    // Diagnostics: the last few passkey requests, without secrets, so a
    // failure at a website can be investigated. Never leaves the phone
    // unless the user copies it.
    // ------------------------------------------------------------------

    @Synchronized
    fun addLog(entry: JSONObject) {
        val arr = runCatching { JSONArray(prefs.getString(KEY_LOG, "[]")) }.getOrDefault(JSONArray())
        val out = JSONArray().put(entry)
        for (i in 0 until minOf(arr.length(), MAX_LOG - 1)) out.put(arr.get(i))
        prefs.edit { putString(KEY_LOG, out.toString()) }
    }

    /**
     * Records that Android asked YK Manager what it can offer (the step
     * before the passkey sheet opens). If a sign-in never shows YK Manager
     * and nothing is recorded here, Android or the browser never asked it.
     */
    @Synchronized
    fun addAsked(entry: JSONObject) {
        val arr = runCatching { JSONArray(prefs.getString(KEY_ASKED, "[]")) }.getOrDefault(JSONArray())
        val out = JSONArray().put(entry)
        for (i in 0 until minOf(arr.length(), MAX_ASKED - 1)) out.put(arr.get(i))
        prefs.edit { putString(KEY_ASKED, out.toString()) }
    }

    /** Newest "asked" entries first. */
    fun asked(): List<JSONObject> = runCatching {
        val arr = JSONArray(prefs.getString(KEY_ASKED, "[]"))
        (0 until arr.length()).map { arr.getJSONObject(it) }
    }.getOrDefault(emptyList())

    fun logText(): String {
        val arr = runCatching { JSONArray(prefs.getString(KEY_LOG, "[]")) }.getOrDefault(JSONArray())
        val asked = runCatching { JSONArray(prefs.getString(KEY_ASKED, "[]")) }.getOrDefault(JSONArray())
        if (arr.length() == 0 && asked.length() == 0) return ""
        return JSONObject()
            .put("android_asked_yk_manager", asked)
            .put("sign_ins", arr)
            .toString(2)
    }

    fun logCount(): Int = runCatching {
        JSONArray(prefs.getString(KEY_LOG, "[]")).length() + JSONArray(prefs.getString(KEY_ASKED, "[]")).length()
    }.getOrDefault(0)

    @Synchronized
    fun clearLog() { prefs.edit { remove(KEY_LOG).remove(KEY_ASKED) } }

    private companion object {
        const val KEY_LOG = "diagnostics_log"
        const val MAX_LOG = 15
        const val KEY_ASKED = "diagnostics_asked"
        const val MAX_ASKED = 15
        const val KEY_ASK_PIN_FIRST = "ask_pin_first"
        const val KEY_REMEMBER = "remember_accounts"
        const val KEY_ACCOUNTS = "accounts"
        const val MAX_ACCOUNTS = 200
    }
}
