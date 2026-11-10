package net.skorchin.ykmanager.yubi

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** What to do when a YubiKey is tapped over NFC while no action is waiting for it. */
enum class NfcTapAction(val label: String, val description: String) {
    REFRESH(
        "Refresh the current screen",
        "Read the key and update whatever screen is open.",
    ),
    ACCOUNTS(
        "Open Accounts and show codes",
        "Switch to the Accounts screen and read the TOTP/HOTP codes from the key.",
    ),
    COPY_OTP(
        "Copy the NDEF one-time password",
        "Read the key's NDEF record (the OTP it would type into a browser) and copy the one-time password to the clipboard.",
    ),
    SHOW_OTP(
        "Show the NDEF one-time password",
        "Read the NDEF record and show the one-time password with a Copy button.",
    ),
    OPEN_LINK(
        "Open the NDEF link",
        "Open the URL from the NDEF record in the browser, as Android does when this app is not running.",
    ),
    NOTHING(
        "Do nothing",
        "Ignore taps unless an action is waiting for the key.",
    ),
}

/** Small persisted preferences store. */
class AppSettings(context: Context) {
    private val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private val _nfcTapAction = MutableStateFlow(
        prefs.getString(KEY_NFC_TAP, null)?.let { v -> NfcTapAction.values().firstOrNull { it.name == v } }
            ?: NfcTapAction.REFRESH
    )
    val nfcTapAction: StateFlow<NfcTapAction> = _nfcTapAction.asStateFlow()

    private val _copyOnShow = MutableStateFlow(prefs.getBoolean(KEY_COPY_ON_SHOW, false))
    /** When showing the OTP, also place it on the clipboard. */
    val copyOnShow: StateFlow<Boolean> = _copyOnShow.asStateFlow()

    fun setNfcTapAction(a: NfcTapAction) {
        _nfcTapAction.value = a
        prefs.edit().putString(KEY_NFC_TAP, a.name).apply()
    }

    fun setCopyOnShow(v: Boolean) {
        _copyOnShow.value = v
        prefs.edit().putBoolean(KEY_COPY_ON_SHOW, v).apply()
    }

    companion object {
        private const val KEY_NFC_TAP = "nfc_tap_action"
        private const val KEY_COPY_ON_SHOW = "nfc_copy_on_show"
    }
}
