package net.skorchin.ykmanager.yubi

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.management.Capability
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import androidx.core.net.toUri

enum class Screen(val title: String, val capability: Capability? = null) {
    HOME("Home"),
    ACCOUNTS("Accounts", Capability.OATH),
    PASSKEYS("Passkeys", Capability.FIDO2),
    FINGERPRINTS("Fingerprints", Capability.FIDO2),
    CERTIFICATES("Certificates", Capability.PIV),
    SLOTS("OTP slots", Capability.OTP),
    OPENPGP("OpenPGP", Capability.OPENPGP),
    APPLICATIONS("Applications"),
    RECIPES("Recipes"),
    RESET("Factory reset"),
    SETTINGS("Settings"),
    ABOUT("About & legal");

    /** Whether this screen makes sense for the connected key (unknown key: show everything). */
    fun availableFor(info: KeyInfo?): Boolean {
        if (info == null) return true
        if (this == FINGERPRINTS) return info.isBio
        val cap = capability ?: return true
        return info.supports(cap)
    }
}

class AppViewModel(app: Application) : AndroidViewModel(app) {

    val core = YubiKeyCore(app)
    val otp = OtpFeature(core, app)
    val oath = OathFeature(core, app)
    val piv = PivFeature(core)
    val fido = FidoFeature(core)
    val pgp = OpenPgpFeature(core)
    val mgmt = ManagementFeature(core)
    val recipes = RecipeFeature(core, otp, mgmt, app)
    val settings = AppSettings(app)

    private val _screen = MutableStateFlow(Screen.HOME)
    val screen: StateFlow<Screen> = _screen.asStateFlow()

    init {
        core.screenRefresher = { device ->
            when (_screen.value) {
                Screen.ACCOUNTS -> oath.refresh(device)
                Screen.PASSKEYS -> fido.refresh(device)
                Screen.FINGERPRINTS -> fido.refresh(device)
                Screen.CERTIFICATES -> piv.refresh(device)
                Screen.OPENPGP -> pgp.refresh(device)
                Screen.SLOTS -> otp.rebuild()
                else -> Unit
            }
        }
        core.onKeyChanged = {
            oath.clear(); piv.clear(); fido.clear(); pgp.clear()
        }
        core.idleTapHandler = { device, intentNdef -> handleIdleTap(device, intentNdef) }
        viewModelScope.launch {
            core.keyInfo.collect { info ->
                otp.rebuild()
                if (info != null && !_screen.value.availableFor(info)) _screen.value = Screen.HOME
            }
        }
        // Keep TOTP codes fresh while a key is plugged in over USB.
        viewModelScope.launch {
            while (true) {
                delay(1000)
                if (_screen.value == Screen.ACCOUNTS && core.isUsb && !core.busy.value) {
                    val st = oath.state.value
                    val now = System.currentTimeMillis()
                    val expired = st.loaded && !st.locked && st.entries.any {
                        it.isTotp && it.code != null && it.code.validUntil <= now
                    }
                    if (expired && now - st.readAt > 3000) core.refreshNow()
                }
            }
        }
    }

    /** The configurable behaviour for a tap that nothing was waiting for. */
    private suspend fun handleIdleTap(device: NfcYubiKeyDevice, intentNdef: ByteArray?): Boolean {
        val app = getApplication<Application>()
        return when (settings.nfcTapAction.value) {
            NfcTapAction.REFRESH -> false
            NfcTapAction.NOTHING -> true
            NfcTapAction.ACCOUNTS -> { _screen.value = Screen.ACCOUNTS; false }
            NfcTapAction.COPY_OTP, NfcTapAction.SHOW_OTP, NfcTapAction.OPEN_LINK -> {
                val prefixes = otp.knownNdefPrefixes()
                val content = intentNdef?.let { runCatching { NdefReader.parse(it, prefixes) }.getOrNull() }
                    ?: core.smartCard(device) { NdefReader.read(it, prefixes) }
                when (settings.nfcTapAction.value) {
                    NfcTapAction.COPY_OTP -> {
                        copy(app, content.otp)
                        core.toast("One-time password copied to the clipboard")
                    }
                    NfcTapAction.OPEN_LINK -> {
                        if (!content.isUri) throw UserFacingException("The NDEF record is text, not a link: ${content.value}")
                        val uri = content.value.toUri()
                        // Only web links: a tag could otherwise carry intent:, file: or other schemes.
                        if (uri.scheme?.lowercase() !in setOf("http", "https"))
                            throw UserFacingException("Only http(s) links are opened. The record is: ${content.value}")
                        app.startActivity(Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                    else -> {
                        if (settings.copyOnShow.value) copy(app, content.otp)
                        val isStatic = content.staticPassword != null
                        core.showDialog(InfoDialog(
                            if (isStatic) "Static password" else "One-time password",
                            content.otp + (if (content.otp != content.value) "\n\n${if (content.isUri) "Link" else "Text"}: ${content.value}" else "") +
                                (if (isStatic) "\n\nThe slot holds a static password. Over NFC the key sends raw keyboard scan codes, which were translated using the US keyboard layout; characters typed on another layout may differ." else "") +
                                (if (settings.copyOnShow.value) "\n\n(copied to the clipboard)" else ""),
                            content.otp,
                        ))
                    }
                }
                true
            }
        }
    }

    private fun copy(ctx: Context, value: String) {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(net.skorchin.ykmanager.ui.sensitiveClip("One-time password", value))
    }

    fun navigate(s: Screen) {
        if (_screen.value == s) return
        _screen.value = s
        if (core.isUsb) core.refreshNow()
    }

    override fun onCleared() {
        core.close()
    }
}
