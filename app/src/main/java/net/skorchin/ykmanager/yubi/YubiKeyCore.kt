package net.skorchin.ykmanager.yubi

import android.app.Activity
import android.app.Application
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.UsbPid
import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.YubiKeyType
import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.otp.OtpConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.management.FormFactor
import com.yubico.yubikit.management.ManagementSession
import com.yubico.yubikit.support.DeviceUtil
import com.yubico.yubikit.yubiotp.ConfigurationState
import com.yubico.yubikit.yubiotp.YubiOtpSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.IOException

/** How the app is currently talking to a YubiKey. */
enum class Link { NONE, USB, NFC }

/** Snapshot of the basic information every screen needs. */
data class KeyInfo(
    val transport: Transport,
    val deviceInfo: DeviceInfo?,
    val otpState: ConfigurationState?,
    val otpVersion: com.yubico.yubikit.core.Version?,
    val serial: Int?,
    /** Product name such as "YubiKey 5C NFC", "YubiKey NEO" or "Security Key NFC". */
    val name: String = "YubiKey",
    val keyType: YubiKeyType? = null,
) {
    val version: com.yubico.yubikit.core.Version? get() = deviceInfo?.version ?: otpVersion

    /** Capabilities the key supports over the transport it is currently connected on. */
    val supportedCapabilities: Int?
        get() = deviceInfo?.let { d ->
            val cur = d.getSupportedCapabilities(transport)
            // Some legacy keys only report one transport; fall back to the other.
            if (cur != 0) cur else d.getSupportedCapabilities(if (transport == Transport.USB) Transport.NFC else Transport.USB)
        }

    /** True if the key is known to support [cap]; unknown keys are treated as supporting everything. */
    fun supports(cap: Capability): Boolean {
        val caps = supportedCapabilities ?: return true
        return caps and cap.bit != 0
    }

    val isBio: Boolean
        get() = deviceInfo?.let {
            it.formFactor == FormFactor.USB_A_BIO || it.formFactor == FormFactor.USB_C_BIO || it.fpsVersion != null
        } ?: false

    /** FIDO-only products: Security Key series and YubiKey Bio FIDO Edition. */
    val isFidoOnly: Boolean
        get() = supportedCapabilities?.let { caps ->
            caps and (Capability.OTP.bit or Capability.OATH.bit or Capability.PIV.bit or
                Capability.OPENPGP.bit or Capability.HSMAUTH.bit) == 0
        } ?: false

    /** YubiKey 5.0+ style device configuration (per-application toggles, NFC, lock code). */
    val hasDeviceConfig: Boolean get() = version?.isAtLeast(5, 0, 0) ?: false

    /** YubiKey NEO / YubiKey 4 style USB interface mode switching. */
    val hasLegacyMode: Boolean
        get() = version?.let { it.isAtLeast(3, 0, 0) && it.isLessThan(5, 0, 0) } ?: false

    /** Device-wide reset exists on YubiKey Bio Multi-protocol Edition (firmware 5.6+). */
    val hasDeviceReset: Boolean
        get() = isBio && !isFidoOnly && (version?.isAtLeast(5, 6, 0) ?: false)
}

data class Message(val text: String, val isError: Boolean = false, val id: Long = System.nanoTime())

/** A dialog with a title, a body and optionally a value to copy. */
data class InfoDialog(val title: String, val body: String, val copyValue: String? = null)

/** A file the UI should offer to save (certificates, CSRs, ...). */
data class ExportFile(val suggestedName: String, val mimeType: String, val bytes: ByteArray)

typealias DeviceAction = suspend (YubiKeyDevice) -> Unit

/**
 * Owns YubiKey discovery and all communication with the key.
 *
 * Important YubiKit rule: a connection obtained via requestConnection() is
 * closed as soon as the callback returns. All work therefore happens inside
 * [connect], which runs the block within the callback and hands the result
 * back to the calling coroutine.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class YubiKeyCore(app: Application) {

    private val yubiKit = YubiKitManager(app)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))

    private var usbDevice: UsbYubiKeyDevice? = null

    /**
     * The YubiKey from the most recent NFC tap. Android only reports a tag
     * once while it stays in the field, so a follow-up action (for example
     * unlocking OATH right after reading it) must reuse this device instead
     * of waiting for a second tap that never comes while the key is still
     * held against the phone.
     */
    private var nfcDevice: NfcYubiKeyDevice? = null
    private var usbStarted = false
    private var pending: Pair<String, DeviceAction>? = null

    /** Called after USB attach / NFC tap to refresh whatever screen is visible. */
    var screenRefresher: DeviceAction? = null

    /** Called when a different YubiKey (by serial) shows up. */
    var onKeyChanged: (() -> Unit)? = null

    /** Run once on the next USB attach (e.g. FIDO reset requires a fresh insert). */
    private var onNextUsbAttach: Pair<String, DeviceAction>? = null

    private val _link = MutableStateFlow(Link.NONE)
    val link: StateFlow<Link> = _link.asStateFlow()

    private val _keyInfo = MutableStateFlow<KeyInfo?>(null)
    val keyInfo: StateFlow<KeyInfo?> = _keyInfo.asStateFlow()

    private val _nfcAvailable = MutableStateFlow<Boolean?>(null)
    val nfcAvailable: StateFlow<Boolean?> = _nfcAvailable.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _tapPrompt = MutableStateFlow<String?>(null)
    val tapPrompt: StateFlow<String?> = _tapPrompt.asStateFlow()

    /** Shown while the key is waiting for a physical touch. */
    private val _touchPrompt = MutableStateFlow(false)
    val touchPrompt: StateFlow<Boolean> = _touchPrompt.asStateFlow()

    private val _message = MutableStateFlow<Message?>(null)
    val message: StateFlow<Message?> = _message.asStateFlow()

    private val _dialog = MutableStateFlow<InfoDialog?>(null)
    val dialog: StateFlow<InfoDialog?> = _dialog.asStateFlow()

    private val _export = MutableStateFlow<ExportFile?>(null)
    val export: StateFlow<ExportFile?> = _export.asStateFlow()

    val isUsb: Boolean get() = usbDevice != null

    fun toast(text: String) { _message.value = Message(text) }
    fun error(text: String) { _message.value = Message(text, isError = true) }
    fun clearMessage() { _message.value = null }
    fun showDialog(d: InfoDialog) { _dialog.value = d }
    fun clearDialog() { _dialog.value = null }
    fun offerExport(f: ExportFile) { _export.value = f }
    fun clearExport() { _export.value = null }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    fun startUsbDiscovery() {
        if (usbStarted) return
        usbStarted = true
        yubiKit.startUsbDiscovery(UsbConfiguration()) { device ->
            usbDevice = device
            // A passkey prompt over another app owns the key right now; don't compete for it.
            if (net.skorchin.ykmanager.passkey.PasskeyPromptState.active) {
                _link.value = Link.USB
                device.setOnClosed { if (usbDevice === device) { usbDevice = null; _link.value = Link.NONE; _keyInfo.value = null } }
                return@startUsbDiscovery
            }
            _link.value = Link.USB
            device.setOnClosed {
                if (usbDevice === device) {
                    usbDevice = null
                    _link.value = Link.NONE
                    _keyInfo.value = null
                }
            }
            val once = onNextUsbAttach
            onNextUsbAttach = null
            launchJob(device) {
                if (once != null) {
                    _tapPrompt.value = null
                    runGuarded(once.first) { once.second(device) }
                }
                runGuarded("read the YubiKey") { refreshAll(device) }
            }
        }
    }

    /** True while this activity holds NFC reader mode (taps come to the app, not to the system). */
    @Volatile private var nfcArmed = false

    /**
     * When true, the app deliberately releases NFC reader mode so Android handles
     * the YubiKey's NDEF tag itself (browser, Yubico Authenticator, ...). Only
     * offered on the OTP slots screen, to test the NDEF output; off everywhere else.
     */
    private val _systemHandlesNfc = MutableStateFlow(false)
    val systemHandlesNfc: StateFlow<Boolean> = _systemHandlesNfc.asStateFlow()

    fun setSystemHandlesNfc(activity: Activity, on: Boolean) {
        _systemHandlesNfc.value = on
        if (on) stopNfcDiscovery(activity) else startNfcDiscovery(activity)
    }

    /**
     * Re-arm reader mode only when it is not already held. Tearing it down and
     * re-enabling while a key is still on the phone restarts NFC discovery, and
     * in that gap the system can read the tag itself and open the NDEF link.
     */
    fun ensureNfcDiscovery(activity: Activity) {
        if (!nfcArmed) startNfcDiscovery(activity)
    }

    fun startNfcDiscovery(activity: Activity) {
        if (_systemHandlesNfc.value) return
        try {
            // skipNdefCheck: don't let Android read the NDEF record on every tap. It is slower,
            // makes the key emit an OTP for nothing, and is a path by which the system may act
            // on the record itself instead of handing the tag to this app.
            yubiKit.startNfcDiscovery(NfcConfiguration().timeout(30_000).skipNdefCheck(true), activity) { onNfcTap(it) }
            nfcArmed = true
            _nfcAvailable.value = true
        } catch (e: NfcNotAvailable) {
            nfcArmed = false
            _nfcAvailable.value = false
        }
    }

    /** A tag delivered through an NFC intent rather than reader mode; treat it like a tap. */
    fun onNfcIntentTag(tag: android.nfc.Tag, ndefMessage: ByteArray?) {
        onNfcTap(NfcYubiKeyDevice(tag, 30_000, intentTagExecutor), ndefMessage)
    }

    private val intentTagExecutor: java.util.concurrent.ExecutorService = java.util.concurrent.Executors.newSingleThreadExecutor()

    fun stopNfcDiscovery(activity: Activity) {
        nfcArmed = false
        runCatching { yubiKit.stopNfcDiscovery(activity) }
    }

    fun close() {
        scope.cancel()
        if (usbStarted) yubiKit.stopUsbDiscovery()
    }

    /**
     * Handles a tap that arrived while nothing was waiting for the key (the
     * user's configurable "NFC tap" behaviour). Receives the NDEF message if
     * the tap came in through an NDEF intent. Returns true when it fully
     * handled the tap and no screen refresh should follow.
     */
    var idleTapHandler: (suspend (NfcYubiKeyDevice, ByteArray?) -> Boolean)? = null

    private fun onNfcTap(device: NfcYubiKeyDevice, intentNdef: ByteArray? = null) {
        if (usbDevice != null) return // prefer the USB key while one is attached
        nfcDevice = device
        val action = pending
        pending = null
        _tapPrompt.value = null
        launchJob(device) {
            if (action != null) {
                runGuarded(action.first) { action.second(device) }
                refreshAfterNfc(device, afterAction = true)
            } else {
                val handler = idleTapHandler
                var handled = false
                if (handler != null) runGuarded("handle the tap") { handled = handler(device, intentNdef) }
                if (!handled) refreshAfterNfc(device, afterAction = false)
            }
            _link.value = Link.NFC
        }
    }

    /**
     * Refresh after an NFC interaction. If the key can no longer be reached
     * (lifted off, or still busy after a write) the action itself has already
     * been reported, so instead of a failure a short note asks for another tap.
     */
    private suspend fun refreshAfterNfc(device: NfcYubiKeyDevice, afterAction: Boolean) {
        val ok = try {
            refreshAll(device); true
        } catch (e: Exception) {
            if (e is UserFacingException) throw e
            false
        }
        if (!ok) {
            // No blocking "Scan your YubiKey" dialog here: the action (if any) has
            // already run and been reported, and the next tap refreshes the screen
            // anyway. Just leave a short, dismissable note.
            nfcDevice = null
            pending = null
            if (afterAction) {
                if (_message.value == null) toast("Done. Tap your YubiKey again any time to refresh what is shown.")
            } else {
                toast("The YubiKey moved away before it could be read. Tap it again to refresh.")
            }
        }
    }

    // ------------------------------------------------------------------
    // Running actions
    // ------------------------------------------------------------------

    /**
     * Run [action] against the key: immediately over USB, or on the next NFC
     * tap. After the action, the visible screen is refreshed.
     */
    fun run(name: String, refresh: Boolean = true, action: DeviceAction) {
        val usb = usbDevice
        if (usb != null) {
            launchJob(usb) {
                runGuarded(name) { action(usb) }
                if (refresh) runGuarded("read the YubiKey") { refreshAll(usb) }
            }
        } else {
            runOnNfc(name, action, refresh)
        }
    }

    /**
     * Run [action] on the NFC key that is still on the phone if possible;
     * otherwise ask for a tap and run it then.
     */
    private fun runOnNfc(name: String, action: DeviceAction, refresh: Boolean) {
        val nfc = nfcDevice
        if (nfc == null) {
            pending = name to action
            _tapPrompt.value = "Hold your YubiKey against the back of the phone to $name."
            return
        }
        launchJob(nfc) {
            // Probe first so an action is never started on a key that has gone away.
            val present = runCatching { connect(nfc, SmartCardConnection::class.java) { true } }.getOrDefault(false)
            if (present) {
                runGuarded(name) { action(nfc) }
                if (refresh) refreshAfterNfc(nfc, afterAction = true)
            } else {
                nfcDevice = null
                pending = name to action
                _tapPrompt.value = "Hold your YubiKey against the back of the phone to $name."
            }
        }
    }

    /** Like [run] but waits for the next USB insertion (USB) or tap (NFC). */
    fun runOnFreshInsert(name: String, action: DeviceAction) {
        if (usbDevice != null) {
            onNextUsbAttach = name to action
            _tapPrompt.value =
                "Unplug your YubiKey, then plug it back in to $name. Touch it when it blinks."
        } else {
            run(name, action = action)
        }
    }

    fun refreshNow() {
        val usb = usbDevice
        if (usb != null) launchJob(usb) { runGuarded("read the YubiKey") { refreshAll(usb) } }
        else {
            pending = null
            runOnNfc("read the YubiKey", { _ -> }, refresh = true)
        }
    }

    fun cancelPrompt() {
        pending = null
        onNextUsbAttach = null
        _tapPrompt.value = null
    }

    private fun launchJob(device: YubiKeyDevice, block: suspend () -> Unit) {
        scope.launch {
            _busy.value = true
            try {
                block()
            } finally {
                _busy.value = false
                _touchPrompt.value = false
            }
        }
    }

    private suspend fun runGuarded(name: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: UserFacingException) {
            error(e.message ?: "Failed to $name")
        } catch (e: Throwable) {
            error("Failed to $name: ${describe(e)}")
        }
    }

    private suspend fun refreshAll(device: YubiKeyDevice) {
        val old = _keyInfo.value
        val info = readKeyInfo(device)
        if (info.deviceInfo == null && info.otpState == null) throw java.io.IOException("The YubiKey could not be read")
        if (old?.serial != null && info.serial != null && old.serial != info.serial) {
            onKeyChanged?.invoke()
        }
        _keyInfo.value = info
        screenRefresher?.let { r ->
            if (device is NfcYubiKeyDevice) r(device)       // failures handled by refreshAfterNfc
            else runGuarded("read data") { r(device) }
        }
    }

    private suspend fun readKeyInfo(device: YubiKeyDevice): KeyInfo {
        val usb = device as? UsbYubiKeyDevice
        val pid: UsbPid? = usb?.pid
        val keyType: YubiKeyType? = pid?.takeIf { it != UsbPid.OTHER }?.type

        // DeviceUtil.readInfo understands every generation (Standard, NEO, 4, 5,
        // Bio, Security Key) and synthesises a DeviceInfo for keys that have no
        // Management application. Try the richest interface first.
        var deviceInfo: DeviceInfo? = null
        if (device.supportsConnection(SmartCardConnection::class.java)) {
            deviceInfo = runCatching {
                connect(device, SmartCardConnection::class.java) { DeviceUtil.readInfo(it, pid) }
            }.getOrNull()
        }
        if (deviceInfo == null && usb != null && usb.supportsConnection(OtpConnection::class.java)) {
            deviceInfo = runCatching {
                withContext(Dispatchers.IO) {
                    val c = usb.openConnection(OtpConnection::class.java)
                    try { DeviceUtil.readInfo(c, pid) } finally { runCatching { c.close() } }
                }
            }.getOrNull()
        }
        if (deviceInfo == null && device.supportsConnection(FidoConnection::class.java)) {
            deviceInfo = runCatching {
                connect(device, FidoConnection::class.java) { DeviceUtil.readInfo(it, pid) }
            }.getOrNull()
        }
        if (deviceInfo == null) {
            deviceInfo = runCatching { management(device) { it.deviceInfo } }.getOrNull()
        }

        val otpCapable = deviceInfo?.let { d ->
            (d.getSupportedCapabilities(Transport.USB) or d.getSupportedCapabilities(Transport.NFC)) and Capability.OTP.bit != 0
        } ?: true
        val otp = if (!otpCapable) null else runCatching {
            otp(device) { s ->
                Triple(
                    s.configurationState,
                    s.version,
                    runCatching { s.serialNumber }.getOrNull()
                )
            }
        }.getOrNull()
        val name = deviceInfo?.let { runCatching { DeviceUtil.getName(it, keyType) }.getOrNull() }
            ?: when (keyType) {
                YubiKeyType.YKS -> "YubiKey Standard"
                YubiKeyType.NEO -> "YubiKey NEO"
                YubiKeyType.SKY -> "Security Key by Yubico"
                YubiKeyType.YKP -> "YubiKey Plus"
                else -> "YubiKey"
            }
        return KeyInfo(
            transport = device.transport,
            deviceInfo = deviceInfo,
            otpState = otp?.first,
            otpVersion = otp?.second,
            serial = deviceInfo?.serialNumber ?: otp?.third,
            name = name,
            keyType = keyType,
        )
    }

    // ------------------------------------------------------------------
    // Connections and sessions
    // ------------------------------------------------------------------

    /** Marks a failure to open the connection, as opposed to a failure inside [connect]'s block. */
    private class OpenFailed(cause: Throwable) : Exception(cause)

    /**
     * Open a connection and run [block] while it is open.
     *
     * Over NFC every call re-connects the ISO-DEP link, and Android refuses
     * the reconnect with a bare IOException while the key is still busy
     * (for instance writing flash right after a FIDO credential was deleted).
     * Opening is therefore retried briefly; [block] itself is never re-run.
     */
    suspend fun <C : YubiKeyConnection, T> connect(
        device: YubiKeyDevice,
        type: Class<C>,
        block: (C) -> T,
    ): T {
        var attempt = 0
        while (true) {
            val outcome = suspendCancellableCoroutine<Result<T>> { cont ->
                device.requestConnection(type) { result ->
                    val conn = try { result.value } catch (e: Throwable) {
                        cont.resume(Result.failure(OpenFailed(e))); return@requestConnection
                    }
                    cont.resume(runCatching { block(conn) })
                }
            }
            val e = outcome.exceptionOrNull() ?: return outcome.getOrThrow()
            if (e is OpenFailed) {
                if (device is NfcYubiKeyDevice && attempt++ < 8) { delay(150); continue }
                throw e.cause ?: e
            }
            throw e
        }
    }

    suspend fun <T> smartCard(device: YubiKeyDevice, block: (SmartCardConnection) -> T): T {
        if (!device.supportsConnection(SmartCardConnection::class.java)) {
            throw UserFacingException(
                "The smart card (CCID) interface is not available. Enable it under Applications."
            )
        }
        return connect(device, SmartCardConnection::class.java, block)
    }

    suspend fun <T> management(device: YubiKeyDevice, block: (ManagementSession) -> T): T = when {
        device.supportsConnection(SmartCardConnection::class.java) ->
            connect(device, SmartCardConnection::class.java) { c -> ManagementSession(c).useSession(block) }
        device.supportsConnection(OtpConnection::class.java) ->
            connect(device, OtpConnection::class.java) { c -> ManagementSession(c).useSession(block) }
        device.supportsConnection(FidoConnection::class.java) ->
            connect(device, FidoConnection::class.java) { c -> ManagementSession(c).useSession(block) }
        else -> throw UserFacingException("No supported interface for device management")
    }

    /**
     * Run an OTP session.
     *
     * Over USB this deliberately does NOT use requestConnection(OtpConnection):
     * YubiKit caches that HID connection and reuses it, and once the app's
     * refresh cycle has interleaved smart card requests with it the stale
     * cached connection makes feature report reads fail with
     * "Unexpected amount of data read: -1" when programming a slot. A dedicated
     * connection is opened and closed per operation instead, and a transport
     * error of that kind is retried once.
     */
    suspend fun <T> otp(device: YubiKeyDevice, block: (YubiOtpSession) -> T): T {
        val usb = device as? UsbYubiKeyDevice
        if (usb != null && usb.supportsConnection(OtpConnection::class.java)) {
            for (attempt in 0 until 2) {
                try {
                    return withContext(Dispatchers.IO) {
                        val connection = usb.openConnection(OtpConnection::class.java)
                        try {
                            YubiOtpSession(connection).useSession(block)
                        } finally {
                            runCatching { connection.close() }
                        }
                    }
                } catch (e: IOException) {
                    if (attempt == 1 || !isHidTransportError(e)) throw e
                    delay(400)
                }
            }
        }
        if (device.supportsConnection(SmartCardConnection::class.java)) {
            return connect(device, SmartCardConnection::class.java) { c -> YubiOtpSession(c).useSession(block) }
        }
        throw UserFacingException(
            "The OTP application is not reachable. Enable YubicoOTP under Applications."
        )
    }

    private fun isHidTransportError(e: Throwable): Boolean {
        var t: Throwable? = e
        while (t != null) {
            if (t.message?.contains("Unexpected amount of data") == true) return true
            t = t.cause
        }
        return false
    }

    suspend fun <T> fido(device: YubiKeyDevice, block: (Ctap2Session) -> T): T = when {
        device.supportsConnection(FidoConnection::class.java) ->
            connect(device, FidoConnection::class.java) { c -> Ctap2Session(c).useSession(block) }
        device.supportsConnection(SmartCardConnection::class.java) ->
            connect(device, SmartCardConnection::class.java) { c -> Ctap2Session(c).useSession(block) }
        else -> throw UserFacingException("FIDO2 is not reachable. Enable it under Applications.")
    }

    /** A CommandState that shows a "touch your key" prompt while the key waits. */
    fun touchState(): CommandState = object : CommandState() {
        override fun onKeepAliveStatus(status: Byte) {
            _touchPrompt.value = status == STATUS_UPNEEDED
        }
    }

    fun showTouchPrompt(show: Boolean) { _touchPrompt.value = show }

    companion object {
        fun describe(e: Throwable): String {
            val root = generateSequence(e) { it.cause }.last()
            val msg = (e.message?.takeIf { it.isNotBlank() } ?: root.message)
            return msg ?: e.javaClass.simpleName
        }
    }
}

/** An exception whose message is meant to be shown to the user as-is. */
class UserFacingException(message: String) : Exception(message)

internal inline fun <S : Closeable, T> S.useSession(block: (S) -> T): T {
    try {
        return block(this)
    } finally {
        try { close() } catch (_: Exception) { }
    }
}
