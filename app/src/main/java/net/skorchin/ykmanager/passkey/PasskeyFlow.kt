package net.skorchin.ykmanager.passkey

import android.content.Context
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.domerrors.DomError
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.domerrors.NotSupportedError
import androidx.credentials.exceptions.domerrors.SecurityError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.CallingAppInfo
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.client.AuthInvalidClientError
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.SerializationType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import java.io.IOException
import kotlin.coroutines.resume

/** Where the prompt is in the ceremony. */
enum class Phase { VERIFYING, READY, WORKING, TOUCH, PICK, FATAL }

/** Which PIN fields to show. */
enum class PinMode { NONE, ENTER, SET_NEW, CHANGE }

data class PasskeyUi(
    val phase: Phase = Phase.VERIFYING,
    val isCreate: Boolean = false,
    val title: String = "",
    val subtitle: String = "",
    val pinMode: PinMode = PinMode.NONE,
    /** Extra explanation under the PIN field(s). */
    val pinHint: String? = null,
    val instruction: String = "",
    val error: String? = null,
    val usbAttached: Boolean = false,
    /** A tapped NFC key that may still be on the phone, so Continue can reuse it. */
    val nfcKeyPresent: Boolean = false,
    val nfcAvailable: Boolean = true,
    val minPinLength: Int = 4,
    val accounts: List<String> = emptyList(),
    val touchIsFingerprint: Boolean = false,
)

/** What the activity should do when the prompt closes. */
sealed class PasskeyResult {
    data class Success(val responseJson: String) : PasskeyResult()
    data class CreateFailed(val error: CreateCredentialException) : PasskeyResult()
    data class GetFailed(val error: GetCredentialException) : PasskeyResult()
}

/**
 * One passkey ceremony (create or sign-in) against a YubiKey.
 *
 * Everything for a ceremony happens inside a single connection: PIN
 * check, optional PIN set/change, and the CTAP2 command. Over NFC that
 * means one tap, provided the PIN is entered first.
 */
@RequiresApi(34)
class PasskeyFlow(
    private val context: Context,
    private val scope: CoroutineScope,
    private val finish: (PasskeyResult) -> Unit,
) {
    private val store = PasskeyStore(context)

    private val _ui = MutableStateFlow(PasskeyUi())
    val ui: StateFlow<PasskeyUi> = _ui.asStateFlow()

    val pin = MutableStateFlow("")
    val newPin = MutableStateFlow("")
    val newPinRepeat = MutableStateFlow("")

    private var isCreate = false
    private var requestJson: JSONObject? = null
    private var clientData: ClientDataProvider? = null
    private var effectiveDomain: String = ""
    private var rpId: String = ""
    private var createUserName: String? = null
    private var createDisplayName: String? = null

    private var usbDevice: UsbYubiKeyDevice? = null
    private var nfcDevice: NfcYubiKeyDevice? = null
    private var queuedDevice: YubiKeyDevice? = null
    private var commandState: CommandState? = null
    private var multiple: MultipleAssertionsAvailable? = null
    private var lastDomError: DomError? = null
    private var lastErrorMessage: String? = null
    private var done = false

    // ------------------------------------------------------------------
    // Setup
    // ------------------------------------------------------------------

    fun start(
        create: Boolean,
        json: String,
        clientDataHash: ByteArray?,
        caller: CallingAppInfo,
        preferredCredentialId: String?,
    ) {
        isCreate = create
        _ui.update { it.copy(isCreate = create, title = if (create) "Save passkey to YubiKey" else "Sign in with YubiKey",
            instruction = "Checking the request…") }

        scope.launch {
            val raw = runCatching { JSONObject(json) }.getOrNull()
            if (raw == null) { fatal("The request from the app could not be read.", NotSupportedError()); return@launch }
            val requestedRp = if (create) raw.optJSONObject("rp")?.optString("id")?.ifBlank { null } else raw.optString("rpId").ifBlank { null }

            when (val v = CallerVerifier.verify(context, caller, requestedRp)) {
                is CallerVerifier.Result.Rejected -> { fatal(v.reason, SecurityError()); return@launch }
                is CallerVerifier.Result.Allowed -> {
                    effectiveDomain = v.effectiveDomain
                    rpId = requestedRp ?: v.effectiveDomain

                    val normalized = if (create) PasskeyJson.normalizeCreate(raw)
                    else PasskeyJson.normalizeGet(raw, rpId).also { narrowToPreferred(it, preferredCredentialId) }
                    requestJson = normalized

                    clientData = if (clientDataHash != null && clientDataHash.size == 32) {
                        // The browser built clientDataJSON itself and only needs the signature.
                        ClientDataProvider.fromHash(clientDataHash)
                    } else {
                        ClientDataProvider.fromClientDataJson(
                            PasskeyJson.clientDataJson(
                                if (create) "webauthn.create" else "webauthn.get",
                                normalized.getString("challenge"),
                                v.origin,
                                if (v.isBrowser) null else caller.packageName,
                            )
                        )
                    }

                    val user = normalized.optJSONObject("user")
                    createUserName = user?.optString("name")?.ifBlank { null }
                    createDisplayName = user?.optString("displayName")?.ifBlank { null }
                    val preferredName = preferredCredentialId?.let { id -> store.accountsFor(rpId).firstOrNull { it.credentialId == id } }
                        ?.let { it.userName ?: it.displayName }

                    val who = if (v.isBrowser) "${v.callerLabel} · $rpId" else "${v.callerLabel} for $rpId"
                    val subtitle = when {
                        create -> listOfNotNull(createUserName ?: createDisplayName, who).joinToString("\n")
                        preferredName != null -> "$preferredName\n$who"
                        else -> who
                    }

                    val askPin = store.askPinFirst && wantsUserVerification(normalized)
                    _ui.update {
                        it.copy(phase = Phase.READY, subtitle = subtitle,
                            pinMode = if (askPin) PinMode.ENTER else PinMode.NONE,
                            pinHint = if (askPin) "Leave empty if your YubiKey has no FIDO2 PIN." else null,
                            instruction = waitingText())
                    }
                    queuedDevice?.let { queuedDevice = null; run(it) }
                    applyUsb()
                }
            }
        }
    }

    /** When an entry for a specific remembered account was chosen, ask the key for only that one. */
    private fun narrowToPreferred(o: JSONObject, id: String?) {
        if (id == null) return
        val allow = o.optJSONArray("allowCredentials")
        if (allow != null && allow.length() > 0) {
            val ids = (0 until allow.length()).mapNotNull { allow.optJSONObject(it)?.optString("id") }
            if (id !in ids) return
        }
        o.put("allowCredentials", org.json.JSONArray().put(JSONObject().put("type", "public-key").put("id", id)))
    }

    private fun wantsUserVerification(o: JSONObject): Boolean {
        if (!isCreate) return o.optString("userVerification", "preferred") != "discouraged"
        val sel = o.optJSONObject("authenticatorSelection")
        val uv = sel?.optString("userVerification", "preferred") ?: "preferred"
        val rk = sel?.optString("residentKey")?.ifBlank { null }
            ?: if (sel?.optBoolean("requireResidentKey") == true) "required" else "discouraged"
        return uv != "discouraged" || rk != "discouraged"
    }

    private fun waitingText(): String {
        val ui = _ui.value
        return when {
            ui.usbAttached -> "YubiKey connected. Press Continue."
            ui.nfcAvailable -> "Hold your YubiKey flat against the back of the phone until it's done, or plug it in."
            else -> "Plug in your YubiKey."
        }
    }

    // ------------------------------------------------------------------
    // Devices
    // ------------------------------------------------------------------

    fun setNfcAvailable(available: Boolean) {
        _ui.update { it.copy(nfcAvailable = available) }
        if (_ui.value.phase == Phase.READY) _ui.update { it.copy(instruction = waitingText()) }
    }

    private var usbNeedsPin: Boolean? = null
    private var usbProbed = false

    fun onUsbAttached(device: UsbYubiKeyDevice) {
        usbDevice = device
        usbProbed = false
        usbNeedsPin = null
        device.setOnClosed {
            if (usbDevice === device) {
                usbDevice = null
                _ui.update { it.copy(usbAttached = false) }
                if (_ui.value.phase == Phase.READY) _ui.update { it.copy(instruction = waitingText()) }
            }
        }
        _ui.update { it.copy(usbAttached = true) }
        if (_ui.value.phase == Phase.READY) _ui.update { it.copy(instruction = waitingText()) }
        scope.launch {
            // Learn whether the key needs a PIN, so keys without one (or Bio keys) start right away.
            usbNeedsPin = probePinNeeded(device)
            usbProbed = true
            applyUsb()
        }
    }

    /** Start on the plugged-in key as soon as everything needed is known. */
    private fun applyUsb() {
        val device = usbDevice ?: return
        val ui = _ui.value
        if (!usbProbed || ui.phase != Phase.READY) return
        when {
            usbNeedsPin == false && (ui.pinMode == PinMode.ENTER || ui.pinMode == PinMode.NONE) -> {
                _ui.update { it.copy(pinMode = PinMode.NONE) }; run(device)
            }
            usbNeedsPin == true && ui.pinMode == PinMode.NONE ->
                _ui.update { it.copy(pinMode = PinMode.ENTER, pinHint = null, instruction = "Enter your FIDO2 PIN, then press Continue.") }
            usbNeedsPin == true && pin.value.isEmpty() ->
                _ui.update { it.copy(pinHint = null, instruction = "Enter your FIDO2 PIN, then press Continue.") }
            else -> run(device)
        }
    }

    fun onNfcTap(device: NfcYubiKeyDevice) {
        if (usbDevice != null) return // a plugged-in key wins
        nfcDevice = device
        _ui.update { it.copy(nfcKeyPresent = true) }
        if (_ui.value.phase == Phase.VERIFYING) { queuedDevice = device; return }
        run(device)
    }

    /** Continue button: the plugged-in key, or the tapped key if it's still on the phone. */
    fun onContinue() {
        val d: YubiKeyDevice = usbDevice ?: nfcDevice ?: run {
            _ui.update { it.copy(instruction = waitingText()) }
            return
        }
        run(d)
    }

    private suspend fun probePinNeeded(device: UsbYubiKeyDevice): Boolean? = runCatching {
        withConnection(device) { conn ->
            val session = if (conn is FidoConnection) Ctap2Session(conn) else Ctap2Session(conn as SmartCardConnection)
            val opts = session.cachedInfo.options
            val pinSet = opts["clientPin"] == true
            val bio = opts["uv"] == true
            _ui.update { it.copy(minPinLength = session.cachedInfo.minPinLength.coerceAtLeast(4)) }
            if (session.cachedInfo.forcePinChange) true else pinSet && !bio
        }
    }.getOrNull()

    // ------------------------------------------------------------------
    // The ceremony
    // ------------------------------------------------------------------

    fun run(device: YubiKeyDevice) {
        val ui = _ui.value
        if (done || ui.phase != Phase.READY) return
        val req = requestJson ?: return
        val cd = clientData ?: return

        val mode = ui.pinMode
        if (mode == PinMode.SET_NEW || mode == PinMode.CHANGE) {
            val problem = when {
                mode == PinMode.CHANGE && pin.value.isEmpty() -> "Enter the current PIN."
                newPin.value.length < ui.minPinLength -> "The new PIN must be at least ${ui.minPinLength} characters."
                newPin.value.toByteArray().size > 63 -> "The new PIN is too long."
                newPin.value != newPinRepeat.value -> "The new PINs don't match."
                else -> null
            }
            if (problem != null) { _ui.update { it.copy(error = problem) }; return }
        }

        val isNfc = device is NfcYubiKeyDevice
        _ui.update {
            it.copy(phase = Phase.WORKING, error = null,
                instruction = if (isNfc) "Keep holding your YubiKey against the phone…" else "Talking to your YubiKey…")
        }
        val state = object : CommandState() {
            override fun onKeepAliveStatus(status: Byte) {
                if (status == STATUS_UPNEEDED) _ui.update { it.copy(phase = Phase.TOUCH, instruction = touchText()) }
            }
        }
        commandState = state
        val pinNow = pin.value.takeIf { it.isNotEmpty() }
        val newPinNow = newPin.value

        scope.launch {
            try {
                val outcome = withConnection(device) { conn ->
                    PasskeyCeremony.run(conn, isCreate, req, cd, effectiveDomain, mode, pinNow, newPinNow, state) { facts ->
                        _ui.update { it.copy(minPinLength = facts.minPinLength, touchIsFingerprint = facts.fingerprint) }
                    }
                }
                when (outcome) {
                    is PasskeyCeremony.Outcome.Done -> succeed(outcome.credential, null)
                    is PasskeyCeremony.Outcome.Pick -> {
                        multiple = outcome.m
                        _ui.update { it.copy(phase = Phase.PICK, accounts = outcome.names,
                            instruction = "Your YubiKey has ${outcome.names.size} passkeys for $rpId. Choose one.") }
                    }
                }
            } catch (e: Throwable) {
                handleError(e, device)
            } finally {
                commandState = null
            }
        }
    }

    private fun touchText(): String =
        if (_ui.value.touchIsFingerprint) "Touch the fingerprint sensor on your YubiKey."
        else "Touch your YubiKey when it blinks."

    fun pick(index: Int) {
        val m = multiple ?: return
        val names = _ui.value.accounts
        multiple = null
        val cred = runCatching { m.select(index) }.getOrElse {
            fatal("That passkey could not be selected.", NotAllowedError()); return
        }
        succeed(cred, names.getOrNull(index))
    }

    private fun succeed(cred: PublicKeyCredential, chosenName: String?) {
        if (done) return
        done = true
        val json = PasskeyJson.ensureClientDataField(PasskeyJson.fromMap(cred.toMap(SerializationType.JSON)))
        val credId = PasskeyJson.b64(cred.rawId)
        runCatching {
            if (isCreate) {
                store.remember(rpId, credId, createUserName, createDisplayName)
            } else {
                val name = chosenName?.substringBefore(" · ")?.takeUnless { it.startsWith("Passkey ") }
                val display = chosenName?.substringAfter(" · ", "")?.ifBlank { null }
                store.remember(rpId, credId, name, display)
            }
        }
        finish(PasskeyResult.Success(json.toString()))
    }

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    private fun handleError(e: Throwable, device: YubiKeyDevice) {
        val isNfc = device is NfcYubiKeyDevice
        val again = if (isNfc) "then tap your YubiKey again" else "then press Continue"
        val ctap = generateSequence(e) { it.cause }.filterIsInstance<CtapException>().firstOrNull()?.ctapError

        fun retry(msg: String, dom: DomError = NotAllowedError(), pinMode: PinMode? = null, hint: String? = null) {
            lastDomError = dom
            lastErrorMessage = msg
            _ui.update {
                it.copy(phase = Phase.READY, error = msg, pinMode = pinMode ?: it.pinMode, pinHint = hint ?: it.pinHint,
                    instruction = waitingText())
            }
        }

        when {
            e is PasskeyCeremony.NeedPinChange -> {
                pin.value = ""; newPin.value = ""; newPinRepeat.value = ""
                retry("Your YubiKey requires a new FIDO2 PIN before it can be used. Enter the current and a new PIN, $again.",
                    pinMode = PinMode.CHANGE, hint = null)
            }
            e is PasskeyCeremony.NeedPinSetup || ctap == CtapException.ERR_PIN_NOT_SET -> {
                newPin.value = ""; newPinRepeat.value = ""
                retry("$rpId requires a PIN, and this YubiKey doesn't have one yet. Choose a FIDO2 PIN (at least ${_ui.value.minPinLength} characters), $again.",
                    pinMode = PinMode.SET_NEW, hint = "You'll use this PIN with this YubiKey on every device.")
            }
            e is PinRequiredClientError ->
                retry("This YubiKey has a FIDO2 PIN. Enter it, $again.", pinMode = PinMode.ENTER, hint = null)
            e is AuthInvalidClientError && e.authType == AuthInvalidClientError.AuthType.UV ->
                retry(if (e.retries > 0) "Fingerprint not recognized (${e.retries} tries left). Try again or enter your PIN."
                    else "Fingerprint is blocked. Enter your PIN instead.", pinMode = PinMode.ENTER, hint = null)
            e is AuthInvalidClientError -> {
                pin.value = ""
                if (e.retries <= 0) fatal("The FIDO2 PIN is blocked after too many wrong attempts. Reset FIDO2 in YK Manager to use this key again (this deletes its passkeys).", NotAllowedError())
                else retry("Incorrect PIN. ${e.retries} ${if (e.retries == 1) "try" else "tries"} left before the PIN is blocked.",
                    pinMode = if (_ui.value.pinMode == PinMode.NONE) PinMode.ENTER else _ui.value.pinMode)
            }
            ctap == CtapException.ERR_PIN_AUTH_BLOCKED ->
                retry("Too many wrong PINs in a row. Remove the YubiKey (or lift it off the phone), reconnect it, $again.")
            ctap == CtapException.ERR_PIN_BLOCKED ->
                fatal("The FIDO2 PIN is blocked. Reset FIDO2 in YK Manager to use this key again (this deletes its passkeys).", NotAllowedError())
            ctap == CtapException.ERR_PIN_POLICY_VIOLATION ->
                retry("The new PIN doesn't meet this YubiKey's PIN rules. Choose a longer or less simple PIN.")
            ctap == CtapException.ERR_CREDENTIAL_EXCLUDED ->
                fatal("This YubiKey already has a passkey for this account on $rpId.", InvalidStateError())
            ctap == CtapException.ERR_NO_CREDENTIALS ->
                retry("This YubiKey has no passkey for $rpId. Try another key, $again.")
            ctap == CtapException.ERR_KEY_STORE_FULL ->
                fatal("This YubiKey has no free passkey slots. Delete passkeys you no longer use in YK Manager > Passkeys.", NotAllowedError())
            ctap == CtapException.ERR_UV_BLOCKED ->
                retry("Fingerprint is blocked. Enter your PIN instead.", pinMode = PinMode.ENTER)
            ctap == CtapException.ERR_OPERATION_DENIED || ctap == CtapException.ERR_USER_ACTION_TIMEOUT ||
                ctap == CtapException.ERR_ACTION_TIMEOUT || ctap == CtapException.ERR_KEEPALIVE_CANCEL ->
                retry("The YubiKey wasn't touched in time. Try again, $again.")
            ctap == CtapException.ERR_UNSUPPORTED_ALGORITHM ->
                fatal("$rpId asked for a key type this YubiKey doesn't support.", NotSupportedError())
            e is ClientError && e.message?.contains("RP ID") == true ->
                fatal("The request is for a different website than the one asking. It was blocked for your safety.", SecurityError())
            e is ClientError && e.message?.contains("CTAP1") == true ->
                fatal("This key only supports U2F, which can't hold passkeys. It still works as a second factor on sites that ask for your password first. " +
                    "For passkeys, use a YubiKey 5 series, Bio or Security Key with FIDO2.", NotSupportedError())
            e is ClientError && e.errorCode == ClientError.Code.DEVICE_INELIGIBLE ->
                retry(if (isCreate) "This YubiKey can't be used to save this passkey (it may already have one for this account)."
                    else "This YubiKey has no passkey for $rpId. Try another key, $again.")
            e is ClientError && e.errorCode == ClientError.Code.CONFIGURATION_UNSUPPORTED ->
                fatal("$rpId requires a feature this YubiKey doesn't support: ${e.message?.substringAfter(" - ")}", NotSupportedError())
            e is IOException || e is ConnectionFailed -> {
                if (isNfc) { nfcDevice = null; _ui.update { it.copy(nfcKeyPresent = false) } }
                retry(if (isNfc) "The YubiKey moved away before it finished. Hold it still against the back of the phone until this sheet closes, and tap again."
                    else "Lost the connection to the YubiKey. Reconnect it and press Continue.")
            }
            else -> retry("Something went wrong: ${e.message ?: e.javaClass.simpleName}. Try again.")
        }
    }

    private fun fatal(message: String, dom: DomError) {
        lastDomError = dom
        lastErrorMessage = message
        _ui.update { it.copy(phase = Phase.FATAL, error = message, instruction = "") }
    }

    fun clearError() { _ui.update { it.copy(error = null) } }

    /** User closed the sheet. Report the last real error, or a cancellation. */
    fun cancel() {
        commandState?.cancel()
        if (done) return
        done = true
        val dom = lastDomError
        val msg = lastErrorMessage
        finish(
            if (isCreate) PasskeyResult.CreateFailed(
                if (dom != null && _ui.value.phase == Phase.FATAL) CreatePublicKeyCredentialDomException(dom, msg)
                else CreateCredentialCancellationException("Cancelled on the YubiKey prompt")
            ) else PasskeyResult.GetFailed(
                if (dom != null && _ui.value.phase == Phase.FATAL) GetPublicKeyCredentialDomException(dom, msg)
                else GetCredentialCancellationException("Cancelled on the YubiKey prompt")
            )
        )
    }

    // ------------------------------------------------------------------
    // Connections
    // ------------------------------------------------------------------

    private class ConnectionFailed(cause: Throwable) : IOException(cause)

    /**
     * Open the FIDO interface (HID over USB, smart card over NFC) and run
     * [block] while it's open. Over NFC the ISO-DEP reconnect is retried
     * briefly, since Android sometimes refuses it right after a tap.
     */
    private suspend fun <T> withConnection(device: YubiKeyDevice, block: (YubiKeyConnection) -> T): T {
        val type: Class<out YubiKeyConnection> =
            if (device is UsbYubiKeyDevice && device.supportsConnection(FidoConnection::class.java)) FidoConnection::class.java
            else SmartCardConnection::class.java
        var attempt = 0
        while (true) {
            val r = suspendCancellableCoroutine<Result<T>> { cont ->
                device.requestConnection(type) { result ->
                    val conn = try { result.value } catch (e: Throwable) {
                        cont.resume(Result.failure(ConnectionFailed(e))); return@requestConnection
                    }
                    cont.resume(runCatching { block(conn) })
                }
            }
            val e = r.exceptionOrNull() ?: return r.getOrThrow()
            if (e is ConnectionFailed && device is NfcYubiKeyDevice && attempt++ < 4) { delay(150); continue }
            throw e
        }
    }
}
