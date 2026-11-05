package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.CommandException
import com.yubico.yubikit.fido.ctap.BioEnrollment
import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.CredentialManagement
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.FingerprintBioEnrollment
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class Passkey(
    val rpId: String,
    val userName: String,
    val displayName: String?,
    val credentialId: Map<String, *>,
)

data class Fingerprint(val templateId: ByteArray, val name: String) {
    val id: String get() = templateId.joinToString("") { "%02x".format(it) }
}

/** Progress of an ongoing fingerprint enrollment. */
data class EnrollProgress(
    val name: String,
    val remaining: Int? = null,
    val total: Int? = null,
    val feedback: String? = null,
    val done: Boolean = false,
    val failed: String? = null,
)

data class FidoState(
    val loaded: Boolean = false,
    val bioSupported: Boolean = false,
    val bioEnrolled: Boolean = false,
    val fingerprints: List<Fingerprint>? = null,  // null until unlocked with the PIN
    val maxFingerprintName: Int = 15,
    val versions: List<String> = emptyList(),
    val aaguid: String? = null,
    val pinSet: Boolean = false,
    val pinRetries: Int? = null,
    val minPinLength: Int = 4,
    val forcePinChange: Boolean = false,
    val remainingCredentials: Int? = null,
    val credMgmtSupported: Boolean = false,
    val alwaysUv: Boolean? = null,
    val passkeys: List<Passkey>? = null,   // null until unlocked with the PIN
    val existingCount: Int? = null,
)

class FidoFeature(private val core: YubiKeyCore) {

    private val _state = MutableStateFlow(FidoState())
    val state: StateFlow<FidoState> = _state.asStateFlow()

    /** PIN remembered for this app session once the user unlocks passkeys. */
    private var rememberedPin: CharArray? = null

    fun clear() {
        _state.value = FidoState()
        rememberedPin = null
    }

    private fun protocol(info: Ctap2Session.InfoData): PinUvAuthProtocol =
        if (info.pinUvAuthProtocols.contains(2)) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()

    suspend fun refresh(device: YubiKeyDevice) {
        val pin = rememberedPin
        _state.value = core.fido(device) { s ->
            val info = s.cachedInfo
            val opts = info.options
            val pinSet = opts["clientPin"] == true
            val cp = ClientPin(s, protocol(info))
            val retries = if (pinSet) runCatching { cp.pinRetries.count }.getOrNull() else null
            val cmSupported = CredentialManagement.isSupported(info)
            val bioSupported = BioEnrollment.isSupported(info)
            var passkeys: List<Passkey>? = null
            var existing: Int? = null
            var fingerprints: List<Fingerprint>? = null
            var maxName = 15
            if (pin != null && pinSet && cmSupported) {
                runCatching { enumerate(s, info, pin) }.onSuccess {
                    passkeys = it.first; existing = it.second
                }.onFailure { rememberedPin = null }
            }
            if (pin != null && pinSet && bioSupported && rememberedPin != null) {
                runCatching {
                    val be = bioEnroll(s, info, pin)
                    maxName = runCatching { be.sensorInfo.maxTemplateFriendlyName }.getOrDefault(15)
                    be.enumerateEnrollments().map { (id, name) -> Fingerprint(id, name ?: "(unnamed)") }
                        .sortedBy { it.name }
                }.onSuccess { fingerprints = it }
            }
            FidoState(
                loaded = true,
                bioSupported = bioSupported,
                bioEnrolled = BioEnrollment.isConfigured(info),
                fingerprints = fingerprints,
                maxFingerprintName = maxName,
                versions = info.versions,
                aaguid = info.aaguid.joinToString("") { "%02x".format(it) }.let {
                    "${it.substring(0, 8)}-${it.substring(8, 12)}-${it.substring(12, 16)}-${it.substring(16, 20)}-${it.substring(20)}"
                },
                pinSet = pinSet,
                pinRetries = retries,
                minPinLength = info.minPinLength,
                forcePinChange = info.forcePinChange,
                remainingCredentials = info.remainingDiscoverableCredentials,
                credMgmtSupported = cmSupported,
                alwaysUv = opts["alwaysUv"] as? Boolean,
                passkeys = passkeys,
                existingCount = existing,
            )
        }
    }

    private fun credMgmt(s: Ctap2Session, info: Ctap2Session.InfoData, pin: CharArray): CredentialManagement {
        val proto = protocol(info)
        val cp = ClientPin(s, proto)
        val perms = if (ClientPin.isTokenSupported(info)) ClientPin.PIN_PERMISSION_CM else null
        val token = try {
            cp.getPinToken(pin, perms, null)
        } catch (e: CommandException) {
            throw UserFacingException("PIN was not accepted (${KeyErrors.ctap(e)}).")
        }
        return CredentialManagement(s, proto, token)
    }

    private fun bioEnroll(s: Ctap2Session, info: Ctap2Session.InfoData, pin: CharArray): FingerprintBioEnrollment {
        val proto = protocol(info)
        val cp = ClientPin(s, proto)
        val perms = if (ClientPin.isTokenSupported(info)) ClientPin.PIN_PERMISSION_BE else null
        val token = try {
            cp.getPinToken(pin, perms, null)
        } catch (e: CommandException) {
            throw UserFacingException("PIN was not accepted (${KeyErrors.ctap(e)}).")
        }
        return FingerprintBioEnrollment(s, proto, token)
    }

    private fun enumerate(s: Ctap2Session, info: Ctap2Session.InfoData, pin: CharArray): Pair<List<Passkey>, Int> {
        val cm = credMgmt(s, info, pin)
        val meta = cm.metadata
        val list = mutableListOf<Passkey>()
        if (meta.existingResidentCredentialsCount > 0) {
            for (rp in cm.enumerateRps()) {
                val rpId = rp.rp["id"] as? String ?: "?"
                for (c in cm.enumerateCredentials(rp.rpIdHash)) {
                    list += Passkey(
                        rpId = rpId,
                        userName = c.user["name"] as? String ?: "(no name)",
                        displayName = c.user["displayName"] as? String,
                        credentialId = c.credentialId,
                    )
                }
            }
        }
        return list.sortedWith(compareBy({ it.rpId }, { it.userName })) to meta.existingResidentCredentialsCount
    }

    fun unlock(pin: CharArray) {
        rememberedPin = pin
        core.run("list your passkeys") { }
    }

    fun lock() {
        rememberedPin = null
        _state.value = _state.value.copy(passkeys = null, fingerprints = null)
    }

    // ------------------------------------------------------------------
    // Fingerprints (YubiKey Bio)
    // ------------------------------------------------------------------

    private val _enroll = MutableStateFlow<EnrollProgress?>(null)
    val enroll: StateFlow<EnrollProgress?> = _enroll.asStateFlow()

    @Volatile private var cancelEnroll = false

    fun dismissEnroll() { _enroll.value = null }
    fun cancelEnroll() { cancelEnroll = true }

    /**
     * Enroll a new fingerprint. The key asks for several samples; each call to
     * capture() blocks until the sensor is touched, then reports quality
     * feedback. Over NFC enrollment is not possible (the sensor needs USB power).
     */
    fun enrollFingerprint(name: String) {
        val pin = rememberedPin ?: return core.error("Unlock with your PIN first")
        if (!core.isUsb) return core.error("Fingerprints can only be enrolled over USB")
        cancelEnroll = false
        _enroll.value = EnrollProgress(name)
        core.run("enroll a fingerprint") { device ->
            core.fido(device) { s ->
                val be = bioEnroll(s, s.cachedInfo, pin)
                val total = runCatching { be.sensorInfo.maxCaptureSamplesRequiredForEnroll }.getOrNull()
                _enroll.value = EnrollProgress(name, total, total)
                val ctx = be.enroll(30_000)
                var templateId: ByteArray? = null
                try {
                    while (templateId == null) {
                        if (cancelEnroll) {
                            runCatching { ctx.cancel() }
                            _enroll.value = null
                            return@fido
                        }
                        core.showTouchPrompt(true)
                        try {
                            templateId = ctx.capture(core.touchState())
                            _enroll.value = EnrollProgress(name, ctx.remaining, total, "Good sample")
                        } catch (e: FingerprintBioEnrollment.CaptureError) {
                            _enroll.value = EnrollProgress(name, ctx.remaining, total, captureFeedback(e.code))
                        } finally {
                            core.showTouchPrompt(false)
                        }
                    }
                } catch (e: Exception) {
                    runCatching { ctx.cancel() }
                    _enroll.value = EnrollProgress(name, failed = describeEnrollError(e))
                    throw UserFacingException("Enrollment failed: ${describeEnrollError(e)}")
                }
                if (name.isNotBlank()) runCatching { be.setName(templateId, name) }
                _enroll.value = EnrollProgress(name, 0, total, done = true)
            }
            core.toast("Fingerprint \"$name\" enrolled")
        }
    }

    private fun describeEnrollError(e: Exception): String = when (e) {
        is CommandException -> KeyErrors.ctap(e)
        else -> YubiKeyCore.describe(e)
    }

    private fun captureFeedback(code: Int): String = when (code) {
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_HIGH -> "Move your finger lower"
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_LOW -> "Move your finger higher"
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_LEFT -> "Move your finger to the right"
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_RIGHT -> "Move your finger to the left"
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_FAST -> "Too fast, hold a little longer"
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_SLOW -> "Too slow, lift and try again"
        FingerprintBioEnrollment.FEEDBACK_FP_POOR_QUALITY -> "Poor quality, try again"
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_SKEWED -> "Finger was skewed, straighten it"
        FingerprintBioEnrollment.FEEDBACK_FP_TOO_SHORT -> "Touch was too short"
        FingerprintBioEnrollment.FEEDBACK_FP_MERGE_FAILURE -> "Could not merge sample, try again"
        FingerprintBioEnrollment.FEEDBACK_FP_EXISTS -> "This fingerprint is already enrolled"
        FingerprintBioEnrollment.FEEDBACK_NO_USER_ACTIVITY -> "No touch detected, try again"
        FingerprintBioEnrollment.FEEDBACK_NO_UP_TRANSITION -> "Lift your finger between samples"
        else -> "Sample not accepted (code $code), try again"
    }

    fun renameFingerprint(fp: Fingerprint, newName: String) {
        val pin = rememberedPin ?: return core.error("Unlock with your PIN first")
        core.run("rename the fingerprint") { device ->
            core.fido(device) { s -> bioEnroll(s, s.cachedInfo, pin).setName(fp.templateId, newName) }
            core.toast("Fingerprint renamed")
        }
    }

    fun deleteFingerprint(fp: Fingerprint) {
        val pin = rememberedPin ?: return core.error("Unlock with your PIN first")
        core.run("delete the fingerprint") { device ->
            core.fido(device) { s -> bioEnroll(s, s.cachedInfo, pin).removeEnrollment(fp.templateId) }
            core.toast("Fingerprint \"${fp.name}\" deleted")
        }
    }

    fun setPin(newPin: CharArray) {
        core.run("set the FIDO2 PIN") { device ->
            core.fido(device) { s ->
                val info = s.cachedInfo
                if (newPin.size < info.minPinLength) throw UserFacingException("PIN must be at least ${info.minPinLength} characters")
                ClientPin(s, protocol(info)).setPin(newPin)
            }
            core.toast("FIDO2 PIN set")
        }
    }

    fun changePin(current: CharArray, newPin: CharArray) {
        core.run("change the FIDO2 PIN") { device ->
            core.fido(device) { s ->
                val info = s.cachedInfo
                if (newPin.size < info.minPinLength) throw UserFacingException("PIN must be at least ${info.minPinLength} characters")
                try {
                    ClientPin(s, protocol(info)).changePin(current, newPin)
                } catch (e: CommandException) {
                    throw UserFacingException("Could not change PIN (${KeyErrors.ctap(e)}).")
                }
            }
            if (rememberedPin != null) rememberedPin = newPin
            core.toast("FIDO2 PIN changed")
        }
    }

    fun delete(passkey: Passkey) {
        val pin = rememberedPin ?: return core.error("Unlock with your PIN first")
        core.run("delete the passkey") { device ->
            core.fido(device) { s -> credMgmt(s, s.cachedInfo, pin).deleteCredential(passkey.credentialId) }
            // Reflect the deletion immediately; the refresh that follows may not reach the key over NFC.
            _state.value = _state.value.copy(
                passkeys = _state.value.passkeys?.filterNot { it.credentialId == passkey.credentialId },
                existingCount = _state.value.existingCount?.let { (it - 1).coerceAtLeast(0) },
            )
            core.toast("Passkey for ${passkey.rpId} deleted")
        }
    }

    /** FIDO reset must happen within seconds of the key being powered up. */
    fun reset() {
        core.runOnFreshInsert("reset FIDO") { device ->
            core.showTouchPrompt(true)
            core.fido(device) { s -> s.reset(core.touchState()) }
            rememberedPin = null
            core.toast("FIDO application reset. All passkeys and the PIN were removed.")
        }
    }
}

object KeyErrors {
    fun ctap(e: CommandException): String {
        val m = e.message ?: return e.javaClass.simpleName
        return when {
            m.contains("0x31") || m.contains("PIN_INVALID", true) -> "wrong PIN"
            m.contains("0x32") || m.contains("PIN_BLOCKED", true) -> "PIN blocked, reset FIDO to recover"
            m.contains("0x34") || m.contains("PIN_AUTH_BLOCKED", true) -> "too many wrong attempts, remove and reinsert the key"
            m.contains("0x37") || m.contains("PIN_POLICY", true) -> "PIN does not meet the policy"
            m.contains("0x30") || m.contains("NOT_ALLOWED", true) -> "not allowed. Reset must happen right after inserting the key"
            else -> m
        }
    }
}
