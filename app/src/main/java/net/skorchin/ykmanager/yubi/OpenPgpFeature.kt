package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.core.Version
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.InvalidPinException
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import com.yubico.yubikit.openpgp.Uif
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class PgpKey(
    val ref: KeyRef,
    val fingerprint: String?,
    val created: Long?,
    val status: String?,
    val touch: Uif?,
)

data class PgpState(
    val loaded: Boolean = false,
    val version: Version? = null,
    val userAttempts: Int? = null,
    val resetAttempts: Int? = null,
    val adminAttempts: Int? = null,
    val signatureCounter: Int? = null,
    val signaturePinPolicy: String? = null,
    val keys: List<PgpKey> = emptyList(),
)

class OpenPgpFeature(private val core: YubiKeyCore) {

    private val _state = MutableStateFlow(PgpState())
    val state: StateFlow<PgpState> = _state.asStateFlow()

    fun clear() { _state.value = PgpState() }

    suspend fun refresh(device: YubiKeyDevice) {
        _state.value = core.smartCard(device) { conn ->
            val s = OpenPgpSession(conn)
            val data = s.applicationRelatedData
            val disc = data.discretionary
            val pw = disc.pwStatus
            val refs = listOf(KeyRef.SIG, KeyRef.DEC, KeyRef.AUT) +
                if (s.version.isAtLeast(5, 2, 0)) listOf(KeyRef.ATT) else emptyList()
            val keys = refs.map { ref ->
                val fp = runCatching { disc.getFingerprint(ref) }.getOrNull()
                    ?.takeIf { b -> b.any { it.toInt() != 0 } }
                    ?.joinToString("") { "%02X".format(it) }?.chunked(4)?.joinToString(" ")
                val gen = runCatching { disc.getGenerationTime(ref) }.getOrNull()?.takeIf { it > 0 }
                val status = runCatching { disc.getKeyStatus(ref)?.name?.lowercase() }.getOrNull()
                val uif = runCatching { s.getUif(ref) }.getOrNull()
                PgpKey(ref, fp, gen?.let { it * 1000L }, status, uif)
            }
            PgpState(
                loaded = true,
                version = s.version,
                userAttempts = pw.attemptsUser,
                resetAttempts = pw.attemptsReset,
                adminAttempts = pw.attemptsAdmin,
                signatureCounter = runCatching { s.signatureCounter }.getOrNull(),
                signaturePinPolicy = pw.pinPolicyUser.name.lowercase(),
                keys = keys,
            )
        }
    }

    private fun op(name: String, done: String, block: (OpenPgpSession) -> Unit) {
        core.run(name) { device ->
            core.smartCard(device) { conn ->
                try {
                    block(OpenPgpSession(conn))
                } catch (e: InvalidPinException) {
                    throw UserFacingException("Wrong PIN. ${e.attemptsRemaining} attempt(s) remaining.")
                }
            }
            core.toast(done)
        }
    }

    fun changeUserPin(old: CharArray, new: CharArray) =
        op("change the user PIN", "User PIN changed") { it.changeUserPin(old, new) }

    fun changeAdminPin(old: CharArray, new: CharArray) =
        op("change the admin PIN", "Admin PIN changed") { it.changeAdminPin(old, new) }

    fun setResetCode(admin: CharArray, code: CharArray) =
        op("set the reset code", "Reset code set") { it.verifyAdminPin(admin); it.setResetCode(code) }

    fun unblockWithResetCode(resetCode: CharArray, newPin: CharArray) =
        op("unblock the user PIN", "User PIN unblocked") { it.resetPin(newPin, resetCode) }

    fun unblockWithAdmin(admin: CharArray, newPin: CharArray) =
        op("unblock the user PIN", "User PIN unblocked") { it.verifyAdminPin(admin); it.resetPin(newPin, null) }

    fun setRetries(admin: CharArray, user: Int, reset: Int, adminRetries: Int) =
        op("set retry counts", "Retry counts set. PINs were reset to defaults (123456 / 12345678).") {
            it.verifyAdminPin(admin); it.setPinAttempts(user, reset, adminRetries)
        }

    fun setTouch(admin: CharArray, ref: KeyRef, uif: Uif) =
        op("set the touch policy", "Touch policy for ${ref.name} set to ${uif.name.lowercase()}") {
            it.verifyAdminPin(admin); it.setUif(ref, uif)
        }

    fun reset() = op("reset OpenPGP", "OpenPGP reset. PIN 123456, admin PIN 12345678.") { it.reset() }
}
