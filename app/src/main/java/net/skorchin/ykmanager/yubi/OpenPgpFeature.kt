package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.core.Version
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.InvalidPinException
import com.yubico.yubikit.core.smartcard.Apdu
import com.yubico.yubikit.core.smartcard.AppId
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.core.smartcard.SmartCardProtocol
import com.yubico.yubikit.core.util.Tlvs
import com.yubico.yubikit.openpgp.Do
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import com.yubico.yubikit.openpgp.Uif
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.nio.ByteBuffer

data class PgpKey(
    val ref: KeyRef,
    val fingerprint: String?,
    val created: Long?,
    val status: String?,
    val touch: Uif?,
    val algorithm: String? = null,
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

    companion object {
        private val CURVE_NAMES = mapOf(
            "2a8648ce3d030107" to "NIST P-256", "2b81040022" to "NIST P-384", "2b81040023" to "NIST P-521",
            "2b2403030208010107" to "brainpoolP256r1", "2b240303020801010b" to "brainpoolP384r1",
            "2b240303020801010d" to "brainpoolP512r1", "2b8104000a" to "secp256k1",
            "2b06010401da470f01" to "Ed25519", "2b060104019755010501" to "X25519",
            "2b6570" to "Ed25519", "2b656e" to "X25519", "2b6571" to "Ed448", "2b656f" to "X448",
        )

        /**
         * Build an [OpenPgpSession], turning YubiKit's parse failures for key
         * types it does not know into a clear message.
         */
        fun openSession(conn: SmartCardConnection): OpenPgpSession = try {
            OpenPgpSession(conn)
        } catch (e: IllegalArgumentException) {
            throw UserFacingException(
                "This key's OpenPGP slots use a key type the bundled YubiKit library can't handle yet " +
                    "(${e.message}). Reading works, but PIN and touch changes must be made with GnuPG or ykman.")
        }
    }

    private val _state = MutableStateFlow(PgpState())
    val state: StateFlow<PgpState> = _state.asStateFlow()

    fun clear() { _state.value = PgpState() }

    /**
     * Read the OpenPGP applet without going through [OpenPgpSession].
     *
     * YubiKit's session constructor parses the algorithm attributes of every
     * key slot and throws "Not a supported curve OID" (or "Unsupported
     * algorithm ID") when a slot holds a key type it does not know, which made
     * the whole screen fail for keys set up with GnuPG using such curves.
     * Reading the data objects directly and describing unknown algorithms
     * by their OID keeps the screen working for every key.
     */
    suspend fun refresh(device: YubiKeyDevice) {
        _state.value = core.smartCard(device) { conn ->
            val p = SmartCardProtocol(conn)
            p.select(AppId.OPENPGP)
            val outer = Tlvs.decodeMap(Tlvs.unpackValue(Do.APPLICATION_RELATED_DATA, p.getData(Do.APPLICATION_RELATED_DATA)))
            val aid = outer[Do.AID] ?: ByteArray(16)
            val version = Version(bcd(aid[6]), bcd(aid[7]), 0)
            val disc = Tlvs.decodeMap(outer[0x73] ?: ByteArray(0))
            val pw = disc[Do.PW_STATUS_BYTES] ?: ByteArray(7)
            val fps = disc[0xC5] ?: ByteArray(0)
            val times = disc[0xCD] ?: ByteArray(0)
            val info = disc[0xDE] ?: ByteArray(0)
            val refs = listOf(KeyRef.SIG, KeyRef.DEC, KeyRef.AUT) +
                if (version.isAtLeast(5, 2, 0)) listOf(KeyRef.ATT) else emptyList()
            val keys = refs.mapIndexed { i, ref ->
                val fp = fps.copyOfRange(i * 20, minOf(fps.size, i * 20 + 20)).takeIf { b -> b.size == 20 && b.any { it.toInt() != 0 } }
                    ?.joinToString("") { "%02X".format(it) }?.chunked(4)?.joinToString(" ")
                val gen = if (times.size >= i * 4 + 4) ByteBuffer.wrap(times, i * 4, 4).int.toLong() and 0xFFFFFFFFL else 0L
                val status = (0 until info.size / 2).map { info[it * 2].toInt() and 0xff to info[it * 2 + 1].toInt() }
                    .firstOrNull { it.first == ref.value.toInt() }?.second
                    ?.let { when (it) { 0 -> "none"; 1 -> "generated"; 2 -> "imported"; else -> "unknown" } }
                val uifTag = when (ref) { KeyRef.SIG -> Do.UIF_SIG; KeyRef.DEC -> Do.UIF_DEC; KeyRef.AUT -> Do.UIF_AUT; KeyRef.ATT -> Do.UIF_ATT }
                val uif = disc[uifTag]?.firstOrNull()?.let { b -> runCatching { Uif.fromValue(b) }.getOrNull() }
                val algTag = when (ref) {
                    KeyRef.SIG -> Do.ALGORITHM_ATTRIBUTES_SIG; KeyRef.DEC -> Do.ALGORITHM_ATTRIBUTES_DEC
                    KeyRef.AUT -> Do.ALGORITHM_ATTRIBUTES_AUT; KeyRef.ATT -> Do.ALGORITHM_ATTRIBUTES_ATT
                }
                PgpKey(ref, fp, gen.takeIf { it > 0 }?.let { it * 1000L }, status, uif, disc[algTag]?.let { describeAlgorithm(it) })
            }
            val sigCounter = runCatching {
                val sst = Tlvs.decodeMap(Tlvs.unpackValue(Do.SECURITY_SUPPORT_TEMPLATE, p.getData(Do.SECURITY_SUPPORT_TEMPLATE)))
                sst[0x93]?.let { b -> ((b[0].toInt() and 0xff) shl 16) or ((b[1].toInt() and 0xff) shl 8) or (b[2].toInt() and 0xff) }
            }.getOrNull()
            PgpState(
                loaded = true,
                version = version,
                userAttempts = pw.getOrNull(4)?.toInt()?.and(0xff),
                resetAttempts = pw.getOrNull(5)?.toInt()?.and(0xff),
                adminAttempts = pw.getOrNull(6)?.toInt()?.and(0xff),
                signatureCounter = sigCounter,
                signaturePinPolicy = pw.getOrNull(0)?.let { if (it.toInt() == 0) "always" else "once" },
                keys = keys,
            )
        }
    }

    private fun SmartCardProtocol.getData(doId: Int): ByteArray =
        sendAndReceive(Apdu(0, 0xCA, doId shr 8, doId and 0xff, null))

    private fun bcd(b: Byte): Int = ((b.toInt() shr 4) and 0xf) * 10 + (b.toInt() and 0xf)

    /** Human-readable form of an OpenPGP algorithm attributes DO, tolerant of unknown values. */
    private fun describeAlgorithm(attr: ByteArray): String {
        if (attr.isEmpty()) return "unknown"
        return when (val id = attr[0].toInt() and 0xff) {
            0x01 -> {
                val bits = if (attr.size >= 3) ((attr[1].toInt() and 0xff) shl 8) or (attr[2].toInt() and 0xff) else 0
                "RSA $bits"
            }
            0x12, 0x13, 0x16 -> {
                val kind = when (id) { 0x12 -> "ECDH"; 0x13 -> "ECDSA"; else -> "EdDSA" }
                var oid = attr.copyOfRange(1, attr.size)
                if (oid.isNotEmpty() && (oid.last().toInt() and 0xff) == 0xFF) oid = oid.copyOfRange(0, oid.size - 1)
                val hex = oid.joinToString("") { "%02x".format(it) }
                val name = CURVE_NAMES[hex] ?: "curve OID ${decodeOid(oid)}"
                "$kind $name"
            }
            else -> "algorithm 0x%02X".format(id)
        }
    }

    private fun decodeOid(oid: ByteArray): String {
        if (oid.isEmpty()) return "?"
        val parts = mutableListOf<Long>()
        var value = 0L
        for ((i, b) in oid.withIndex()) {
            value = (value shl 7) or (b.toLong() and 0x7f)
            if (b.toInt() and 0x80 == 0) {
                if (parts.isEmpty()) { parts += value / 40; parts += value % 40 } else parts += value
                value = 0
            }
            if (i == oid.size - 1 && b.toInt() and 0x80 != 0) parts += value // truncated
        }
        return parts.joinToString(".")
    }

    private fun op(name: String, done: String, block: (OpenPgpSession) -> Unit) {
        core.run(name) { device ->
            core.smartCard(device) { conn ->
                try {
                    block(openSession(conn))
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
