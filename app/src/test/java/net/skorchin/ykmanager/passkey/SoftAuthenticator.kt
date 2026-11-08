package net.skorchin.ykmanager.passkey

import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.Cbor
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A minimal software CTAP2 authenticator reached over the smart card
 * (NFC) transport, the same path a YubiKey tapped on a phone uses:
 * SELECT FIDO AID, then NFCCTAP_MSG APDUs carrying CBOR.
 *
 * Supports getInfo, clientPin (PIN/UV auth protocol 1: retries, key
 * agreement, setPin, changePin, getPinToken), makeCredential,
 * getAssertion and getNextAssertion, with resident credentials.
 */
class SoftAuthenticator(
    var pin: String? = null,
    var forcePinChange: Boolean = false,
) : SmartCardConnection {

    class Cred(val rpId: String, val id: ByteArray, val user: Map<String, Any?>, val keys: KeyPair, val resident: Boolean)

    val credentials = mutableListOf<Cred>()
    var pinRetries = 8
    private val rnd = SecureRandom()
    private val aaguid = ByteArray(16) { it.toByte() }
    private var counter = 0
    private var agreementKey: KeyPair = newEcKey()
    private var pinToken: ByteArray = ByteArray(32).also { rnd.nextBytes(it) }
    private val pending = ArrayDeque<Map<Int, Any?>>()

    override fun getTransport(): Transport = Transport.NFC
    override fun isExtendedLengthApduSupported(): Boolean = true
    override fun getAtr(): ByteArray = ByteArray(0)
    override fun close() {}

    override fun sendAndReceive(apdu: ByteArray): ByteArray {
        val ins = apdu[1].toInt() and 0xFF
        val data = apduData(apdu)
        return when (ins) {
            0xA4 -> "U2F_V2".toByteArray() + ok()
            0x10 -> {
                val cmd = data[0].toInt() and 0xFF
                val params = if (data.size > 1) (Cbor.decode(data, 1, data.size - 1) as Map<*, *>) else emptyMap<Any, Any>()
                @Suppress("UNCHECKED_CAST")
                val res = handle(cmd, params as Map<Int, Any?>)
                val (status, body) = res
                byteArrayOf(status.toByte()) + (body?.let { Cbor.encode(it) } ?: ByteArray(0)) + ok()
            }
            else -> byteArrayOf(0x6D, 0x00)
        }
    }

    private fun ok() = byteArrayOf(0x90.toByte(), 0x00)

    private fun apduData(a: ByteArray): ByteArray {
        if (a.size <= 5) return ByteArray(0)
        return if (a[4].toInt() == 0 && a.size >= 7) {
            val lc = ((a[5].toInt() and 0xFF) shl 8) or (a[6].toInt() and 0xFF)
            a.copyOfRange(7, 7 + lc)
        } else {
            val lc = a[4].toInt() and 0xFF
            a.copyOfRange(5, 5 + lc)
        }
    }

    // ------------------------------------------------------------------

    private fun handle(cmd: Int, p: Map<Int, Any?>): Pair<Int, Any?> = when (cmd) {
        0x04 -> 0 to getInfo()
        0x06 -> clientPin(p)
        0x01 -> makeCredential(p)
        0x02 -> getAssertion(p)
        0x08 -> if (pending.isEmpty()) 0x30 to null else 0 to pending.removeFirst()
        else -> 0x01 to null
    }

    private fun getInfo(): Map<Int, Any?> = mapOf(
        1 to listOf("FIDO_2_0", "U2F_V2"),
        2 to emptyList<String>(),
        3 to aaguid,
        4 to mapOf("rk" to true, "up" to true, "plat" to false, "clientPin" to (pin != null)),
        5 to 1200,
        6 to listOf(1),
        7 to 8,
        8 to 128,
        0x0C to forcePinChange,
        0x0D to 4,
    )

    // ------------------------------------------------------------------
    // clientPin, PIN/UV auth protocol 1
    // ------------------------------------------------------------------

    private fun clientPin(p: Map<Int, Any?>): Pair<Int, Any?> {
        return when (p[2] as Int) {
            0x01 -> 0 to mapOf(3 to pinRetries)
            0x02 -> 0 to mapOf(1 to cose(agreementKey.public as ECPublicKey, -25))
            0x03 -> { // setPin
                if (pin != null) return 0x30 to null
                val shared = shared(p)
                val newPinEnc = p[5] as ByteArray
                if (!hmac16(shared, newPinEnc).contentEquals(p[4] as ByteArray)) return 0x33 to null
                pin = decodePin(aes(shared, newPinEnc, false))
                0 to null
            }
            0x04 -> { // changePin
                val cur = pin ?: return 0x35 to null
                val shared = shared(p)
                val newPinEnc = p[5] as ByteArray
                val pinHashEnc = p[6] as ByteArray
                if (!hmac16(shared, newPinEnc + pinHashEnc).contentEquals(p[4] as ByteArray)) return 0x33 to null
                if (!aes(shared, pinHashEnc, false).contentEquals(left16(sha256(cur.toByteArray())))) {
                    pinRetries--; agreementKey = newEcKey(); return 0x31 to null
                }
                pin = decodePin(aes(shared, newPinEnc, false))
                forcePinChange = false
                pinRetries = 8
                0 to null
            }
            0x05 -> { // getPinToken
                val cur = pin ?: return 0x35 to null
                if (pinRetries <= 0) return 0x32 to null
                if (forcePinChange) return 0x37 to null
                val shared = shared(p)
                if (!aes(shared, p[6] as ByteArray, false).contentEquals(left16(sha256(cur.toByteArray())))) {
                    pinRetries--; agreementKey = newEcKey()
                    return 0x31 to null
                }
                pinRetries = 8
                pinToken = ByteArray(32).also { rnd.nextBytes(it) }
                0 to mapOf(2 to aes(shared, pinToken, true))
            }
            else -> 0x3E to null
        }
    }

    private fun shared(p: Map<Int, Any?>): ByteArray {
        @Suppress("UNCHECKED_CAST")
        val k = p[3] as Map<Int, Any?>
        val spec = ECPublicKeySpec(ECPoint(BigInteger(1, k[-2] as ByteArray), BigInteger(1, k[-3] as ByteArray)),
            (agreementKey.public as ECPublicKey).params)
        val peer = KeyFactory.getInstance("EC").generatePublic(spec)
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(agreementKey.private)
        ka.doPhase(peer, true)
        return sha256(ka.generateSecret())
    }

    private fun decodePin(padded: ByteArray): String = String(padded.takeWhile { it != 0.toByte() }.toByteArray())

    private fun aes(key: ByteArray, data: ByteArray, encrypt: Boolean): ByteArray {
        val c = Cipher.getInstance("AES/CBC/NoPadding")
        c.init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(ByteArray(16)))
        return c.doFinal(data)
    }

    private fun hmac16(key: ByteArray, msg: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256"); m.init(SecretKeySpec(key, "HmacSHA256"))
        return left16(m.doFinal(msg))
    }

    private fun checkUv(cdh: ByteArray, param: Any?): Int? {
        if (pin == null) return null
        if (param == null) return 0x36 // PUAT required
        return if (hmac16(pinToken, cdh).contentEquals(param as ByteArray)) null else 0x33
    }

    // ------------------------------------------------------------------
    // makeCredential / getAssertion
    // ------------------------------------------------------------------

    @Suppress("UNCHECKED_CAST")
    private fun makeCredential(p: Map<Int, Any?>): Pair<Int, Any?> {
        val cdh = p[1] as ByteArray
        val rp = p[2] as Map<String, Any?>
        val user = p[3] as Map<String, Any?>
        val rpId = rp["id"] as String
        (p[5] as? List<Map<String, Any?>>)?.forEach { d ->
            if (credentials.any { it.rpId == rpId && it.id.contentEquals(d["id"] as ByteArray) }) return 0x19 to null
        }
        checkUv(cdh, p[8])?.let { return it to null }
        val opts = p[7] as? Map<String, Any?>
        val rk = opts?.get("rk") == true
        val keys = newEcKey()
        val id = ByteArray(32).also { rnd.nextBytes(it) }
        credentials += Cred(rpId, id, user, keys, rk)
        val flags = 0x01 or (if (pin != null) 0x04 else 0) or 0x40
        val authData = ByteBuffer.allocate(32 + 1 + 4 + 16 + 2 + id.size).apply {
            put(sha256(rpId.toByteArray())); put(flags.toByte()); putInt(++counter)
            put(aaguid); putShort(id.size.toShort()); put(id)
        }.array() + Cbor.encode(cose(keys.public as ECPublicKey, -7))
        return 0 to mapOf(1 to "none", 2 to authData, 3 to emptyMap<String, Any>())
    }

    @Suppress("UNCHECKED_CAST")
    private fun getAssertion(p: Map<Int, Any?>): Pair<Int, Any?> {
        val rpId = p[1] as String
        val cdh = p[2] as ByteArray
        val allow = p[3] as? List<Map<String, Any?>>
        checkUv(cdh, p[6])?.let { return it to null }
        val matches = if (!allow.isNullOrEmpty()) {
            credentials.filter { c -> c.rpId == rpId && allow.any { (it["id"] as ByteArray).contentEquals(c.id) } }
        } else credentials.filter { it.rpId == rpId && it.resident }
        if (matches.isEmpty()) return 0x2E to null
        val flags = 0x01 or (if (pin != null) 0x04 else 0)
        val responses = matches.map { c ->
            val authData = ByteBuffer.allocate(37).apply { put(sha256(rpId.toByteArray())); put(flags.toByte()); putInt(++counter) }.array()
            val sig = Signature.getInstance("SHA256withECDSA").run { initSign(c.keys.private); update(authData + cdh); sign() }
            val m = linkedMapOf<Int, Any?>(1 to mapOf("type" to "public-key", "id" to c.id), 2 to authData, 3 to sig)
            if (allow.isNullOrEmpty()) m[4] = c.user
            m
        }
        pending.clear()
        val first = LinkedHashMap(responses.first())
        if (responses.size > 1) first[5] = responses.size
        pending.addAll(responses.drop(1))
        return 0 to first
    }

    // ------------------------------------------------------------------

    private fun newEcKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun cose(k: ECPublicKey, alg: Int): Map<Int, Any> = mapOf(
        1 to 2, 3 to alg, -1 to 1, -2 to coord(k.w.affineX), -3 to coord(k.w.affineY),
    )

    private fun coord(b: BigInteger): ByteArray {
        val raw = b.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32 -> raw.copyOfRange(raw.size - 32, raw.size)
            else -> ByteArray(32 - raw.size) + raw
        }
    }

    companion object {
        fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
        fun left16(b: ByteArray) = b.copyOf(16)
    }
}
