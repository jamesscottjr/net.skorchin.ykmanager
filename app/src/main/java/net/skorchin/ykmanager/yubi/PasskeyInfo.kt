package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.fido.Cbor
import java.security.MessageDigest

/** One labelled value on the passkey details screen. */
data class InfoItem(
    val label: String,
    val value: String,
    /** Value worth copying (IDs, hashes, key material); shown in monospace with a copy action. */
    val copyable: Boolean = false,
    /** Extra explanation under the value. */
    val note: String? = null,
)

data class InfoSection(val title: String, val items: List<InfoItem>)

/**
 * Turns everything the authenticator reports about a discoverable credential into
 * human-readable sections. Pure Kotlin so it is unit-testable.
 */
object PasskeyInfo {

    private const val B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    fun hex(b: ByteArray): String = Encoding.toHex(b)

    /** RFC 4648 base64url without padding, as used by WebAuthn JSON. */
    fun base64Url(b: ByteArray): String = buildString {
        var i = 0
        while (i < b.size) {
            val b0 = b[i].toInt() and 0xff
            val b1 = if (i + 1 < b.size) b[i + 1].toInt() and 0xff else -1
            val b2 = if (i + 2 < b.size) b[i + 2].toInt() and 0xff else -1
            append(B64URL[b0 shr 2])
            append(B64URL[((b0 and 0x03) shl 4) or (if (b1 >= 0) b1 shr 4 else 0)])
            if (b1 >= 0) append(B64URL[((b1 and 0x0f) shl 2) or (if (b2 >= 0) b2 shr 6 else 0)])
            if (b2 >= 0) append(B64URL[b2 and 0x3f])
            i += 3
        }
    }

    /** Printable text if the bytes are valid UTF-8 without control characters, else null. */
    fun printable(b: ByteArray): String? {
        if (b.isEmpty()) return null
        val s = try {
            val dec = Charsets.UTF_8.newDecoder()
            dec.decode(java.nio.ByteBuffer.wrap(b)).toString()
        } catch (_: Exception) { return null }
        return s.takeIf { str -> str.all { !it.isISOControl() } && str.any { it.isLetterOrDigit() } }
    }

    fun algorithmName(alg: Int?): String = when (alg) {
        null -> "unknown"
        -7 -> "ES256 (ECDSA P-256 / SHA-256)"
        -8 -> "EdDSA"
        -35 -> "ES384 (ECDSA P-384 / SHA-384)"
        -36 -> "ES512 (ECDSA P-521 / SHA-512)"
        -37 -> "PS256 (RSASSA-PSS / SHA-256)"
        -38 -> "PS384 (RSASSA-PSS / SHA-384)"
        -39 -> "PS512 (RSASSA-PSS / SHA-512)"
        -47 -> "ES256K (ECDSA secp256k1 / SHA-256)"
        -257 -> "RS256 (RSASSA-PKCS1-v1_5 / SHA-256)"
        -258 -> "RS384 (RSASSA-PKCS1-v1_5 / SHA-384)"
        -259 -> "RS512 (RSASSA-PKCS1-v1_5 / SHA-512)"
        -65535 -> "RS1 (RSASSA-PKCS1-v1_5 / SHA-1)"
        else -> "COSE algorithm $alg"
    }

    fun keyTypeName(kty: Int?): String = when (kty) {
        1 -> "OKP (Octet key pair)"
        2 -> "EC2 (Elliptic curve)"
        3 -> "RSA"
        4 -> "Symmetric"
        null -> "unknown"
        else -> "COSE key type $kty"
    }

    fun curveName(crv: Int?): String? = when (crv) {
        null -> null
        1 -> "P-256 (secp256r1)"
        2 -> "P-384 (secp384r1)"
        3 -> "P-521 (secp521r1)"
        4 -> "X25519"
        5 -> "X448"
        6 -> "Ed25519"
        7 -> "Ed448"
        8 -> "secp256k1"
        else -> "COSE curve $crv"
    }

    fun credProtectName(level: Int?): Pair<String, String> = when (level) {
        null -> "Not reported" to "The key did not return a credProtect policy for this credential (older firmware or default policy)."
        1 -> "Level 1 – user verification optional" to "Usable without PIN/biometric when the site allows it; discoverable without user verification."
        2 -> "Level 2 – user verification optional with credential ID list" to "Discoverable only after user verification; still usable without it when the site supplies the credential ID."
        3 -> "Level 3 – user verification required" to "Every use of this credential requires PIN or fingerprint."
        else -> "Level $level" to "Unknown credProtect policy value."
    }

    fun transportName(t: String): String = when (t) {
        "usb" -> "USB"
        "nfc" -> "NFC"
        "ble" -> "Bluetooth LE"
        "hybrid" -> "Hybrid (phone/QR)"
        "internal" -> "Internal"
        "smart-card" -> "Smart card"
        else -> t
    }

    private fun Map<Any?, *>.int(k: Int): Int? = (this[k] as? Number)?.toInt()
    private fun Map<Any?, *>.bytes(k: Int): ByteArray? = this[k] as? ByteArray

    /** SHA-256 over the CBOR-encoded COSE key, a stable identifier for the public key. */
    fun keyFingerprint(coseKey: Map<Any?, *>): String? = runCatching {
        hex(MessageDigest.getInstance("SHA-256").digest(Cbor.encode(coseKey)))
    }.getOrNull()

    fun describe(p: Passkey): List<InfoSection> {
        val d = p.details
        val sections = mutableListOf<InfoSection>()

        sections += InfoSection("Relying party", buildList {
            add(InfoItem("RP ID", p.rpId, copyable = true, note = "The website or app domain this passkey is bound to."))
            d.rpName?.takeIf { it.isNotBlank() && it != p.rpId }?.let { add(InfoItem("RP name", it)) }
            add(InfoItem("RP ID hash", hex(d.rpIdHash), copyable = true, note = "SHA-256 of the RP ID, as stored on the key."))
        })

        sections += InfoSection("User account", buildList {
            add(InfoItem("User name", p.userName, copyable = true))
            p.displayName?.takeIf { it.isNotBlank() }?.let { add(InfoItem("Display name", it, copyable = true)) }
            if (d.userId.isNotEmpty()) {
                add(InfoItem("User handle (hex)", hex(d.userId), copyable = true,
                    note = "${d.userId.size} bytes. Opaque account identifier chosen by the site; it is not shown during sign-in."))
                add(InfoItem("User handle (base64url)", base64Url(d.userId), copyable = true))
                printable(d.userId)?.let { add(InfoItem("User handle (text)", it, copyable = true)) }
            } else {
                add(InfoItem("User handle", "(empty)"))
            }
        })

        sections += InfoSection("Credential", buildList {
            add(InfoItem("Kind", "Discoverable credential (resident key)",
                note = "Stored on the YubiKey, so it can be used without the site first naming it."))
            d.credentialType?.let { add(InfoItem("Type", it)) }
            if (d.credentialIdBytes.isNotEmpty()) {
                add(InfoItem("Credential ID (hex)", hex(d.credentialIdBytes), copyable = true,
                    note = "${d.credentialIdBytes.size} bytes."))
                add(InfoItem("Credential ID (base64url)", base64Url(d.credentialIdBytes), copyable = true,
                    note = "Same value as the \"id\" field in the WebAuthn JSON the site stores."))
            }
            if (d.transports.isNotEmpty()) add(InfoItem("Transports", d.transports.joinToString(", ") { transportName(it) }))
            val (cp, cpNote) = credProtectName(d.credProtect)
            add(InfoItem("Protection policy", cp, note = cpNote))
            add(InfoItem("Large blob key", if (d.hasLargeBlobKey) "Present" else "None",
                note = if (d.hasLargeBlobKey) "The site can store extra encrypted data (largeBlob extension) tied to this passkey."
                       else "No largeBlob extension data is associated with this passkey."))
        })

        val k = d.publicKey
        val kty = k.int(1)
        val alg = k.int(3)
        sections += InfoSection("Public key", buildList {
            add(InfoItem("Algorithm", algorithmName(alg)))
            add(InfoItem("Key type", keyTypeName(kty)))
            when (kty) {
                2 -> { // EC2
                    curveName(k.int(-1))?.let { add(InfoItem("Curve", it)) }
                    val x = k.bytes(-2); val y = k.bytes(-3)
                    if (x != null && y != null) {
                        add(InfoItem("Public point", "04" + hex(x) + hex(y), copyable = true,
                            note = "Uncompressed SEC1 encoding (${(x.size * 8)}-bit coordinates)."))
                    }
                }
                1 -> { // OKP
                    curveName(k.int(-1))?.let { add(InfoItem("Curve", it)) }
                    k.bytes(-2)?.let { add(InfoItem("Public key", hex(it), copyable = true, note = "${it.size * 8}-bit.")) }
                }
                3 -> { // RSA
                    k.bytes(-1)?.let { n ->
                        val bits = (n.size - n.indexOfFirst { it.toInt() != 0 }.coerceAtLeast(0)) * 8
                        add(InfoItem("Modulus", hex(n), copyable = true, note = "$bits-bit."))
                    }
                    k.bytes(-2)?.let { add(InfoItem("Exponent", hex(it), copyable = true)) }
                }
            }
            keyFingerprint(k)?.let { add(InfoItem("Key fingerprint", it, copyable = true, note = "SHA-256 of the COSE-encoded public key.")) }
            if (k.isEmpty()) add(InfoItem("COSE key", "(not returned by the key)"))
        })

        return sections
    }
}
