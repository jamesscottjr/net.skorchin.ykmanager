package net.skorchin.ykmanager.yubi

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** Fields of a decrypted Yubico OTP (see developers.yubico.com/OTP/OTPs_Explained.html). */
data class DecodedOtp(
    /** ModHex public ID as typed (may be empty). */
    val publicId: String,
    /** Public ID as hex; for keys programmed with the serial number this decodes to it. */
    val publicIdHex: String,
    val privateIdHex: String,
    /** Non-volatile usage counter, incremented on each power-up (or when the session counter wraps). */
    val usageCounter: Int,
    /** Session counter, incremented on every OTP within one power-up. */
    val sessionCounter: Int,
    /** 24-bit timer at 8 Hz, started at a random value on power-up. */
    val timestamp: Int,
    val random: Int,
    val crc: Int,
    val crcValid: Boolean,
    /** The 16 decrypted bytes, hex. */
    val plaintextHex: String,
    /** Null when no expected private ID was given. */
    val privateIdMatches: Boolean?,
) {
    /** Serial number encoded in the public ID, when it follows Yubico's "serial as public ID" scheme. */
    val serialFromPublicId: Long?
        get() {
            // ykman / Yubico Authenticator: ModHex of 0xff 0x00 followed by the 4-byte serial (big-endian).
            if (publicIdHex.length != 12 || !publicIdHex.startsWith("ff00")) return null
            return publicIdHex.substring(4).toLongOrNull(16)?.takeIf { it > 0 }
        }

    val timestampSeconds: Double get() = timestamp / 8.0
}

/**
 * Decrypts a Yubico OTP with its slot's AES key, entirely on the phone.
 * The key never leaves the device and nothing is stored.
 */
object OtpDecoder {
    private const val MODHEX = "cbdefghijklnrtuv"
    private const val TOKEN_CHARS = 32

    /**
     * Pull the OTP out of whatever was pasted or typed: a bare OTP, a my.yubico.com link
     * (anything after the last '#', '/', '=' or '?'), surrounding whitespace, Enter or Tab.
     */
    fun extract(input: String): String {
        val t = input.trim().replace(Regex("\\s+"), "")
        val tail = t.substringAfterLast('#').substringAfterLast('/').substringAfterLast('=').substringAfterLast('?')
        return Regex("[cbdefghijklnrtuv]{32,64}$").find(tail.lowercase())?.value ?: tail.lowercase()
    }

    /** Throws [IllegalArgumentException] with a user-facing message for bad input. */
    fun decode(otpInput: String, aesKeyHex: String, expectedPrivateIdHex: String = ""): DecodedOtp {
        val otp = extract(otpInput)
        require(otp.isNotEmpty()) { "Enter or capture an OTP first." }
        val bad = otp.firstOrNull { it !in MODHEX }
        require(bad == null) {
            "'$bad' is not a ModHex character. A Yubico OTP only uses cbdefghijklnrtuv; if other letters appear, " +
                "the key typed it with a different keyboard layout, or the slot is not Yubico OTP."
        }
        require(otp.length >= TOKEN_CHARS && otp.length % 2 == 0 && otp.length <= TOKEN_CHARS + 32) {
            "A Yubico OTP has 32 encrypted characters after the public ID (44 characters in total by default); " +
                "this one has ${otp.length}."
        }
        val key = cleanHex(aesKeyHex)
        require(key.length == 32) { "The AES key must be 32 hex characters (16 bytes); got ${key.length}." }
        val expected = cleanHex(expectedPrivateIdHex)
        require(expected.isEmpty() || expected.length == 12) { "The private ID must be 12 hex characters (6 bytes)." }

        val publicId = otp.dropLast(TOKEN_CHARS)
        val cipherText = Encoding.fromModhex(otp.takeLast(TOKEN_CHARS))
        // The Yubico OTP format is a single 16-byte AES block (no chaining, nothing to replay): ECB is
        // the defined construction, and this only decrypts for display.
        val c = Cipher.getInstance("AES/ECB/NoPadding") // nosemgrep: kotlin.lang.security.ecb-cipher.ecb-cipher, mobsf.mobsfscan.kotlin.crypto.android_kotlin_aes_ecb
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(Encoding.fromHex(key), "AES"))
        val p = c.doFinal(cipherText)
        fun u(i: Int) = p[i].toInt() and 0xff
        val privateId = Encoding.toHex(p.copyOfRange(0, 6))
        return DecodedOtp(
            publicId = publicId,
            publicIdHex = Encoding.toHex(Encoding.fromModhex(publicId)),
            privateIdHex = privateId,
            usageCounter = u(6) or (u(7) shl 8),
            timestamp = u(8) or (u(9) shl 8) or (u(10) shl 16),
            sessionCounter = u(11),
            random = u(12) or (u(13) shl 8),
            crc = u(14) or (u(15) shl 8),
            crcValid = crc16(p) == 0xf0b8,
            plaintextHex = Encoding.toHex(p),
            privateIdMatches = if (expected.isEmpty()) null else expected.equals(privateId, ignoreCase = true),
        )
    }

    /** ISO 13239 CRC-16 as used by YubiKeys; over a valid block including its CRC it yields 0xf0b8. */
    fun crc16(data: ByteArray): Int {
        var crc = 0xffff
        for (b in data) {
            crc = crc xor (b.toInt() and 0xff)
            repeat(8) {
                val j = crc and 1
                crc = crc shr 1
                if (j != 0) crc = crc xor 0x8408
            }
        }
        return crc
    }

    private fun cleanHex(s: String) = s.trim().replace(Regex("[\\s:-]"), "").lowercase().also {
        require(it.all { ch -> ch in "0123456789abcdef" }) { "Only hex characters (0-9, a-f) are allowed in the key and private ID." }
    }
}
