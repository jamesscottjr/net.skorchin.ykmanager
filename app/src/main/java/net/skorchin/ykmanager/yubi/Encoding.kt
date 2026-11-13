package net.skorchin.ykmanager.yubi

import java.security.SecureRandom

/** Encoding helpers for YubiKey OTP slot data. */
object Encoding {

    private val MODHEX_ALPHABET = "cbdefghijklnrtuv"
    private val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private val random = SecureRandom()

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    /** Random password using only modhex characters (layout independent). */
    fun randomModhex(length: Int): String {
        val n = length.coerceIn(1, 38)
        return toModhex(randomBytes((n + 1) / 2)).take(n)
    }

    fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    fun fromHex(hex: String): ByteArray {
        val cleaned = hex.replace(" ", "").replace(":", "")
        require(cleaned.length % 2 == 0) { "Hex string must have an even number of digits" }
        val chars = cleaned.lowercase()
        return ByteArray(cleaned.length / 2) { i ->
            val hi = Character.digit(chars[i * 2], 16)
            val lo = Character.digit(chars[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex string" }
            ((hi shl 4) or lo).toByte()
        }
    }

    fun toModhex(bytes: ByteArray): String = buildString {
        for (b in bytes) {
            append(MODHEX_ALPHABET[(b.toInt() shr 4) and 0xF])
            append(MODHEX_ALPHABET[b.toInt() and 0xF])
        }
    }

    fun fromModhex(s: String): ByteArray {
        val cleaned = s.lowercase().filter { !it.isWhitespace() }
        require(cleaned.length % 2 == 0) { "Modhex string must have an even number of characters" }
        return ByteArray(cleaned.length / 2) { i ->
            val hi = MODHEX_ALPHABET.indexOf(cleaned[i * 2])
            val lo = MODHEX_ALPHABET.indexOf(cleaned[i * 2 + 1])
            require(hi >= 0 && lo >= 0) { "Invalid modhex characters" }
            ((hi shl 4) or lo).toByte()
        }
    }

    /** RFC 4648 base32 decode, padding optional, case-insensitive. */
    fun fromBase32(s: String): ByteArray {
        val cleaned = s.uppercase().filter { it in BASE32_ALPHABET }
        require(cleaned.length >= 8) { "Secret too short" }
        var bits = 0L
        var bitCount = 0
        val out = mutableListOf<Byte>()
        for (c in cleaned) {
            bits = (bits shl 5) or BASE32_ALPHABET.indexOf(c).toLong()
            bitCount += 5
            if (bitCount >= 8) {
                bitCount -= 8
                out.add(((bits shr bitCount) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    /**
     * Convert a password typed on a US-English layout into USB HID keyboard
     * scan codes, one byte per character: the low 7 bits are the key usage and
     * the high bit (0x80) means SHIFT is held (uppercase and shifted symbols).
     */
    fun passwordToScanCodes(password: String): ByteArray = ByteArray(password.length) { i ->
        val c = password[i]
        val code = KEYMAP[c] ?: throw IllegalArgumentException(
            "Character '$c' is not available on the US keyboard layout"
        )
        code.toByte()
    }

    private const val SHIFT = 0x80

    /** US-English keyboard: character to HID usage code, | SHIFT when shifted. */
    private val KEYMAP: Map<Char, Int> = buildMap {
        for (c in 'a'..'z') put(c, 0x04 + (c - 'a'))
        for (c in 'A'..'Z') put(c, 0x04 + (c - 'A') or SHIFT)
        for (c in '1'..'9') put(c, 0x1E + (c - '1'))
        put('0', 0x27)
        put('!', 0x1E or SHIFT); put('@', 0x1F or SHIFT); put('#', 0x20 or SHIFT)
        put('$', 0x21 or SHIFT); put('%', 0x22 or SHIFT); put('^', 0x23 or SHIFT)
        put('&', 0x24 or SHIFT); put('*', 0x25 or SHIFT); put('(', 0x26 or SHIFT)
        put(')', 0x27 or SHIFT)
        put('-', 0x2D); put('_', 0x2D or SHIFT)
        put('=', 0x2E); put('+', 0x2E or SHIFT)
        put('[', 0x2F); put('{', 0x2F or SHIFT)
        put(']', 0x30); put('}', 0x30 or SHIFT)
        put('\\', 0x31); put('|', 0x31 or SHIFT)
        put(';', 0x33); put(':', 0x33 or SHIFT)
        put('\'', 0x34); put('"', 0x34 or SHIFT)
        put('`', 0x35); put('~', 0x35 or SHIFT)
        put(',', 0x36); put('<', 0x36 or SHIFT)
        put('.', 0x37); put('>', 0x37 or SHIFT)
        put('/', 0x38); put('?', 0x38 or SHIFT)
        put(' ', 0x2C); put('\t', 0x2B); put('\n', 0x28)
    }

    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SPECIALS = "!@#$%^&*()-_=+[]{};:'\",.<>/?`~|\\"

    /**
     * Random password using the full US keyboard character set. Guarantees at
     * least one lowercase letter, uppercase letter, digit and special character
     * (when at least 4 characters long).
     */
    fun randomPassword(length: Int): String {
        val n = length.coerceIn(1, 38)
        val classes = listOf(LOWER, UPPER, DIGITS, SPECIALS)
        val chars = if (n >= 4) classes.map { it[random.nextInt(it.length)] }.toMutableList()
        else mutableListOf()
        val alphabet = LOWER + UPPER + DIGITS + SPECIALS
        repeat(n - chars.size) { chars.add(alphabet[random.nextInt(alphabet.length)]) }
        // Fisher-Yates shuffle so the guaranteed classes are not always first.
        for (i in chars.size - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val t = chars[i]; chars[i] = chars[j]; chars[j] = t
        }
        return String(chars.toCharArray())
    }
}
