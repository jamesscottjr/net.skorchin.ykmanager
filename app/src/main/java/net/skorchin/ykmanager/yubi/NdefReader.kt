package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import java.io.IOException

/** The decoded content of the YubiKey's NDEF record. */
data class NdefContent(
    /** Full URI or text carried by the record. */
    val value: String,
    /** True for a URI record, false for a text record. */
    val isUri: Boolean,
    /**
     * Set when the slot held a static password: the key then emits raw USB
     * keyboard scan codes instead of characters, and this is their
     * translation using the US keyboard layout.
     */
    val staticPassword: String? = null,
) {
    /**
     * The one-time password part of the record: whatever follows the last
     * '#', '/' or '=' when it looks like an OTP, otherwise the trailing run
     * of ModHex / digits, otherwise the whole value.
     */
    val otp: String
        get() {
            staticPassword?.let { return it }
            val tail = value.substringAfterLast('#').substringAfterLast('/').substringAfterLast('=')
            if (looksLikeOtp(tail)) return tail
            val run = Regex("([cbdefghijklnrtuv]{32,48}|[0-9]{6,8})$").find(value)?.value
            return run ?: tail
        }

    private fun looksLikeOtp(s: String) =
        (s.length in 32..48 && s.all { it in "cbdefghijklnrtuv" }) || (s.length in 6..8 && s.all { it.isDigit() })
}

/**
 * Reads the YubiKey's NDEF record over the smart card connection (NFC Forum
 * Type 4 Tag), so it works regardless of whether Android performed its own
 * NDEF check, and parses it.
 */
object NdefReader {
    /** NFC Forum well-known URI prefixes, indexed by identifier code minus one. */
    val URL_PREFIXES = arrayOf(
        "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:", "ftp://anonymous:anonymous@",
        "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:",
        "rtsp://", "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://",
        "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
    )

    private val NDEF_AID = byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x00, 0x85.toByte(), 0x01, 0x01)

    /** Read the raw NDEF message bytes from the key. Each read makes the key produce a fresh OTP. */
    fun readMessage(conn: SmartCardConnection): ByteArray {
        fun apdu(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }
        fun send(cmd: ByteArray, what: String): ByteArray {
            val r = conn.sendAndReceive(cmd)
            if (r.size < 2 || r[r.size - 2] != 0x90.toByte() || r[r.size - 1] != 0x00.toByte())
                throw IOException("NDEF $what failed (SW ${r.takeLast(2).joinToString("") { "%02X".format(it) }})")
            return r.copyOfRange(0, r.size - 2)
        }
        send(apdu(0x00, 0xA4, 0x04, 0x00, NDEF_AID.size) + NDEF_AID + apdu(0x00), "application select")
        send(apdu(0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03), "capability container select")
        val cc = send(apdu(0x00, 0xB0, 0x00, 0x00, 0x0F), "capability container read")
        if (cc.size < 15) throw IOException("NDEF capability container too short")
        val maxRead = (((cc[3].toInt() and 0xff) shl 8) or (cc[4].toInt() and 0xff)).coerceIn(16, 0xFF)
        val fileId = cc.copyOfRange(9, 11)
        send(apdu(0x00, 0xA4, 0x00, 0x0C, 0x02) + fileId, "file select")
        val lenBytes = send(apdu(0x00, 0xB0, 0x00, 0x00, 0x02), "length read")
        val len = ((lenBytes[0].toInt() and 0xff) shl 8) or (lenBytes[1].toInt() and 0xff)
        val out = ByteArray(len)
        var off = 0
        while (off < len) {
            val n = minOf(maxRead, len - off)
            val pos = off + 2
            val chunk = send(apdu(0x00, 0xB0, pos shr 8, pos and 0xff, n), "read")
            if (chunk.isEmpty()) throw IOException("NDEF read returned no data")
            chunk.copyInto(out, off)
            off += chunk.size
        }
        return out
    }

    fun read(conn: SmartCardConnection): NdefContent = parse(readMessage(conn))

    /** Parse the first record of an NDEF message (as produced by [readMessage] or NdefMessage.toByteArray()). */
    fun parse(msg: ByteArray): NdefContent {
        if (msg.size < 3) throw IOException("NDEF record is empty")
        var i = 0
        val header = msg[i++].toInt() and 0xff
        val shortRecord = header and 0x10 != 0
        val hasId = header and 0x08 != 0
        val tnf = header and 0x07
        val typeLen = msg[i++].toInt() and 0xff
        val payloadLen = if (shortRecord) msg[i++].toInt() and 0xff else {
            val v = ((msg[i].toInt() and 0xff) shl 24) or ((msg[i + 1].toInt() and 0xff) shl 16) or
                ((msg[i + 2].toInt() and 0xff) shl 8) or (msg[i + 3].toInt() and 0xff)
            i += 4; v
        }
        val idLen = if (hasId) msg[i++].toInt() and 0xff else 0
        val type = String(msg, i, typeLen, Charsets.US_ASCII); i += typeLen
        i += idLen
        if (i + payloadLen > msg.size) throw IOException("NDEF record is truncated")
        val payload = msg.copyOfRange(i, i + payloadLen)
        return when {
            tnf == 1 && type == "U" && payload.isNotEmpty() -> {
                val code = payload[0].toInt() and 0xff
                val prefix = if (code in 1..URL_PREFIXES.size) URL_PREFIXES[code - 1] else ""
                content(prefix, payload.copyOfRange(1, payload.size), isUri = true)
            }
            tnf == 1 && type == "T" && payload.isNotEmpty() -> {
                val status = payload[0].toInt() and 0xff
                val langLen = status and 0x3F
                if (status and 0x80 != 0)
                    NdefContent(String(payload, 1 + langLen, payload.size - 1 - langLen, Charsets.UTF_16), isUri = false)
                else content("", payload.copyOfRange(minOf(1 + langLen, payload.size), payload.size), isUri = false)
            }
            tnf == 3 -> content(type, payload, isUri = true) // absolute URI
            else -> content("", payload, isUri = false)
        }
    }

    /**
     * Build the content, translating a static password's keyboard scan codes
     * (which the key emits as-is over NFC) into readable characters.
     */
    private fun content(prefix: String, body: ByteArray, isUri: Boolean): NdefContent {
        val split = splitScanCodes(body)
        if (split == null) return NdefContent(prefix + String(body, Charsets.UTF_8), isUri)
        val (textPart, codes) = split
        val password = ScanCodes.decode(codes)
        val text = prefix + String(textPart, Charsets.UTF_8)
        return NdefContent(text + password, isUri, staticPassword = password)
    }

    /**
     * If [body] contains bytes that cannot be text, treat everything after the
     * last delimiter that precedes the first such byte as scan codes.
     */
    private fun splitScanCodes(body: ByteArray): Pair<ByteArray, ByteArray>? {
        val firstBad = body.indexOfFirst { val v = it.toInt() and 0xff; v < 0x20 || v > 0x7E }
        if (firstBad < 0) return null
        var start = 0
        for (k in firstBad - 1 downTo 0) {
            if (body[k].toInt().toChar() in "#/=: ") { start = k + 1; break }
        }
        return body.copyOfRange(0, start) to body.copyOfRange(start, body.size)
    }
}

/** USB HID keyboard usage IDs → characters, US layout; bit 7 is the Shift modifier. */
object ScanCodes {
    // Usage IDs 0x04..0x38 (0x29 Esc and 0x2A Backspace produce nothing).
    private const val PLAIN = "abcdefghijklmnopqrstuvwxyz1234567890\n\u0000\u0000\t -=[]\\#;'`,./"
    private const val SHIFT = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#\$%^&*()\n\u0000\u0000\t _+{}|~:\"~<>?"
    // Usage IDs 0x54..0x63 (numeric keypad).
    private const val KEYPAD = "/*-+\n1234567890."

    fun decode(codes: ByteArray): String {
        val sb = StringBuilder()
        for (b in codes) {
            val v = b.toInt() and 0xff
            if (v == 0) continue
            val shift = v and 0x80 != 0
            val c = when (val u = v and 0x7F) {
                in 0x04..0x38 -> (if (shift) SHIFT else PLAIN)[u - 0x04]
                in 0x54..0x63 -> KEYPAD[u - 0x54]
                0x64 -> if (shift) '|' else '\\'
                else -> '\uFFFD'
            }
            if (c != '\u0000') sb.append(c)
        }
        return sb.toString()
    }
}
