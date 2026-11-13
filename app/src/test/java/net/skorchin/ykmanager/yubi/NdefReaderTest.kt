package net.skorchin.ykmanager.yubi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NdefReaderTest {
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** Short NDEF URI record; [rest] follows the URI identifier code (0x04 = "https://"). */
    private fun uri(rest: ByteArray): ByteArray {
        val payload = byteArrayOf(0x04) + rest
        return byteArrayOf(0xD1.toByte(), 1, payload.size.toByte(), 'U'.code.toByte()) + payload
    }

    /** Short NDEF text record (UTF-8, "en"). */
    private fun text(rest: ByteArray): ByteArray {
        val payload = byteArrayOf(2, 'e'.code.toByte(), 'n'.code.toByte()) + rest
        return byteArrayOf(0xD1.toByte(), 1, payload.size.toByte(), 'T'.code.toByte()) + payload
    }

    private val yk = "my.yubico.com/yk/#".toByteArray()

    @Test fun passwordStartingWithSixKeepsTheSix() {
        // '6' is scan code 0x23, the same byte as '#': it used to be taken as part of the prefix.
        val c = NdefReader.parse(uri(yk + Encoding.passwordToScanCodes("6abc")))
        assertEquals("6abc", c.staticPassword)
        assertEquals("https://my.yubico.com/yk/#6abc", c.value)
    }

    @Test fun digitOnlyPasswordIsDecoded() {
        // 3..0 are scan codes 0x20..0x27, all printable: previously shown as " !\"#$%&'".
        val c = NdefReader.parse(uri(yk + Encoding.passwordToScanCodes("34567890")))
        assertEquals("34567890", c.staticPassword)
        assertEquals("20 21 22 23 24 25 26 27", c.scanCodesHex)
    }

    @Test fun unknownPrefixMixedPassword() {
        val c = NdefReader.parse(uri("example.com/otp=".toByteArray() + Encoding.passwordToScanCodes("Pass6!x/")))
        assertEquals("Pass6!x/", c.staticPassword)
        assertEquals("https://example.com/otp=Pass6!x/", c.value)
    }

    @Test fun knownPrefixFromApp() {
        val c = NdefReader.parse(text("Key/1:".toByteArray() + Encoding.passwordToScanCodes("7=9")), listOf("Key/1:"))
        assertEquals("7=9", c.staticPassword)
    }

    @Test fun scanCodeModeHelloWorld() {
        // ykpersonalize's documented scan-code example, no prefix.
        val c = NdefReader.parse(text(hex("8b080f0f122c9a12150f079e")))
        assertEquals("Hello World!", c.staticPassword)
    }

    @Test fun yubicoOtpAndHotpStayText() {
        val otp = "ccccccbcgujhingjrdejhgfnuetrgigvejhhgbkugded"
        val c = NdefReader.parse(uri(yk + otp.toByteArray()))
        assertNull(c.staticPassword)
        assertEquals(otp, c.otp)
        val h = NdefReader.parse(text("123456".toByteArray()))
        assertNull(h.staticPassword)
        assertEquals("123456", h.otp)
    }

    @Test fun backslashAndPipeRoundTrip() {
        val pw = "a\\b|c"
        assertEquals("31", "%02x".format(Encoding.passwordToScanCodes("\\")[0]))
        assertEquals(pw, NdefReader.parse(uri(yk + Encoding.passwordToScanCodes(pw))).staticPassword)
        // Older builds wrote backslash as 0x32.
        assertEquals("a\\|", NdefReader.parse(uri(yk + hex("0432b2"))).staticPassword)
    }

    @Test fun everyUsCharacterRoundTrips() {
        val all = ('a'..'z').joinToString("") + ('A'..'Z').joinToString("") + "0123456789" +
            "!@#\$%^&*()-_=+[]{}\\|;:'\",.<>/?`~ \t"
        assertEquals(all, NdefReader.parse(uri(yk + Encoding.passwordToScanCodes(all))).staticPassword)
    }
}
