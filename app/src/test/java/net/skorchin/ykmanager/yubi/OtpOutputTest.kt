package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.yubiotp.HmacSha1SlotConfiguration
import com.yubico.yubikit.yubiotp.HotpSlotConfiguration
import com.yubico.yubikit.yubiotp.UpdateConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OtpOutputTest {
    // Config layout: fixed(16) uid(6) key(16) acc(6) fixedSize(1) ext(1) tkt(1) cfg(1) rfu(2) crc(2)
    private fun flags(c: com.yubico.yubikit.yubiotp.SlotConfiguration): Triple<Int, Int, Int> {
        val b = c.getConfig(null)
        return Triple(b[45].toInt() and 0xff, b[46].toInt() and 0xff, b[47].toInt() and 0xff)
    }

    @Test fun defaultsMatchYubiKitKeyboardDefaults() {
        val plain = HotpSlotConfiguration(ByteArray(20))
        val ours = HotpSlotConfiguration(ByteArray(20)).also { OtpOutputSettings().applyTo(it, keyboard = true) }
        assertEquals(flags(plain), flags(ours))
        assertTrue(OtpOutputSettings().isDefault)
        assertTrue(OtpOutputSettings().changesFromDefault().isEmpty())
    }

    @Test fun keyboardFlagsAreWritten() {
        val s = OtpOutputSettings(tabFirst = true, tabAfterSecond = true, appendEnter = false, delayAfterFirst = true,
            pacing = OtpPacing.SLOW_30, numericKeypad = true, fastTrigger = false, invertLed = true,
            serialButton = true, serialUsb = true, serialApi = false, allowUpdate = false)
        val (ext, tkt, cfg) = flags(HotpSlotConfiguration(ByteArray(20)).also { s.applyTo(it, keyboard = true) })
        assertEquals(0x01 or 0x04 or 0x08 or 0x40, tkt)       // TAB_FIRST, TAB2, DELAY1, OATH_HOTP
        assertEquals(0x0c, cfg and 0x0c)                      // PACING_10MS + 20MS
        assertEquals(0x01 or 0x02 or 0x08 or 0x80, ext)       // SERIAL_BTN, SERIAL_USB, NUMERIC, LED_INV
    }

    @Test fun challengeResponseKeepsItsOwnFlags() {
        val s = OtpOutputSettings(pacing = OtpPacing.STANDARD, tabFirst = true, invertLed = true)
        val c = HmacSha1SlotConfiguration(ByteArray(20)).requireTouch(true).lt64(true)
        s.applyTo(c, keyboard = false)
        val (ext, tkt, cfg) = flags(c)
        assertEquals(0x40, tkt)                               // CHAL_RESP only, no tab
        assertEquals(0x22 or 0x04 or 0x08, cfg)               // CHAL_HMAC, HMAC_LT64, BTN_TRIG intact
        assertEquals(0x80, ext and 0x80)
    }

    @Test fun updateConfigurationAcceptsAllSettings() {
        val s = OtpOutputSettings(tabAfterFirst = true, delayAfterSecond = true, pacing = OtpPacing.SLOW_10,
            sendReference = true, numericKeypad = true, invertLed = true, serialButton = true)
        s.applyTo(UpdateConfiguration(), keyboard = true)    // must not throw (send-ref is skipped)
    }

    @Test fun patternAndJsonRoundTrip() {
        val s = OtpOutputSettings(tabFirst = true, tabAfterFirst = true, delayAfterSecond = true, pacing = OtpPacing.SLOW_20)
        assertEquals("Tab · public ID · Tab · OTP · 0.5 s pause · Enter", s.outputPattern())
        assertEquals("code · Enter", OtpOutputSettings().outputPattern(firstPart = null, secondPart = "code"))
        assertEquals(s, OtpOutputSettings.fromJson(org.json.JSONObject(s.toJson().toString())))
        assertEquals(OtpOutputSettings(), OtpOutputSettings.fromJson(null))
    }
}
