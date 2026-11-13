package net.skorchin.ykmanager.yubi

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class OtpDecoderTest {
    @Test fun libyubikeyVector() {
        // ykparse example from Yubico's yubico-c (libyubikey) README.
        val r = OtpDecoder.decode("dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", "ecde18dbe76fbd0c33330f1c354871db")
        assertTrue(r.crcValid)
        assertEquals("87 92 eb fe 26 cc".replace(" ", ""), r.privateIdHex)
        assertEquals(19, r.usageCounter)
        assertEquals(17, r.sessionCounter)
        assertEquals("dteffuje", r.publicId)  // 4-byte public ID in this vector
    }

    @Test fun roundTripWithSerialPublicId() {
        val key = Encoding.fromHex("00112233445566778899aabbccddeeff")
        val block = Encoding.fromHex("a1b2c3d4e5f6" + "0500" + "102030" + "07" + "beef")
        val crc = OtpDecoder.crc16(block).inv() and 0xffff
        val plain = block + byteArrayOf((crc and 0xff).toByte(), (crc shr 8).toByte())
        val c = Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES")) }
        val pub = Encoding.toModhex(Encoding.fromHex("ff0000bc614e"))  // serial 12345678
        val otp = pub + Encoding.toModhex(c.doFinal(plain))
        val r = OtpDecoder.decode("https://my.yubico.com/yk/#$otp\n", "0011 2233 4455 6677 8899 AABB CCDD EEFF", "A1B2C3D4E5F6")
        assertTrue(r.crcValid)
        assertEquals("a1b2c3d4e5f6", r.privateIdHex)
        assertEquals(5, r.usageCounter)
        assertEquals(0x302010, r.timestamp)
        assertEquals(7, r.sessionCounter)
        assertEquals(0xefbe, r.random)
        assertEquals(12345678L, r.serialFromPublicId)
        assertEquals(true, r.privateIdMatches)
    }

    @Test fun wrongKeyFailsChecksum() {
        val r = OtpDecoder.decode("dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", "00000000000000000000000000000000", "8792ebfe26cc")
        assertFalse(r.crcValid)
        assertEquals(false, r.privateIdMatches)
        assertNull(r.serialFromPublicId)
    }

    @Test fun badInputGivesMessages() {
        fun msg(otp: String, key: String) = try { OtpDecoder.decode(otp, key); fail(); "" } catch (e: IllegalArgumentException) { e.message!! }
        assertTrue(msg("dteffujehknhfjbrjnlnldnhcujvddbikngjrtga", "ecde18dbe76fbd0c33330f1c354871db").contains("ModHex"))
        assertTrue(msg("cccccccc", "ecde18dbe76fbd0c33330f1c354871db").contains("32 encrypted"))
        assertTrue(msg("dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh", "abc").contains("32 hex"))
    }
}
