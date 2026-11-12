package net.skorchin.ykmanager.yubi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PasskeyInfoTest {

    private fun sample(credProtect: Int? = 2, largeBlob: Boolean = true): Passkey {
        val x = ByteArray(32) { (it + 1).toByte() }
        val y = ByteArray(32) { (0xA0 + it).toByte() }
        val cose: Map<Any?, Any> = mapOf(1 to 2, 3 to -7, -1 to 1, -2 to x, -3 to y)
        val credId = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        return Passkey(
            rpId = "example.com",
            userName = "alice@example.com",
            displayName = "Alice",
            credentialId = mapOf("type" to "public-key", "id" to credId),
            details = PasskeyDetails(
                rpName = "Example Inc.",
                rpIdHash = ByteArray(32) { 0x11 },
                userId = "user-42".toByteArray(),
                credentialIdBytes = credId,
                credentialType = "public-key",
                transports = listOf("usb", "nfc"),
                publicKey = cose,
                credProtect = credProtect,
                hasLargeBlobKey = largeBlob,
            ),
        )
    }

    private fun List<InfoSection>.value(label: String): String? =
        flatMap { it.items }.firstOrNull { it.label == label }?.value

    @Test
    fun base64UrlMatchesWebAuthnEncoding() {
        assertEquals("3q2-7w", PasskeyInfo.base64Url(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())))
        assertEquals("", PasskeyInfo.base64Url(ByteArray(0)))
        assertEquals("YQ", PasskeyInfo.base64Url("a".toByteArray()))
        assertEquals("YWI", PasskeyInfo.base64Url("ab".toByteArray()))
        assertEquals("YWJj", PasskeyInfo.base64Url("abc".toByteArray()))
    }

    @Test
    fun printableDetectsTextHandles() {
        assertEquals("user-42", PasskeyInfo.printable("user-42".toByteArray()))
        assertNull(PasskeyInfo.printable(byteArrayOf(0, 1, 2, 3)))
        assertNull(PasskeyInfo.printable(byteArrayOf(0xFF.toByte(), 0xFE.toByte())))
    }

    @Test
    fun describeCoversEverySection() {
        val s = PasskeyInfo.describe(sample())
        assertEquals(listOf("Relying party", "User account", "Credential", "Public key"), s.map { it.title })
        assertEquals("example.com", s.value("RP ID"))
        assertEquals("Example Inc.", s.value("RP name"))
        assertEquals("11".repeat(32), s.value("RP ID hash"))
        assertEquals("user-42", s.value("User handle (text)"))
        assertEquals("deadbeef", s.value("Credential ID (hex)"))
        assertEquals("3q2-7w", s.value("Credential ID (base64url)"))
        assertEquals("USB, NFC", s.value("Transports"))
        assertTrue(s.value("Protection policy")!!.startsWith("Level 2"))
        assertEquals("Present", s.value("Large blob key"))
        assertEquals("ES256 (ECDSA P-256 / SHA-256)", s.value("Algorithm"))
        assertEquals("P-256 (secp256r1)", s.value("Curve"))
        val point = s.value("Public point")!!
        assertEquals(2 + 128, point.length)
        assertTrue(point.startsWith("04010203"))
        assertEquals(64, s.value("Key fingerprint")!!.length)
    }

    @Test
    fun describeHandlesMissingOptionalFields() {
        val s = PasskeyInfo.describe(sample(credProtect = null, largeBlob = false))
        assertEquals("Not reported", s.value("Protection policy"))
        assertEquals("None", s.value("Large blob key"))
    }

    @Test
    fun algorithmAndCurveNames() {
        assertEquals("EdDSA", PasskeyInfo.algorithmName(-8))
        assertEquals("RS256 (RSASSA-PKCS1-v1_5 / SHA-256)", PasskeyInfo.algorithmName(-257))
        assertEquals("COSE algorithm -999", PasskeyInfo.algorithmName(-999))
        assertEquals("Ed25519", PasskeyInfo.curveName(6))
        assertNull(PasskeyInfo.curveName(null))
    }
}
