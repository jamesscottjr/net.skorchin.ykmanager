package net.skorchin.ykmanager.passkey

import com.yubico.yubikit.fido.Cbor
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.webauthn.SerializationType
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * The registration response must pass Chrome's checks for provider responses
 * (components/webauthn/json/value_conversions.cc, MakeCredentialResponseFromValue):
 * authenticatorData, publicKeyAlgorithm and publicKey must equal what Chrome
 * derives from attestationObject. And attestation "none" must come back as
 * fmt "none", like Chrome does for security keys.
 */
class RegistrationResponseTest {
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private fun unb64(s: String) = Base64.getUrlDecoder().decode(s)

    private fun createReq(attestation: String?) = JSONObject().apply {
        put("challenge", b64.encodeToString(ByteArray(32) { 7 }))
        put("rp", JSONObject().put("id", "example.com").put("name", "Example"))
        put("user", JSONObject().put("id", b64.encodeToString("u1".toByteArray())).put("name", "alice").put("displayName", "Alice"))
        put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
        put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", "preferred"))
        attestation?.let { put("attestation", it) }
    }

    /** Register on the soft key, then dress the attestation up as a YubiKey's "packed" one. */
    private fun registerPacked(req: JSONObject): Pair<JSONObject, SoftAuthenticator> {
        val key = SoftAuthenticator(pin = "123456")
        val out = PasskeyCeremony.run(key, true, PasskeyJson.normalizeCreate(req), ClientDataProvider.fromHash(ByteArray(32) { 3 }),
            "example.com", PinMode.ENTER, "123456", "", null) as PasskeyCeremony.Outcome.Done
        val json = PasskeyJson.fromMap(out.credential.toMap(SerializationType.JSON))
        val r = json.getJSONObject("response")
        @Suppress("UNCHECKED_CAST")
        val att = Cbor.decode(unb64(r.getString("attestationObject"))) as Map<String, Any?>
        val authData = (att["authData"] as ByteArray).copyOf()
        for (i in 37 until 53) authData[i] = 0x2f // a non-zero AAGUID, like a real YubiKey's
        val packed = linkedMapOf<String, Any>("fmt" to "packed", "attStmt" to mapOf("alg" to -7, "sig" to byteArrayOf(1, 2, 3)), "authData" to authData)
        r.put("attestationObject", b64.encodeToString(Cbor.encode(packed)))
        r.put("authenticatorData", b64.encodeToString(authData))
        r.remove("publicKey")
        return json to key
    }

    private fun attOf(json: JSONObject): Map<*, *> = Cbor.decode(unb64(json.getJSONObject("response").getString("attestationObject"))) as Map<*, *>

    private fun assertChromeConsistent(json: JSONObject, key: SoftAuthenticator) {
        val r = json.getJSONObject("response")
        val authData = attOf(json)["authData"] as ByteArray
        assertArrayEquals(authData, unb64(r.getString("authenticatorData")))
        assertEquals(-7, r.getInt("publicKeyAlgorithm"))
        // Named-curve SubjectPublicKeyInfo, as Chrome (BoringSSL) and the JDK encode it.
        assertArrayEquals(key.credentials.single().keys.public.encoded, unb64(r.getString("publicKey")))
        assertTrue(r.has("transports"))
    }

    @Test fun noneRequestedReturnsNoneAttestationWithZeroAaguid() {
        for (att in listOf(null, "none")) {
            val (json, key) = registerPacked(createReq(att))
            val info = PasskeyJson.prepareRegistration(json, createReq(att))
            assertEquals("packed", info.formatFromKey)
            assertEquals("none", info.formatReturned)
            val o = attOf(json)
            assertEquals("none", o["fmt"])
            assertTrue((o["attStmt"] as Map<*, *>).isEmpty())
            assertTrue((o["authData"] as ByteArray).copyOfRange(37, 53).all { it == 0.toByte() })
            assertChromeConsistent(json, key)
        }
    }

    @Test fun directKeepsTheKeysAttestation() {
        val (json, key) = registerPacked(createReq("direct"))
        val info = PasskeyJson.prepareRegistration(json, createReq("direct"))
        assertEquals("packed", info.formatReturned)
        assertEquals("packed", attOf(json)["fmt"])
        assertTrue((attOf(json)["authData"] as ByteArray).copyOfRange(37, 53).all { it == 0x2f.toByte() })
        assertChromeConsistent(json, key)
    }

    @Test fun spkiMatchesJdkEncodingForManyKeys() {
        // Leading 0x00 / 0xFF coordinate bytes are where BigInteger-based encoders slip.
        repeat(200) {
            val kp = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.genKeyPair()
            val pub = kp.public as java.security.interfaces.ECPublicKey
            fun c(b: java.math.BigInteger) = b.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
            val cose = mapOf(1 to 2, 3 to -7, -1 to 1, -2 to c(pub.w.affineX), -3 to c(pub.w.affineY))
            assertArrayEquals(pub.encoded, PasskeyJson.spkiFromCose(cose))
        }
    }
}
