package net.skorchin.ykmanager.passkey

import com.yubico.yubikit.fido.client.AuthInvalidClientError
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.webauthn.SerializationType
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.Signature
import java.util.Base64

class PasskeyCeremonyTest {

    private val rp = "example.com"
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private fun unb64(s: String) = Base64.getUrlDecoder().decode(s)

    private fun createReq(userId: String = b64.encodeToString("user-1".toByteArray()), name: String = "alice",
                          challenge: String = b64.encodeToString(ByteArray(32) { 7 }), uv: String = "preferred",
                          exclude: JSONArray? = null): JSONObject = JSONObject().apply {
        put("challenge", challenge)
        put("rp", JSONObject().put("id", rp).put("name", "Example"))
        put("user", JSONObject().put("id", userId).put("name", name).put("displayName", name.replaceFirstChar { it.uppercase() }))
        put("pubKeyCredParams", JSONArray().put(JSONObject().put("type", "public-key").put("alg", -7)))
        put("authenticatorSelection", JSONObject().put("residentKey", "required").put("userVerification", uv))
        exclude?.let { put("excludeCredentials", it) }
    }

    private fun getReq(rpId: String = rp, allow: JSONArray? = null): JSONObject = JSONObject().apply {
        put("challenge", b64.encodeToString(ByteArray(32) { 9 }))
        put("rpId", rpId)
        put("userVerification", "preferred")
        allow?.let { put("allowCredentials", it) }
    }

    private val hash = ByteArray(32) { 3 }

    private fun run(key: SoftAuthenticator, create: Boolean, req: JSONObject, pin: String? = null,
                    mode: PinMode = if (pin != null) PinMode.ENTER else PinMode.NONE, newPin: String = "",
                    cd: ClientDataProvider = ClientDataProvider.fromHash(hash), domain: String = rp) =
        PasskeyCeremony.run(key, create,
            if (create) PasskeyJson.normalizeCreate(req) else PasskeyJson.normalizeGet(req, null),
            cd, domain, mode, pin, newPin, null)

    private fun register(key: SoftAuthenticator, name: String, pin: String?) =
        (run(key, true, createReq(userId = b64.encodeToString(name.toByteArray()), name = name), pin) as PasskeyCeremony.Outcome.Done).credential

    @Test fun registerReturnsWebAuthnJson() {
        val key = SoftAuthenticator(pin = "123456")
        val cred = register(key, "alice", "123456")
        val json = PasskeyJson.fromMap(cred.toMap(SerializationType.JSON))
        assertEquals("public-key", json.getString("type"))
        assertEquals(json.getString("id"), json.getString("rawId"))
        assertArrayEquals(key.credentials.single().id, unb64(json.getString("id")))
        val r = json.getJSONObject("response")
        assertTrue(r.getString("attestationObject").isNotEmpty())
        assertTrue(PasskeyJson.ensureClientDataField(json).getJSONObject("response").has("clientDataJSON"))
        assertTrue(key.credentials.single().resident)
    }

    @Test fun signInWithSingleAccountVerifiesSignature() {
        val key = SoftAuthenticator(pin = "123456")
        register(key, "alice", "123456")
        val out = run(key, false, getReq(), "123456") as PasskeyCeremony.Outcome.Done
        val json = PasskeyJson.fromMap(out.credential.toMap(SerializationType.JSON))
        val r = json.getJSONObject("response")
        val authData = unb64(r.getString("authenticatorData"))
        val sig = unb64(r.getString("signature"))
        assertEquals("alice", String(unb64(r.getString("userHandle"))))
        assertEquals(0x05, authData[32].toInt() and 0x05) // UP + UV
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.credentials.single().keys.public); update(authData + hash); verify(sig)
        }
        assertTrue("assertion signature must verify", ok)
    }

    @Test fun multipleAccountsOfferAPicker() {
        val key = SoftAuthenticator(pin = "123456")
        register(key, "alice", "123456"); register(key, "bob", "123456")
        val out = run(key, false, getReq(), "123456") as PasskeyCeremony.Outcome.Pick
        assertEquals(listOf("alice · Alice", "bob · Bob"), out.names)
        val picked = out.m.select(1)
        assertArrayEquals(key.credentials[1].id, picked.rawId)
    }

    @Test fun allowCredentialsNarrowsToOne() {
        val key = SoftAuthenticator(pin = "123456")
        register(key, "alice", "123456"); val bob = register(key, "bob", "123456")
        // Standard base64 with padding, as some sites send it.
        val std = Base64.getEncoder().encodeToString(bob.rawId)
        val allow = JSONArray().put(JSONObject().put("id", std))
        val out = run(key, false, getReq(allow = allow), "123456") as PasskeyCeremony.Outcome.Done
        assertArrayEquals(bob.rawId, out.credential.rawId)
    }

    @Test fun standardBase64InCreateIsAccepted() {
        val key = SoftAuthenticator(pin = "123456")
        val raw = byteArrayOf(-5, -17, -1, 62, 63, 0)
        val req = createReq(userId = Base64.getEncoder().encodeToString(raw), challenge = Base64.getEncoder().encodeToString(ByteArray(33) { -2 }))
        run(key, true, req, "123456") as PasskeyCeremony.Outcome.Done
        assertArrayEquals(raw, key.credentials.single().user["id"] as ByteArray)
    }

    @Test fun nativeAppClientDataIsPassedThrough() {
        val key = SoftAuthenticator()
        val origin = "android:apk-key-hash:abc"
        val cdj = PasskeyJson.clientDataJson("webauthn.create", "Y2hhbA", origin, "com.example.app")
        val out = run(key, true, createReq(), cd = ClientDataProvider.fromClientDataJson(cdj)) as PasskeyCeremony.Outcome.Done
        val r = PasskeyJson.fromMap(out.credential.toMap(SerializationType.JSON)).getJSONObject("response")
        val parsed = JSONObject(String(unb64(r.getString("clientDataJSON"))))
        assertEquals(origin, parsed.getString("origin"))
        assertEquals("com.example.app", parsed.getString("androidPackageName"))
    }

    @Test fun wrongPinReportsRetries() {
        val key = SoftAuthenticator(pin = "123456")
        register(key, "alice", "123456")
        try { run(key, false, getReq(), "000000"); fail() } catch (e: AuthInvalidClientError) {
            assertEquals(7, e.retries)
        }
    }

    @Test fun missingPinIsRequested() {
        val key = SoftAuthenticator(pin = "123456")
        register(key, "alice", "123456")
        try { run(key, false, getReq()); fail() } catch (_: PinRequiredClientError) {}
    }

    @Test fun pinTypedForKeyWithoutPinIsIgnored() {
        val key = SoftAuthenticator()
        register(key, "alice", null)
        assertNotNull(run(key, false, getReq(), "123456") as PasskeyCeremony.Outcome.Done)
    }

    @Test fun rpIdMustMatchCallerDomain() {
        val key = SoftAuthenticator()
        register(key, "alice", null)
        try { run(key, false, getReq(rpId = "evil.com")); fail() } catch (e: ClientError) {
            assertTrue(e.message.orEmpty().contains("RP ID"))
        }
    }

    @Test fun subdomainCallerMayUseParentRpId() {
        val key = SoftAuthenticator()
        register(key, "alice", null)
        assertNotNull(run(key, false, getReq(), domain = "login.example.com") as PasskeyCeremony.Outcome.Done)
    }

    @Test fun uvRequiredWithoutPinAsksForSetupThenWorks() {
        val key = SoftAuthenticator(pin = null)
        try { run(key, true, createReq(uv = "required")); fail() } catch (_: PasskeyCeremony.NeedPinSetup) {}
        run(key, true, createReq(uv = "required"), mode = PinMode.SET_NEW, newPin = "246810") as PasskeyCeremony.Outcome.Done
        assertEquals("246810", key.pin)
    }

    @Test fun forcedPinChangeIsHandled() {
        val key = SoftAuthenticator(pin = "123456", forcePinChange = true)
        try { run(key, true, createReq(), "123456"); fail() } catch (_: PasskeyCeremony.NeedPinChange) {}
        run(key, true, createReq(), "123456", mode = PinMode.CHANGE, newPin = "654321") as PasskeyCeremony.Outcome.Done
        assertEquals("654321", key.pin)
    }

    @Test fun excludedCredentialIsRejected() {
        val key = SoftAuthenticator(pin = "123456")
        val alice = register(key, "alice", "123456")
        val ex = JSONArray().put(JSONObject().put("id", b64.encodeToString(alice.rawId)).put("type", "public-key"))
        try { run(key, true, createReq(exclude = ex), "123456"); fail() } catch (e: ClientError) {
            assertEquals(ClientError.Code.DEVICE_INELIGIBLE, e.errorCode)
        }
        assertEquals(1, key.credentials.size)
    }

    @Test fun preferredUvWorksOnKeyWithoutPin() {
        val key = SoftAuthenticator()
        run(key, true, createReq(uv = "preferred")) as PasskeyCeremony.Outcome.Done
        val out = run(key, false, getReq()) as PasskeyCeremony.Outcome.Done
        assertEquals(0, PasskeyJson.fromMap(out.credential.toMap(SerializationType.JSON)).getJSONObject("response")
            .getString("authenticatorData").let { unb64(it)[32].toInt() and 0x04 })
    }

    @Test fun allowedIdsAreNormalized() {
        val req = JSONObject().put("allowCredentials", JSONArray().put(JSONObject().put("id", "a+b/c==")))
        assertEquals(setOf("a-b_c"), PasskeyJson.allowedIds(req.toString()))
    }
}
