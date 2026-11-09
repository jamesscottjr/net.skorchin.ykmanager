package net.skorchin.ykmanager.passkey

import androidx.annotation.RequiresApi
import org.json.JSONArray
import org.json.JSONObject

/** Conversions between the WebAuthn JSON used by Credential Manager and YubiKit's maps. */
@RequiresApi(26) // only used by the Android 14+ passkey provider
object PasskeyJson {

    fun toMap(o: JSONObject): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        for (k in o.keys()) m[k] = unwrap(o.get(k))
        return m
    }

    private fun unwrap(v: Any?): Any? = when (v) {
        JSONObject.NULL -> null
        is JSONObject -> toMap(v)
        is JSONArray -> (0 until v.length()).map { unwrap(v.get(it)) }
        else -> v
    }

    fun fromMap(m: Map<String, *>): JSONObject = JSONObject().apply {
        m.forEach { (k, v) -> if (v != null) put(k, wrap(v)) }
    }

    private fun wrap(v: Any): Any = when (v) {
        is Map<*, *> -> JSONObject().apply { v.forEach { (k, x) -> if (k != null && x != null) put(k.toString(), wrap(x)) } }
        is Collection<*> -> JSONArray().apply { v.filterNotNull().forEach { put(wrap(it)) } }
        is ByteArray -> b64(v)
        else -> v
    }

    fun b64(bytes: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /** Some sites send standard Base64 (with + / =). YubiKit expects base64url without padding. */
    fun normalizeB64(s: String): String = s.trim().replace('+', '-').replace('/', '_').trimEnd('=')

    /**
     * Copy of the request with every binary field converted to canonical
     * base64url, so a site's encoding quirks can't break parsing.
     */
    fun normalizeCreate(json: JSONObject): JSONObject {
        val o = JSONObject(json.toString())
        o.optString("challenge").takeIf { it.isNotEmpty() }?.let { o.put("challenge", normalizeB64(it)) }
        o.optJSONObject("user")?.let { u -> u.optString("id").takeIf { it.isNotEmpty() }?.let { u.put("id", normalizeB64(it)) } }
        o.optJSONArray("excludeCredentials")?.let { normalizeDescriptors(it) }
        return o
    }

    fun normalizeGet(json: JSONObject, fallbackRpId: String?): JSONObject {
        val o = JSONObject(json.toString())
        o.optString("challenge").takeIf { it.isNotEmpty() }?.let { o.put("challenge", normalizeB64(it)) }
        o.optJSONArray("allowCredentials")?.let { normalizeDescriptors(it) }
        if (o.optString("rpId").isBlank() && fallbackRpId != null) o.put("rpId", fallbackRpId)
        return o
    }

    private fun normalizeDescriptors(arr: JSONArray) {
        for (i in 0 until arr.length()) {
            val d = arr.optJSONObject(i) ?: continue
            d.optString("id").takeIf { it.isNotEmpty() }?.let { d.put("id", normalizeB64(it)) }
            if (!d.has("type")) d.put("type", "public-key")
        }
    }

    /** Copy of the request with userVerification "preferred" (or unset) turned into "discouraged". */
    fun relaxPreferredUv(json: JSONObject, isCreate: Boolean): JSONObject {
        val o = JSONObject(json.toString())
        val holder = if (isCreate) (o.optJSONObject("authenticatorSelection") ?: JSONObject().also { o.put("authenticatorSelection", it) }) else o
        if (holder.optString("userVerification", "preferred") != "required") holder.put("userVerification", "discouraged")
        return o
    }

    /**
     * Browser calls hand us only clientDataHash. Recreate the clientDataJSON
     * the browser built (Chrome's format, with and without its optional
     * extra key) and return it only if its SHA-256 matches the hash we signed.
     * Then the response is correct whether or not the browser swaps in its own copy.
     */
    fun matchBrowserClientData(hash: ByteArray, type: String, challenge: String, origin: String): ByteArray? {
        val q = ::jsonString
        val base = "{\"type\":${q(type)},\"challenge\":${q(challenge)},\"origin\":${q(origin)}"
        val extra = ",\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\""
        val candidates = listOf(
            "$base,\"crossOrigin\":false}",
            "$base,\"crossOrigin\":false$extra}",
            "$base}",
            "$base$extra}",
        )
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return candidates.map { it.toByteArray(Charsets.UTF_8) }.firstOrNull { md.digest(it).contentEquals(hash) }
    }

    /** JSON string literal as browsers write it: only quote, backslash and control characters escaped (no "\\/"). */
    fun jsonString(v: String): String {
        val sb = StringBuilder("\"")
        for (c in v) when {
            c == '"' -> sb.append("\\\"")
            c == '\\' -> sb.append("\\\\")
            c < ' ' -> sb.append(String.format("\\u%04x", c.code))
            else -> sb.append(c)
        }
        return sb.append('"').toString()
    }

    /** How clientDataJSON in the response was produced, for the diagnostics log. */
    enum class ClientDataMode { BUILT, MATCHED, PLACEHOLDER }

    /**
     * Shape the response the way Android passkey providers are expected to
     * return it (as Google Password Manager, Bitwarden and KeePassDX do):
     * authenticatorAttachment "platform", clientExtensionResults present, and
     * a clientDataJSON value. If the browser gave only a hash and the JSON
     * could not be recreated, a placeholder is used, which Android's
     * guidance says the browser replaces.
     */
    fun finalizeResponse(json: JSONObject, matchedClientData: ByteArray?): Pair<JSONObject, ClientDataMode> {
        json.put("authenticatorAttachment", "platform")
        if (!json.has("clientExtensionResults")) json.put("clientExtensionResults", JSONObject())
        val r = json.optJSONObject("response") ?: return json to ClientDataMode.BUILT
        val mode = when {
            matchedClientData != null -> { r.put("clientDataJSON", b64(matchedClientData)); ClientDataMode.MATCHED }
            r.has("clientDataJSON") -> ClientDataMode.BUILT
            else -> { r.put("clientDataJSON", b64("{}".toByteArray())); ClientDataMode.PLACEHOLDER }
        }
        return json to mode
    }

    /** What [prepareRegistration] did, for the diagnostics log. */
    data class RegistrationInfo(val attestationRequested: String, val formatFromKey: String, val formatReturned: String)

    /**
     * Make a registration response look like what a browser returns for a
     * security key, and keep every field consistent with attestationObject.
     *
     * - Attestation "none" (or unset): Chrome replaces a security key's
     *   attestation with fmt "none" and a zero AAGUID. Many sites (banks in
     *   particular) only accept "none" when that's what they asked for.
     *   "direct", "indirect" and "enterprise" keep the key's attestation.
     * - authenticatorData, publicKey and publicKeyAlgorithm are derived from
     *   the returned attestationObject. Chrome rejects the response if they
     *   differ in any byte from what it computes.
     */
    fun prepareRegistration(json: JSONObject, request: JSONObject?): RegistrationInfo {
        val requested = request?.optString("attestation")?.ifBlank { null } ?: "none"
        val r = json.optJSONObject("response") ?: return RegistrationInfo(requested, "?", "?")
        val attBytes = java.util.Base64.getUrlDecoder().decode(r.getString("attestationObject"))
        @Suppress("UNCHECKED_CAST")
        val att = com.yubico.yubikit.fido.Cbor.decode(attBytes) as Map<String, Any?>
        val fmt = att["fmt"] as? String ?: "?"
        var authData = att["authData"] as ByteArray
        var outFmt = fmt
        if (requested == "none" && fmt != "none") {
            authData = authData.copyOf()
            if (authData.size >= 53 && (authData[32].toInt() and 0x40) != 0) {
                for (i in 37 until 53) authData[i] = 0
            }
            val none = LinkedHashMap<String, Any>()
            none["fmt"] = "none"
            none["attStmt"] = emptyMap<String, Any>()
            none["authData"] = authData
            r.put("attestationObject", b64(com.yubico.yubikit.fido.Cbor.encode(none)))
            outFmt = "none"
        }
        r.put("authenticatorData", b64(authData))

        val cose = com.yubico.yubikit.fido.webauthn.AuthenticatorData
            .parseFrom(java.nio.ByteBuffer.wrap(authData)).attestedCredentialData?.cosePublicKey
        if (cose != null) {
            (cose[3] as? Number)?.let { r.put("publicKeyAlgorithm", it.toInt()) }
            val spki = spkiFromCose(cose)
            if (spki != null) r.put("publicKey", b64(spki))
        }
        if (!r.has("transports")) r.put("transports", JSONArray())
        return RegistrationInfo(requested, fmt, outFmt)
    }

    private val P256_SPKI_PREFIX = hex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    private val ED25519_SPKI_PREFIX = hex("302a300506032b6570032100")

    /**
     * DER SubjectPublicKeyInfo for P-256 (named curve) and Ed25519 keys, the
     * exact encoding Chrome computes. Other key types: null (YubiKit's value is kept).
     */
    fun spkiFromCose(cose: Map<Int, *>): ByteArray? {
        val kty = (cose[1] as? Number)?.toInt()
        val crv = (cose[-1] as? Number)?.toInt()
        val x = cose[-2] as? ByteArray ?: return null
        return when {
            kty == 2 && crv == 1 -> {
                val y = cose[-3] as? ByteArray ?: return null
                if (x.size != 32 || y.size != 32) return null
                P256_SPKI_PREFIX + byteArrayOf(0x04) + x + y
            }
            kty == 1 && crv == 6 && x.size == 32 -> ED25519_SPKI_PREFIX + x
            else -> null
        }
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** Back-compat for tests: placeholder only. */
    fun ensureClientDataField(json: JSONObject): JSONObject = finalizeResponse(json, null).first

    /** IDs from allowCredentials, in canonical base64url. */
    fun allowedIds(requestJson: String): Set<String> = runCatching {
        val arr = JSONObject(requestJson).optJSONArray("allowCredentials") ?: return emptySet()
        (0 until arr.length()).mapNotNull { arr.optJSONObject(it)?.optString("id")?.takeIf { s -> s.isNotEmpty() } }
            .map { normalizeB64(it) }.toSet()
    }.getOrDefault(emptySet())

    /** The clientDataJSON a browser would produce, for requests from native apps. */
    fun clientDataJson(type: String, challenge: String, origin: String, androidPackage: String?): ByteArray {
        val sb = StringBuilder()
        sb.append("{\"type\":").append(jsonString(type))
        sb.append(",\"challenge\":").append(jsonString(challenge))
        sb.append(",\"origin\":").append(jsonString(origin))
        if (androidPackage != null) sb.append(",\"androidPackageName\":").append(jsonString(androidPackage))
        sb.append("}")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }
}
