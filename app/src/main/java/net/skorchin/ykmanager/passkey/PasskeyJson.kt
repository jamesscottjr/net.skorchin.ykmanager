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
     * Browser calls hand us only the clientDataHash, so YubiKit's JSON has
     * no clientDataJSON. The browser substitutes its own; some parsers still
     * expect the field, so add a placeholder.
     */
    fun ensureClientDataField(json: JSONObject): JSONObject {
        val r = json.optJSONObject("response") ?: return json
        if (!r.has("clientDataJSON")) r.put("clientDataJSON", b64("{}".toByteArray()))
        return json
    }

    /** IDs from allowCredentials, in canonical base64url. */
    fun allowedIds(requestJson: String): Set<String> = runCatching {
        val arr = JSONObject(requestJson).optJSONArray("allowCredentials") ?: return emptySet()
        (0 until arr.length()).mapNotNull { arr.optJSONObject(it)?.optString("id")?.takeIf { s -> s.isNotEmpty() } }
            .map { normalizeB64(it) }.toSet()
    }.getOrDefault(emptySet())

    /** The clientDataJSON a browser would produce, for requests from native apps. */
    fun clientDataJson(type: String, challenge: String, origin: String, androidPackage: String?): ByteArray {
        val sb = StringBuilder()
        sb.append("{\"type\":").append(JSONObject.quote(type))
        sb.append(",\"challenge\":").append(JSONObject.quote(challenge))
        sb.append(",\"origin\":").append(JSONObject.quote(origin))
        if (androidPackage != null) sb.append(",\"androidPackageName\":").append(JSONObject.quote(androidPackage))
        sb.append("}")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }
}
