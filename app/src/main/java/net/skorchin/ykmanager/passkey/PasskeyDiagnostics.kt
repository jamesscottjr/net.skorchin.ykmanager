package net.skorchin.ykmanager.passkey

import androidx.annotation.RequiresApi
import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds the entries of the passkey diagnostics log: what a site asked for
 * and what was sent back, without challenges, signatures or keys.
 */
@RequiresApi(26)
object PasskeyDiagnostics {

    fun summarizeRequest(o: JSONObject, create: Boolean): JSONObject = JSONObject().apply {
        if (create) {
            val sel = o.optJSONObject("authenticatorSelection")
            put("userVerification", sel?.optString("userVerification")?.ifBlank { null } ?: "(unset)")
            put("residentKey", sel?.optString("residentKey")?.ifBlank { null } ?: "(unset)")
            put("authenticatorAttachment", sel?.optString("authenticatorAttachment")?.ifBlank { null } ?: "(unset)")
            put("attestation", o.optString("attestation").ifBlank { "(unset)" })
            put("excludeCredentials", o.optJSONArray("excludeCredentials")?.length() ?: 0)
            put("algorithms", JSONArray().apply {
                o.optJSONArray("pubKeyCredParams")?.let { a -> for (i in 0 until a.length()) put(a.optJSONObject(i)?.opt("alg")) }
            })
        } else {
            put("userVerification", o.optString("userVerification").ifBlank { "(unset)" })
            val allow = o.optJSONArray("allowCredentials")
            put("allowCredentials", allow?.length() ?: 0)
            if (allow != null) put("allowTransports", JSONArray().apply {
                for (i in 0 until allow.length()) put(allow.optJSONObject(i)?.optJSONArray("transports") ?: JSONArray())
            })
        }
        put("extensions", JSONArray(o.optJSONObject("extensions")?.keys()?.asSequence()?.toList().orEmpty()))
        o.optJSONArray("hints")?.let { put("hints", it) }
        put("timeout", o.opt("timeout") ?: "(unset)")
    }

    fun summarizeResponse(json: JSONObject, create: Boolean, mode: PasskeyJson.ClientDataMode): JSONObject = JSONObject().apply {
        put("credentialIdPrefix", json.optString("id").take(10))
        put("authenticatorAttachment", json.optString("authenticatorAttachment"))
        put("clientDataJSON", mode.name.lowercase())
        val r = json.optJSONObject("response")
        put("responseFields", JSONArray(r?.keys()?.asSequence()?.toList().orEmpty()))
        put("clientExtensionResults", json.optJSONObject("clientExtensionResults")?.toString() ?: "(none)")
        val ad = r?.optString("authenticatorData")?.let { runCatching { java.util.Base64.getUrlDecoder().decode(it) }.getOrNull() }
        if (ad != null && ad.size >= 37) {
            val f = ad[32].toInt() and 0xFF
            put("flags", buildList {
                if (f and 0x01 != 0) add("UP"); if (f and 0x04 != 0) add("UV")
                if (f and 0x08 != 0) add("BE"); if (f and 0x10 != 0) add("BS")
                if (f and 0x40 != 0) add("AT"); if (f and 0x80 != 0) add("ED")
            }.joinToString(","))
            put("signCount", ((ad[33].toLong() and 0xFF) shl 24) or ((ad[34].toLong() and 0xFF) shl 16) or
                ((ad[35].toLong() and 0xFF) shl 8) or (ad[36].toLong() and 0xFF))
            if (create && ad.size >= 53) put("aaguid", ad.copyOfRange(37, 53).joinToString("") { "%02x".format(it) })
        }
        if (!create) put("userHandle", r?.has("userHandle") == true)
        if (create) put("transports", r?.optJSONArray("transports") ?: JSONArray())
    }
}
