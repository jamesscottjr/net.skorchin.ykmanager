package com.yubico.yubikit.fido.ctap

import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.Cbor
import java.io.ByteArrayOutputStream

/**
 * Credential enumeration that returns the complete CTAP 2.1 response maps.
 *
 * YubiKit's [CredentialManagement.CredentialData] only surfaces the user, credential ID and
 * public key. The authenticator also reports the credProtect policy (0x0A) and whether a
 * large-blob key exists (0x0B); YK Manager shows those on the passkey details screen, so this
 * class issues the same authenticatorCredentialManagement sub-commands and keeps the raw maps.
 *
 * It lives in YubiKit's package only because `Ctap2Session.credentialManagement` is
 * package-private; it uses no other internals.
 */
class RawCredentialManagement(
    private val ctap: Ctap2Session,
    private val pinUvAuth: PinUvAuthProtocol,
    private val pinUvToken: ByteArray,
) {
    /** One stored discoverable credential together with the relying party it belongs to. */
    class RawCredential(
        val rp: Map<String, *>,
        val rpIdHash: ByteArray,
        val user: Map<String, *>,
        val credentialId: Map<String, *>,
        val publicKey: Map<Any?, *>,
        val credProtect: Int?,
        val largeBlobKey: ByteArray?,
    )

    private fun call(subCommand: Byte, params: Map<*, *>?, authenticate: Boolean): Map<Int, *> {
        var auth: ByteArray? = null
        if (authenticate) {
            val out = ByteArrayOutputStream()
            out.write(subCommand.toInt())
            if (params != null) Cbor.encodeTo(out, params)
            auth = pinUvAuth.authenticate(pinUvToken, out.toByteArray())
        }
        return ctap.credentialManagement(subCommand.toInt(), params, pinUvAuth.version, auth)
    }

    /** Enumerates every relying party and every credential stored for it. */
    fun enumerateAll(): List<RawCredential> {
        val out = mutableListOf<RawCredential>()
        val rps = try {
            val first = call(CredentialManagement.CMD_ENUMERATE_RPS_BEGIN, null, true)
            val total = first[CredentialManagement.RESULT_TOTAL_RPS] as? Int ?: 1
            buildList {
                add(first)
                repeat(total - 1) { add(call(CredentialManagement.CMD_ENUMERATE_RPS_NEXT, null, false)) }
            }
        } catch (e: CtapException) {
            if (e.ctapError != CtapException.ERR_NO_CREDENTIALS) throw e
            emptyList()
        }
        for (rpData in rps) {
            @Suppress("UNCHECKED_CAST")
            val rp = rpData[CredentialManagement.RESULT_RP] as? Map<String, *> ?: emptyMap<String, Any>()
            val rpIdHash = rpData[CredentialManagement.RESULT_RP_ID_HASH] as? ByteArray ?: continue
            val creds = try {
                val first = call(
                    CredentialManagement.CMD_ENUMERATE_CREDS_BEGIN,
                    mapOf(CredentialManagement.PARAM_RP_ID_HASH to rpIdHash),
                    true,
                )
                val total = first[CredentialManagement.RESULT_TOTAL_CREDENTIALS] as? Int ?: 1
                buildList {
                    add(first)
                    repeat(total - 1) { add(call(CredentialManagement.CMD_ENUMERATE_CREDS_NEXT, null, false)) }
                }
            } catch (e: CtapException) {
                if (e.ctapError != CtapException.ERR_NO_CREDENTIALS) throw e
                emptyList()
            }
            for (c in creds) {
                @Suppress("UNCHECKED_CAST")
                out += RawCredential(
                    rp = rp,
                    rpIdHash = rpIdHash,
                    user = c[CredentialManagement.RESULT_USER] as? Map<String, *> ?: emptyMap<String, Any>(),
                    credentialId = c[CredentialManagement.RESULT_CREDENTIAL_ID] as? Map<String, *> ?: emptyMap<String, Any>(),
                    publicKey = c[CredentialManagement.RESULT_PUBLIC_KEY] as? Map<Any?, *> ?: emptyMap<Any?, Any>(),
                    credProtect = c[CredentialManagement.RESULT_CRED_PROTECT] as? Int,
                    largeBlobKey = c[CredentialManagement.RESULT_LARGE_BLOB_KEY] as? ByteArray,
                )
            }
        }
        return out
    }
}
