package net.skorchin.ykmanager.passkey

import androidx.annotation.RequiresApi
import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.Ctap2Client
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable
import com.yubico.yubikit.fido.client.WebAuthnClient
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import com.yubico.yubikit.fido.webauthn.SerializationType
import org.json.JSONObject

/**
 * The CTAP part of a passkey ceremony, free of Android UI so it can be
 * tested against a software authenticator.
 *
 * Runs on YubiKit's connection thread while the key is connected, and does
 * everything in that one connection: optional PIN set or change, PIN/UV
 * token, then makeCredential or getAssertion. That is what makes a single
 * NFC tap enough.
 */
@RequiresApi(26)
object PasskeyCeremony {

    sealed class Outcome {
        data class Done(val credential: PublicKeyCredential) : Outcome()
        data class Pick(val m: MultipleAssertionsAvailable, val names: List<String>) : Outcome()
    }

    /** The key insists on a new PIN before use (forcePinChange). */
    class NeedPinChange : Exception()

    /** The site needs user verification but the key has no PIN yet. */
    class NeedPinSetup : Exception()

    data class KeyFacts(val minPinLength: Int, val fingerprint: Boolean)

    fun run(
        conn: YubiKeyConnection,
        isCreate: Boolean,
        req: JSONObject,
        clientData: ClientDataProvider,
        effectiveDomain: String,
        mode: PinMode,
        pinIn: String?,
        newPinIn: String,
        state: CommandState?,
        onFacts: (KeyFacts) -> Unit = {},
    ): Outcome {
        val client = WebAuthnClient.create(conn, null, null)
        try {
            var pinToUse: String? = pinIn
            if (client is Ctap2Client) {
                val info = client.session.cachedInfo
                onFacts(KeyFacts(info.minPinLength.coerceAtLeast(4), info.options["uv"] == true && pinIn == null))
                when (mode) {
                    PinMode.SET_NEW -> { client.setPin(newPinIn.toCharArray()); pinToUse = newPinIn }
                    PinMode.CHANGE -> { client.changePin(pinIn.orEmpty().toCharArray(), newPinIn.toCharArray()); pinToUse = newPinIn }
                    else -> if (info.forcePinChange) throw NeedPinChange()
                }
                // A PIN typed for a key that has none is simply not used.
                if (!client.isPinConfigured) pinToUse = null
            } else {
                pinToUse = null // U2F-only key (YubiKey 4, NEO, FIDO U2F Security Key)
            }

            // Browsers treat "preferred" as optional when the key has no PIN
            // or fingerprint; YubiKit would refuse. Only "required" asks for setup.
            val noUv = client is Ctap2Client && !client.isPinConfigured &&
                client.session.cachedInfo.options["uv"] != true
            val map = PasskeyJson.toMap(if (noUv) PasskeyJson.relaxPreferredUv(req, isCreate) else req)
            return if (isCreate) {
                val options = PublicKeyCredentialCreationOptions.fromMap(map, SerializationType.JSON)
                try {
                    Outcome.Done(client.makeCredential(clientData, options, effectiveDomain, pinToUse?.toCharArray(), null, state))
                } catch (e: ClientError) {
                    if (needsPinSetup(client, e)) throw NeedPinSetup() else throw e
                }
            } else {
                val options = PublicKeyCredentialRequestOptions.fromMap(map, SerializationType.JSON)
                try {
                    Outcome.Done(client.getAssertion(clientData, options, effectiveDomain, pinToUse?.toCharArray(), state))
                } catch (m: MultipleAssertionsAvailable) {
                    val names = runCatching {
                        m.users.mapIndexed { i, u ->
                            listOfNotNull(u.name.ifBlank { null }, u.displayName.takeIf { it.isNotBlank() && it != u.name })
                                .joinToString(" · ").ifBlank { "Passkey ${i + 1}" }
                        }
                    }.getOrElse { (1..m.assertionCount).map { "Passkey $it" } }
                    Outcome.Pick(m, names)
                } catch (e: ClientError) {
                    if (needsPinSetup(client, e)) throw NeedPinSetup() else throw e
                }
            }
        } finally {
            runCatching { client.close() }
        }
    }

    private fun needsPinSetup(client: WebAuthnClient, e: ClientError): Boolean =
        client is Ctap2Client && client.isPinSupported && !client.isPinConfigured &&
            e.errorCode == ClientError.Code.CONFIGURATION_UNSUPPORTED
}
