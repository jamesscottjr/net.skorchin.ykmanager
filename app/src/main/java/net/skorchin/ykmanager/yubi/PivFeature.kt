package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.core.Version
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.keys.PrivateKeyValues
import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.piv.KeyType
import com.yubico.yubikit.piv.ManagementKeyMetadata
import com.yubico.yubikit.piv.ManagementKeyType
import com.yubico.yubikit.piv.PinMetadata
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.SlotMetadata
import com.yubico.yubikit.piv.TouchPolicy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.StringReader
import java.math.BigInteger
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

data class PivSlotView(
    val slot: Slot,
    val certificate: X509Certificate?,
    val metadata: SlotMetadata?,
) {
    val isEmpty: Boolean get() = certificate == null && metadata == null
}

data class PivState(
    val loaded: Boolean = false,
    val version: Version? = null,
    val pinAttempts: Int? = null,
    val pin: PinMetadata? = null,
    val puk: PinMetadata? = null,
    val managementKey: ManagementKeyMetadata? = null,
    val slots: List<PivSlotView> = emptyList(),
    val includesRetired: Boolean = false,
)

enum class CertOutput { SELF_SIGNED, CSR }

/** How to sign a new certificate: algorithm id plus a function that signs data. */
private class PivSigner(
    private val session: PivSession,
    private val slot: Slot,
    private val keyType: KeyType,
) : ContentSigner {
    private val buffer = ByteArrayOutputStream()

    private val sigAlgName = when (keyType) {
        KeyType.ECCP384 -> "SHA384WITHECDSA"
        KeyType.ECCP256 -> "SHA256WITHECDSA"
        else -> "SHA256WITHRSA"
    }

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier =
        DefaultSignatureAlgorithmIdentifierFinder().find(sigAlgName)

    override fun getOutputStream(): OutputStream = buffer

    override fun getSignature(): ByteArray {
        val data = buffer.toByteArray()
        return when (keyType) {
            KeyType.ECCP256 -> session.rawSignOrDecrypt(slot, keyType, sha("SHA-256", data))
            KeyType.ECCP384 -> session.rawSignOrDecrypt(slot, keyType, sha("SHA-384", data))
            else -> {
                // RSA PKCS#1 v1.5: 00 01 FF..FF 00 || DigestInfo(SHA-256)
                val digestInfo = DigestInfo(
                    AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE),
                    sha("SHA-256", data)
                ).encoded
                val len = keyType.params.bitLength / 8
                val padded = ByteArray(len)
                padded[0] = 0; padded[1] = 1
                val psEnd = len - digestInfo.size - 1
                for (i in 2 until psEnd) padded[i] = 0xff.toByte()
                padded[psEnd] = 0
                digestInfo.copyInto(padded, psEnd + 1)
                session.rawSignOrDecrypt(slot, keyType, padded)
            }
        }
    }

    private fun sha(alg: String, d: ByteArray) = MessageDigest.getInstance(alg).digest(d)
}

class PivFeature(private val core: YubiKeyCore) {

    private val _state = MutableStateFlow(PivState())
    val state: StateFlow<PivState> = _state.asStateFlow()

    private val bc = BouncyCastleProvider()

    var showRetired: Boolean = false

    fun clear() { _state.value = PivState() }

    suspend fun refresh(device: YubiKeyDevice) {
        _state.value = core.smartCard(device) { conn ->
            val s = PivSession(conn)
            val hasMeta = s.supports(PivSession.FEATURE_METADATA)
            val slots = (MAIN_SLOTS + if (showRetired) RETIRED_SLOTS else emptyList()).map { slot ->
                val cert = runCatching { s.getCertificate(slot) }.getOrNull()
                val meta = if (hasMeta) runCatching { s.getSlotMetadata(slot) }.getOrNull() else null
                PivSlotView(slot, cert, meta)
            }.filter { it.slot in MAIN_SLOTS || !it.isEmpty }
            PivState(
                loaded = true,
                version = s.version,
                pinAttempts = runCatching { s.pinAttempts }.getOrNull(),
                pin = if (hasMeta) runCatching { s.pinMetadata }.getOrNull() else null,
                puk = if (hasMeta) runCatching { s.pukMetadata }.getOrNull() else null,
                managementKey = if (hasMeta) runCatching { s.managementKeyMetadata }.getOrNull() else null,
                slots = slots,
                includesRetired = showRetired,
            )
        }
    }

    private fun PivSession.auth(mgmtKeyHex: String) {
        val key = runCatching { Encoding.fromHex(mgmtKeyHex.ifBlank { DEFAULT_MGMT_KEY }) }
            .getOrElse { throw UserFacingException("Management key must be hex") }
        try {
            authenticate(key)
        } catch (e: Exception) {
            throw UserFacingException("Management key authentication failed. Check the key and its type.")
        }
    }

    private fun PivSession.pin(pin: CharArray) {
        try {
            verifyPin(pin)
        } catch (e: com.yubico.yubikit.core.application.InvalidPinException) {
            throw UserFacingException("Wrong PIN. ${e.attemptsRemaining} attempt(s) remaining.")
        }
    }

    fun generate(
        slot: Slot, keyType: KeyType, pinPolicy: PinPolicy, touchPolicy: TouchPolicy,
        subject: String, validDays: Int, output: CertOutput, mgmtKeyHex: String, pin: CharArray,
    ) {
        core.run("generate a key") { device ->
            val name = runCatching { X500Name(if (subject.contains("=")) subject else "CN=$subject") }
                .getOrElse { throw UserFacingException("Subject must look like CN=Name,O=Org") }
            val csr: ByteArray? = core.smartCard(device) { conn ->
                val s = PivSession(conn)
                s.auth(mgmtKeyHex)
                if (touchPolicy == TouchPolicy.ALWAYS || touchPolicy == TouchPolicy.CACHED) core.showTouchPrompt(true)
                val pub: PublicKeyValues = s.generateKeyValues(slot, keyType, pinPolicy, touchPolicy)
                val spki = SubjectPublicKeyInfo.getInstance(pub.encoded)
                s.pin(pin)
                val signer = PivSigner(s, slot, keyType)
                if (output == CertOutput.SELF_SIGNED) {
                    val now = System.currentTimeMillis()
                    val builder = X509v3CertificateBuilder(
                        name, BigInteger(64, java.security.SecureRandom()).abs(),
                        Date(now - 60_000), Date(now + validDays * 86_400_000L), name, spki,
                    ).addExtension(Extension.basicConstraints, false, BasicConstraints(false))
                    val holder = builder.build(signer)
                    val cert = CertificateFactory.getInstance("X.509")
                        .generateCertificate(ByteArrayInputStream(holder.encoded)) as X509Certificate
                    s.putCertificate(slot, cert)
                    null
                } else {
                    PKCS10CertificationRequestBuilder(name, spki).build(signer).encoded
                }
            }
            core.showTouchPrompt(false)
            if (csr != null) {
                core.offerExport(ExportFile("${slotName(slot)}.csr", "application/pkcs10", pem("CERTIFICATE REQUEST", csr)))
                core.toast("Key generated. Save the certificate signing request.")
            } else {
                core.toast("Key and self-signed certificate created in slot ${slotHex(slot)}")
            }
        }
    }

    /**
     * Import a certificate and/or private key. Supports PKCS#12 (.p12/.pfx),
     * PEM (certificate and/or private key) and DER certificates.
     */
    fun import(
        slot: Slot, bytes: ByteArray, password: CharArray?, pinPolicy: PinPolicy,
        touchPolicy: TouchPolicy, mgmtKeyHex: String,
    ) {
        core.run("import into slot ${slotHex(slot)}") { _device ->
            val (key, cert) = parseImport(bytes, password)
            if (key == null && cert == null) throw UserFacingException("No certificate or private key found in the file")
            core.smartCard(_device) { conn ->
                val s = PivSession(conn)
                s.auth(mgmtKeyHex)
                if (key != null) s.putKey(slot, PrivateKeyValues.fromPrivateKey(key), pinPolicy, touchPolicy)
                if (cert != null) s.putCertificate(slot, cert)
            }
            core.toast(buildString {
                append("Imported ")
                append(listOfNotNull(key?.let { "private key" }, cert?.let { "certificate" }).joinToString(" and "))
                append(" into slot ${slotHex(slot)}")
            })
        }
    }

    private fun parseImport(bytes: ByteArray, password: CharArray?): Pair<PrivateKey?, X509Certificate?> {
        val text = runCatching { String(bytes, Charsets.US_ASCII) }.getOrDefault("")
        if (text.contains("-----BEGIN")) {
            var key: PrivateKey? = null
            var cert: X509Certificate? = null
            val conv = JcaPEMKeyConverter().setProvider(bc)
            PEMParser(StringReader(text)).use { p ->
                while (true) {
                    val obj = p.readObject() ?: break
                    when (obj) {
                        is PEMKeyPair -> key = key ?: conv.getKeyPair(obj).private
                        is PrivateKeyInfo -> key = key ?: conv.getPrivateKey(obj)
                        is org.bouncycastle.cert.X509CertificateHolder -> cert = cert ?: CertificateFactory
                            .getInstance("X.509").generateCertificate(ByteArrayInputStream(obj.encoded)) as X509Certificate
                        is org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo -> {
                            val pw = password ?: throw UserFacingException("This private key is encrypted. Enter its password.")
                            val dec = org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder()
                                .setProvider(bc).build(pw)
                            key = conv.getPrivateKey(obj.decryptPrivateKeyInfo(dec))
                        }
                        is org.bouncycastle.openssl.PEMEncryptedKeyPair -> {
                            val pw = password ?: throw UserFacingException("This private key is encrypted. Enter its password.")
                            val dec = org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder().setProvider(bc).build(pw)
                            key = conv.getKeyPair(obj.decryptKeyPair(dec)).private
                        }
                    }
                }
            }
            return key to cert
        }
        // DER certificate?
        runCatching {
            val c = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
            return null to c
        }
        // PKCS#12
        val ks = KeyStore.getInstance("PKCS12", bc)
        try {
            ks.load(ByteArrayInputStream(bytes), password ?: CharArray(0))
        } catch (e: Exception) {
            throw UserFacingException("Could not open the file. If it is a PKCS#12 file, check the password.")
        }
        for (alias in ks.aliases()) {
            if (ks.isKeyEntry(alias)) {
                val k = ks.getKey(alias, password ?: CharArray(0)) as? PrivateKey
                val c = ks.getCertificate(alias) as? X509Certificate
                return k to c
            }
        }
        val alias = ks.aliases().toList().firstOrNull()
        return null to (alias?.let { ks.getCertificate(it) as? X509Certificate })
    }

    fun exportCertificate(view: PivSlotView) {
        val cert = view.certificate ?: return
        core.offerExport(ExportFile("${slotName(view.slot)}.pem", "application/x-pem-file", pem("CERTIFICATE", cert.encoded)))
    }

    fun delete(slot: Slot, deleteKey: Boolean, mgmtKeyHex: String) {
        core.run("delete slot ${slotHex(slot)}") { device ->
            core.smartCard(device) { conn ->
                val s = PivSession(conn)
                s.auth(mgmtKeyHex)
                runCatching { s.deleteCertificate(slot) }
                if (deleteKey) {
                    if (!s.supports(PivSession.FEATURE_MOVE_KEY)) {
                        throw UserFacingException("Deleting keys requires firmware 5.7 or newer. The certificate was deleted.")
                    }
                    s.deleteKey(slot)
                }
            }
            core.toast(if (deleteKey) "Certificate and key deleted" else "Certificate deleted")
        }
    }

    fun changePin(old: CharArray, new: CharArray) = pinOp("change the PIN") { s ->
        s.changePin(old, new); "PIN changed"
    }

    fun changePuk(old: CharArray, new: CharArray) = pinOp("change the PUK") { s ->
        s.changePuk(old, new); "PUK changed"
    }

    fun unblockPin(puk: CharArray, new: CharArray) = pinOp("unblock the PIN") { s ->
        s.unblockPin(puk, new); "PIN unblocked and set"
    }

    fun setRetries(pinRetries: Int, pukRetries: Int, mgmtKeyHex: String, pin: CharArray) = pinOp("set retry counts") { s ->
        s.auth(mgmtKeyHex); s.pin(pin); s.setPinAttempts(pinRetries, pukRetries)
        "Retry counts set. PIN and PUK were reset to their defaults (123456 / 12345678)."
    }

    fun changeManagementKey(currentHex: String, type: ManagementKeyType, newHex: String?, requireTouch: Boolean) {
        core.run("change the management key") { device ->
            val newKey = newHex?.takeIf { it.isNotBlank() }?.let(Encoding::fromHex)
                ?: Encoding.randomBytes(type.keyLength)
            if (newKey.size != type.keyLength) {
                throw UserFacingException("A ${type.name} key must be ${type.keyLength} bytes (${type.keyLength * 2} hex digits)")
            }
            core.smartCard(device) { conn ->
                val s = PivSession(conn)
                s.auth(currentHex)
                s.setManagementKey(type, newKey, requireTouch)
            }
            core.showDialog(
                InfoDialog(
                    "Management key changed",
                    "New ${type.name} management key:\n${Encoding.toHex(newKey)}\n\n" +
                        "Store it safely. You need it to change certificates and keys.",
                    Encoding.toHex(newKey),
                )
            )
        }
    }

    fun reset() {
        core.run("reset the PIV application") { device ->
            core.smartCard(device) { conn -> PivSession(conn).reset() }
            core.toast("PIV reset. PIN 123456, PUK 12345678, default management key.")
        }
    }

    private fun pinOp(name: String, op: (PivSession) -> String) {
        core.run(name) { device ->
            val msg = core.smartCard(device) { conn ->
                try {
                    op(PivSession(conn))
                } catch (e: com.yubico.yubikit.core.application.InvalidPinException) {
                    throw UserFacingException("Wrong PIN/PUK. ${e.attemptsRemaining} attempt(s) remaining.")
                }
            }
            core.toast(msg)
        }
    }

    companion object {
        const val DEFAULT_MGMT_KEY = "010203040506070801020304050607080102030405060708"

        val MAIN_SLOTS = listOf(Slot.AUTHENTICATION, Slot.SIGNATURE, Slot.KEY_MANAGEMENT, Slot.CARD_AUTH)
        val RETIRED_SLOTS = Slot.values().filter { it.name.startsWith("RETIRED") }

        fun slotHex(slot: Slot) = "%02X".format(slot.value)

        fun slotName(slot: Slot) = when (slot) {
            Slot.AUTHENTICATION -> "Authentication (9A)"
            Slot.SIGNATURE -> "Digital signature (9C)"
            Slot.KEY_MANAGEMENT -> "Key management (9D)"
            Slot.CARD_AUTH -> "Card authentication (9E)"
            else -> "Retired ${slot.name.removePrefix("RETIRED")} (${slotHex(slot)})"
        }

        fun pem(type: String, der: ByteArray): ByteArray {
            val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
            return "-----BEGIN $type-----\n$b64\n-----END $type-----\n".toByteArray()
        }

        fun fingerprint(cert: X509Certificate): String =
            MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString(":") { "%02X".format(it) }
    }
}
