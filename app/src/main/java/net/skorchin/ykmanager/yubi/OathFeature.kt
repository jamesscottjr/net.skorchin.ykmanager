package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.core.Version
import com.yubico.yubikit.oath.AccessKey
import com.yubico.yubikit.oath.Code
import com.yubico.yubikit.oath.Credential
import com.yubico.yubikit.oath.CredentialData
import com.yubico.yubikit.oath.HashAlgorithm
import com.yubico.yubikit.oath.OathSession
import com.yubico.yubikit.oath.OathType
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.URI
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class OathEntry(val credential: Credential, val code: Code?) {
    val issuer: String? get() = credential.issuer
    val name: String get() = credential.accountName
    val isTotp: Boolean get() = credential.oathType == OathType.TOTP
}

data class OathState(
    val loaded: Boolean = false,
    val version: Version? = null,
    val deviceId: String? = null,
    val hasPassword: Boolean = false,
    val locked: Boolean = false,
    val entries: List<OathEntry> = emptyList(),
    val readAt: Long = 0,
)

/** Parameters for a new account entered manually. */
data class NewAccount(
    val issuer: String,
    val name: String,
    val secretBase32: String,
    val type: OathType,
    val algorithm: HashAlgorithm,
    val digits: Int,
    val period: Int,
    val requireTouch: Boolean,
)

class OathFeature(private val core: YubiKeyCore) {

    private val _state = MutableStateFlow(OathState())
    val state: StateFlow<OathState> = _state.asStateFlow()

    /** Derived access keys remembered for this app session, keyed by device ID. */
    private val accessKeys = mutableMapOf<String, ByteArray>()

    fun clear() {
        _state.value = OathState()
        accessKeys.clear()
    }

    private fun accessKey(key: ByteArray) = AccessKey { challenge ->
        Mac.getInstance("HmacSHA1").run {
            init(SecretKeySpec(key, "HmacSHA1"))
            doFinal(challenge)
        }
    }

    /** Opens an OATH session, unlocking it with a remembered key when possible. */
    private suspend fun <T> withOath(
        device: com.yubico.yubikit.core.YubiKeyDevice,
        requireUnlocked: Boolean = true,
        block: (OathSession) -> T,
    ): T = core.smartCard(device) { conn ->
        val s = OathSession(conn)
        if (s.isLocked) {
            val k = accessKeys[s.deviceId]
            if (k == null || !s.unlock(accessKey(k))) {
                accessKeys.remove(s.deviceId)
                if (requireUnlocked) throw UserFacingException("The OATH application is password protected. Unlock it first.")
            }
        }
        block(s)
    }

    suspend fun refresh(device: com.yubico.yubikit.core.YubiKeyDevice) {
        _state.value = core.smartCard(device) { conn ->
            val s = OathSession(conn)
            var locked = s.isLocked
            if (locked) {
                accessKeys[s.deviceId]?.let { k -> if (s.unlock(accessKey(k))) locked = false }
            }
            val entries = if (locked) emptyList() else s.calculateCodes()
                .map { (cred, code) -> OathEntry(cred, code) }
                .filter { !it.name.startsWith("_hidden:") }
                .sortedWith(compareBy({ (it.issuer ?: it.name).lowercase() }, { it.name.lowercase() }))
            OathState(
                loaded = true,
                version = s.version,
                deviceId = s.deviceId,
                hasPassword = s.isAccessKeySet,
                locked = locked,
                entries = entries,
                readAt = System.currentTimeMillis(),
            )
        }
    }

    fun unlock(password: CharArray, remember: Boolean) {
        core.run("unlock accounts") { device ->
            core.smartCard(device) { conn ->
                val s = OathSession(conn)
                val key = s.deriveAccessKey(password)
                if (!s.unlock(accessKey(key))) throw UserFacingException("Wrong password")
                accessKeys[s.deviceId] = key
            }
            if (!remember) core.toast("Unlocked")
        }
    }

    fun calculate(entry: OathEntry) {
        core.run("calculate a code") { device ->
            if (entry.credential.isTouchRequired) core.showTouchPrompt(true)
            val code = withOath(device) { it.calculateCode(entry.credential) }
            core.showTouchPrompt(false)
            _state.value = _state.value.copy(entries = _state.value.entries.map {
                if (it.credential == entry.credential) it.copy(code = code) else it
            })
        }
    }

    fun add(acc: NewAccount) {
        core.run("add the account") { device ->
            val secret = runCatching { com.yubico.yubikit.oath.Base32.decode(acc.secretBase32.uppercase().replace(" ", "").trimEnd('=')) }
                .getOrElse { throw UserFacingException("The secret is not valid base32") }
            val data = CredentialData(
                acc.name, acc.type, acc.algorithm, secret, acc.digits, acc.period, 0,
                acc.issuer.ifBlank { null },
            )
            withOath(device) { it.putCredential(data, acc.requireTouch) }
            core.toast("Account added")
        }
    }

    fun addFromUri(uri: String, requireTouch: Boolean) {
        core.run("add the account") { device ->
            val data = runCatching { CredentialData.parseUri(URI(uri.trim())) }
                .getOrElse { throw UserFacingException("Not a valid otpauth:// link: ${it.message}") }
            withOath(device) { it.putCredential(data, requireTouch) }
            core.toast("Added ${data.issuer?.let { "$it: " } ?: ""}${data.accountName}")
        }
    }

    /** Add several accounts (for example from a Google Authenticator export) in one go. */
    fun addMany(uris: List<String>, requireTouch: Boolean) {
        core.run("add the accounts") { device ->
            val parsed = uris.map { uri ->
                runCatching { CredentialData.parseUri(URI(uri.trim())) }
                    .getOrElse { throw UserFacingException("Not a valid otpauth:// link: ${it.message}") }
            }
            val failed = mutableListOf<String>()
            withOath(device) { s ->
                for (d in parsed) {
                    runCatching { s.putCredential(d, requireTouch) }
                        .onFailure { failed += "${d.issuer?.let { "$it: " } ?: ""}${d.accountName} (${it.message})" }
                }
            }
            if (failed.isEmpty()) core.toast("Added ${parsed.size} accounts")
            else throw UserFacingException("Added ${parsed.size - failed.size} of ${parsed.size} accounts. Failed: ${failed.joinToString("; ")}")
        }
    }

    fun rename(entry: OathEntry, issuer: String, name: String) {
        core.run("rename the account") { device ->
            withOath(device) { it.renameCredential(entry.credential, name, issuer.ifBlank { null }) }
            core.toast("Account renamed")
        }
    }

    fun delete(entry: OathEntry) {
        core.run("delete the account") { device ->
            withOath(device) { it.deleteCredential(entry.credential) }
            core.toast("Account deleted")
        }
    }

    fun setPassword(current: CharArray?, new: CharArray) {
        core.run("set the password") { device ->
            core.smartCard(device) { conn ->
                val s = OathSession(conn)
                if (s.isLocked) {
                    val ok = current?.let { s.unlock(accessKey(s.deriveAccessKey(it))) }
                        ?: accessKeys[s.deviceId]?.let { s.unlock(accessKey(it)) } ?: false
                    if (!ok) throw UserFacingException("Current password is wrong")
                }
                val key = s.deriveAccessKey(new)
                s.setAccessKey(key)
                accessKeys[s.deviceId] = key
            }
            core.toast("Password set")
        }
    }

    fun removePassword(current: CharArray) {
        core.run("remove the password") { device ->
            core.smartCard(device) { conn ->
                val s = OathSession(conn)
                if (s.isLocked && !s.unlock(accessKey(s.deriveAccessKey(current)))) {
                    throw UserFacingException("Wrong password")
                }
                s.deleteAccessKey()
                accessKeys.remove(s.deviceId)
            }
            core.toast("Password removed")
        }
    }

    fun forgetPassword() {
        _state.value.deviceId?.let { accessKeys.remove(it) }
        _state.value = _state.value.copy(locked = _state.value.hasPassword, entries = emptyList())
    }

    fun reset() {
        core.run("reset the OATH application") { device ->
            core.smartCard(device) { conn -> OathSession(conn).reset() }
            accessKeys.clear()
            core.toast("OATH application reset. All accounts were deleted.")
        }
    }
}
