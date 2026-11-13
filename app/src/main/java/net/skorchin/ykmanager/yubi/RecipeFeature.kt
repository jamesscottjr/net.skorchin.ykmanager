package net.skorchin.ykmanager.yubi

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.oath.OathSession
import com.yubico.yubikit.openpgp.OpenPgpSession
import com.yubico.yubikit.piv.ManagementKeyType
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.yubiotp.Slot
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// ----------------------------------------------------------------------
// Model
// ----------------------------------------------------------------------

/** One OTP slot write inside a recipe. [kind] is the name of ui.Prog. */
data class SlotStep(
    val kind: String,
    val program: SlotProgram,
    val appendEnter: Boolean,
    val newAccessCodeHex: String,
    /** Output settings captured when the step was added; older recipes get the defaults. */
    val output: OtpOutputSettings = OtpOutputSettings(),
) {
    val summary: String
        get() = baseSummary + output.copy(appendEnter = appendEnter).changesFromDefault()
            .takeIf { it.isNotEmpty() && program !is SlotProgram.ChallengeResponse }
            ?.joinToString(prefix = " · ").orEmpty()

    private val baseSummary: String
        get() = when (val p = program) {
            is SlotProgram.YubicoOtp -> "Yubico OTP, public ID " + when {
                p.useSerialAsPublicId -> "from serial"
                p.publicIdModhex != null -> p.publicIdModhex
                else -> "random"
            } + if (p.keyHex == null) ", random secret" else ", fixed secret"
            is SlotProgram.Hotp -> "OATH-HOTP, ${if (p.digits8) 8 else 6} digits"
            is SlotProgram.StaticPassword ->
                if (p.password != null) "Static password (same on every key)"
                else "Static password, random ${p.generateLength} chars" + if (p.modhexOnly) " (modhex)" else ""
            is SlotProgram.ChallengeResponse ->
                "HMAC-SHA1 challenge-response, " + (if (p.secretHex == null) "random secret" else "fixed secret") +
                    if (p.requireTouch) ", touch" else ""
        }

    fun toJson(): JSONObject = JSONObject().apply {
        put("kind", kind); put("enter", appendEnter); put("acc", newAccessCodeHex)
        put("out", output.toJson())
        when (val p = program) {
            is SlotProgram.YubicoOtp -> { put("t", "otp"); put("pub", p.publicIdModhex); put("serial", p.useSerialAsPublicId); put("priv", p.privateIdHex); put("key", p.keyHex) }
            is SlotProgram.Hotp -> { put("t", "hotp"); put("sec", p.secretBase32); put("d8", p.digits8); put("ctr", p.initialCounter) }
            is SlotProgram.StaticPassword -> { put("t", "static"); put("pw", p.password); put("len", p.generateLength); put("modhex", p.modhexOnly) }
            is SlotProgram.ChallengeResponse -> { put("t", "cr"); put("sec", p.secretHex); put("touch", p.requireTouch) }
        }
    }

    companion object {
        fun fromJson(o: JSONObject): SlotStep {
            fun str(k: String): String? = if (o.isNull(k)) null else o.optString(k)
            val program: SlotProgram = when (o.optString("t")) {
                "otp" -> SlotProgram.YubicoOtp(str("pub"), o.optBoolean("serial"), str("priv"), str("key"))
                "hotp" -> SlotProgram.Hotp(o.optString("sec"), o.optBoolean("d8"), o.optInt("ctr"))
                "static" -> SlotProgram.StaticPassword(str("pw"), o.optInt("len", 38), o.optBoolean("modhex"))
                else -> SlotProgram.ChallengeResponse(str("sec"), o.optBoolean("touch"))
            }
            return SlotStep(o.optString("kind"), program, o.optBoolean("enter", true), o.optString("acc"),
                OtpOutputSettings.fromJson(o.optJSONObject("out")))
        }
    }
}

/**
 * A reusable set of settings that can be applied to many keys. Every part is
 * optional; parts a key does not support are skipped when applying.
 */
data class Recipe(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val notes: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    // Device configuration (Applications screen)
    val usbCaps: Int? = null,
    val nfcCaps: Int? = null,
    val chalrespTimeout: Int? = null,
    val autoEjectTimeout: Int? = null,
    val lockCodeHex: String = "",
    // OTP slots
    val slot1: SlotStep? = null,
    val slot2: SlotStep? = null,
    val deleteSlot1: Boolean = false,
    val deleteSlot2: Boolean = false,
    val currentAccessCodeHex: String = "",
    // Credentials, applied from factory defaults
    val fidoPin: String? = null,
    val oathPassword: String? = null,
    val pivPin: String? = null,
    val pivPuk: String? = null,
    /** null = don't touch; "" = random per key; otherwise hex. */
    val pivMgmtKeyHex: String? = null,
    val pgpUserPin: String? = null,
    val pgpAdminPin: String? = null,
) {
    val hasConfig get() = usbCaps != null || nfcCaps != null || chalrespTimeout != null || autoEjectTimeout != null
    val hasSlots get() = slot1 != null || slot2 != null || deleteSlot1 || deleteSlot2
    val hasPiv get() = pivPin != null || pivPuk != null || pivMgmtKeyHex != null
    val hasPgp get() = pgpUserPin != null || pgpAdminPin != null
    val stepCount: Int
        get() = (if (hasConfig) 1 else 0) + listOfNotNull(slot1, slot2).size + (if (deleteSlot1) 1 else 0) +
            (if (deleteSlot2) 1 else 0) + (if (fidoPin != null) 1 else 0) + (if (oathPassword != null) 1 else 0) +
            (if (pivPin != null) 1 else 0) + (if (pivPuk != null) 1 else 0) + (if (pivMgmtKeyHex != null) 1 else 0) +
            (if (pgpUserPin != null) 1 else 0) + (if (pgpAdminPin != null) 1 else 0)

    /** True if the recipe stores anything secret (so the user knows what's on the phone). */
    val containsSecrets: Boolean
        get() = fidoPin != null || oathPassword != null || pivPin != null || pivPuk != null ||
            !pivMgmtKeyHex.isNullOrEmpty() || pgpUserPin != null || pgpAdminPin != null || lockCodeHex.isNotBlank() ||
            listOfNotNull(slot1, slot2).any {
                when (val p = it.program) {
                    is SlotProgram.YubicoOtp -> p.keyHex != null
                    is SlotProgram.Hotp -> true
                    is SlotProgram.StaticPassword -> p.password != null
                    is SlotProgram.ChallengeResponse -> p.secretHex != null
                }
            }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("notes", notes); put("created", createdAt)
        put("usb", usbCaps); put("nfc", nfcCaps); put("cr", chalrespTimeout); put("ae", autoEjectTimeout); put("lock", lockCodeHex)
        put("slot1", slot1?.toJson()); put("slot2", slot2?.toJson())
        put("del1", deleteSlot1); put("del2", deleteSlot2); put("curacc", currentAccessCodeHex)
        put("fido", fidoPin); put("oath", oathPassword)
        put("pivpin", pivPin); put("pivpuk", pivPuk); put("pivmk", pivMgmtKeyHex)
        put("pgpuser", pgpUserPin); put("pgpadmin", pgpAdminPin)
    }

    companion object {
        fun fromJson(o: JSONObject): Recipe {
            fun str(k: String): String? = if (o.isNull(k)) null else o.optString(k)
            fun int(k: String): Int? = if (o.isNull(k)) null else o.optInt(k)
            return Recipe(
                id = o.optString("id"), name = o.optString("name"), notes = o.optString("notes"),
                createdAt = o.optLong("created"),
                usbCaps = int("usb"), nfcCaps = int("nfc"), chalrespTimeout = int("cr"), autoEjectTimeout = int("ae"),
                lockCodeHex = o.optString("lock"),
                slot1 = o.optJSONObject("slot1")?.let(SlotStep::fromJson),
                slot2 = o.optJSONObject("slot2")?.let(SlotStep::fromJson),
                deleteSlot1 = o.optBoolean("del1"), deleteSlot2 = o.optBoolean("del2"),
                currentAccessCodeHex = o.optString("curacc"),
                fidoPin = str("fido"), oathPassword = str("oath"),
                pivPin = str("pivpin"), pivPuk = str("pivpuk"), pivMgmtKeyHex = str("pivmk"),
                pgpUserPin = str("pgpuser"), pgpAdminPin = str("pgpadmin"),
            )
        }
    }
}

// ----------------------------------------------------------------------
// Encrypted storage (AES-GCM with a key held in the Android Keystore)
// ----------------------------------------------------------------------

class RecipeStore(context: Context) {
    private val file = File(context.filesDir, "recipes.bin")

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    fun load(): List<Recipe> {
        if (!file.exists()) return emptyList()
        return runCatching {
            val blob = file.readBytes()
            val iv = blob.copyOfRange(0, 12)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            val json = String(cipher.doFinal(blob.copyOfRange(12, blob.size)), Charsets.UTF_8)
            val arr = JSONArray(json)
            (0 until arr.length()).map { Recipe.fromJson(arr.getJSONObject(it)) }
        }.getOrDefault(emptyList())
    }

    fun save(recipes: List<Recipe>) {
        val arr = JSONArray().apply { recipes.forEach { put(it.toJson()) } }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val enc = cipher.doFinal(arr.toString().toByteArray(Charsets.UTF_8))
        file.writeBytes(cipher.iv + enc)
    }

    companion object { private const val ALIAS = "ykmanager_recipes" }
}

// ----------------------------------------------------------------------
// Preview and apply
// ----------------------------------------------------------------------

enum class StepStatus { APPLY, SKIP, WARN }

data class PreviewItem(val title: String, val current: String, val planned: String, val status: StepStatus, val note: String? = null)

data class RecipePreview(val recipeId: String, val serial: Int?, val keyName: String, val items: List<PreviewItem>) {
    val applicable get() = items.count { it.status != StepStatus.SKIP }
}

data class StepResult(val title: String, val ok: Boolean, val message: String, val secrets: String? = null)

data class ApplyResult(val recipeName: String, val serial: Int?, val keyName: String, val at: Long, val steps: List<StepResult>) {
    val failures get() = steps.count { !it.ok }
}

class RecipeFeature(
    private val core: YubiKeyCore,
    private val otp: OtpFeature,
    private val mgmt: ManagementFeature,
    context: Context,
) {
    private val store = RecipeStore(context)

    private val _recipes = MutableStateFlow(store.load())
    val recipes: StateFlow<List<Recipe>> = _recipes.asStateFlow()

    private val _preview = MutableStateFlow<RecipePreview?>(null)
    val preview: StateFlow<RecipePreview?> = _preview.asStateFlow()

    private val _lastResult = MutableStateFlow<ApplyResult?>(null)
    val lastResult: StateFlow<ApplyResult?> = _lastResult.asStateFlow()

    /** Everything applied in this app session, for the batch log export. */
    private val _log = MutableStateFlow<List<ApplyResult>>(emptyList())
    val log: StateFlow<List<ApplyResult>> = _log.asStateFlow()

    fun save(recipe: Recipe) {
        val list = _recipes.value.filter { it.id != recipe.id } + recipe
        _recipes.value = list.sortedBy { it.name.lowercase() }
        runCatching { store.save(_recipes.value) }.onFailure { core.error("Could not save recipe: ${YubiKeyCore.describe(it)}") }
    }

    fun delete(recipe: Recipe) {
        _recipes.value = _recipes.value.filter { it.id != recipe.id }
        runCatching { store.save(_recipes.value) }
        if (_preview.value?.recipeId == recipe.id) _preview.value = null
    }

    fun clearPreview() { _preview.value = null }
    fun clearResult() { _lastResult.value = null }

    // ---------------------------------------------------------------- preview

    /** Read the connected key and work out what the recipe would change on it. */
    fun preview(recipe: Recipe) {
        _preview.value = null
        core.run("preview the recipe", refresh = false) { device ->
            val info = core.keyInfo.value ?: throw UserFacingException("Key information is not available yet")
            _preview.value = buildPreview(device, recipe, info)
        }
    }

    private suspend fun buildPreview(device: YubiKeyDevice, r: Recipe, k: KeyInfo): RecipePreview {
        val items = mutableListOf<PreviewItem>()
        val d = k.deviceInfo

        // Device configuration
        if (r.hasConfig) {
            when {
                k.hasDeviceConfig && d != null -> {
                    val usbNow = d.config.getEnabledCapabilities(Transport.USB) ?: 0
                    val nfcNow = d.config.getEnabledCapabilities(Transport.NFC) ?: 0
                    val usbSup = d.getSupportedCapabilities(Transport.USB)
                    val nfcSup = d.getSupportedCapabilities(Transport.NFC)
                    r.usbCaps?.let { want ->
                        val eff = want and usbSup
                        items += PreviewItem("USB applications", capList(usbNow, usbSup), capList(eff, usbSup),
                            if (eff == usbNow) StepStatus.SKIP else StepStatus.APPLY,
                            if (eff == usbNow) "Already as configured" else if (eff != want) "Applications this key lacks are ignored" else null)
                    }
                    r.nfcCaps?.let { want ->
                        if (!d.hasTransport(Transport.NFC)) {
                            items += PreviewItem("NFC applications", "no NFC on this key", "-", StepStatus.SKIP, "Key has no NFC")
                        } else {
                            val eff = want and nfcSup
                            items += PreviewItem("NFC applications", capList(nfcNow, nfcSup), capList(eff, nfcSup),
                                if (eff == nfcNow) StepStatus.SKIP else StepStatus.APPLY)
                        }
                    }
                    r.chalrespTimeout?.let {
                        val now = d.config.challengeResponseTimeout?.toInt()?.and(0xff)
                        items += PreviewItem("Challenge-response timeout", "${now ?: "?"} s", "$it s", if (now == it) StepStatus.SKIP else StepStatus.APPLY)
                    }
                    r.autoEjectTimeout?.let {
                        val now = d.config.autoEjectTimeout?.toInt()?.and(0xffff)
                        items += PreviewItem("Auto-eject timeout", "${now ?: "?"} s", "$it s", if (now == it) StepStatus.SKIP else StepStatus.APPLY)
                    }
                    if (d.isLocked && r.lockCodeHex.isBlank() && items.any { it.status == StepStatus.APPLY }) {
                        items += PreviewItem("Configuration lock", "locked", "-", StepStatus.WARN, "This key has a lock code and the recipe has none; the configuration step will fail")
                    }
                }
                k.hasLegacyMode -> {
                    items += PreviewItem("USB interfaces (mode)", "firmware ${k.version}", r.usbCaps?.let { "mode from recipe applications" } ?: "timeouts only",
                        StepStatus.APPLY, "YubiKey 4 / NEO: applied as a USB mode; NFC and lock code settings are ignored")
                }
                else -> items += PreviewItem("Device configuration", "-", "-", StepStatus.SKIP, "Not configurable on this key")
            }
        }

        // OTP slots
        val slotViews = otp.slots.value
        fun slotNow(slot: Slot): String {
            val v = slotViews.firstOrNull { it.slot == slot }
            return when (v?.configured) {
                null -> "unknown"
                false -> "empty"
                true -> v.type?.label ?: "programmed (type unknown)"
            }
        }
        if (r.hasSlots) {
            if (!k.supports(Capability.OTP)) {
                items += PreviewItem("OTP slots", "-", "-", StepStatus.SKIP, "This key has no OTP application")
            } else {
                val otpOn = d?.config?.getEnabledCapabilities(k.transport)?.let { it and Capability.OTP.bit != 0 } ?: true
                listOf(Slot.ONE to (r.slot1 to r.deleteSlot1), Slot.TWO to (r.slot2 to r.deleteSlot2)).forEach { (slot, pair) ->
                    val (step, del) = pair
                    val now = slotNow(slot)
                    when {
                        step != null -> items += PreviewItem("Slot ${slot.num}", now, step.summary,
                            if (otpOn) StepStatus.APPLY else StepStatus.WARN,
                            if (!otpOn) "OTP is disabled over ${k.transport}; enable it first" else if (now != "empty" && now != "unknown") "Existing credential will be overwritten" else null)
                        del -> items += PreviewItem("Slot ${slot.num}", now, "delete",
                            if (now == "empty") StepStatus.SKIP else StepStatus.APPLY, if (now == "empty") "Already empty" else null)
                    }
                }
            }
        }

        // FIDO2 PIN
        r.fidoPin?.let { pin ->
            if (!k.supports(Capability.FIDO2)) {
                items += PreviewItem("FIDO2 PIN", "-", "-", StepStatus.SKIP, "No FIDO2 on this key")
            } else {
                val pinSet = runCatching { core.fido(device) { it.cachedInfo.options["clientPin"] == true } }.getOrNull()
                items += when (pinSet) {
                    true -> PreviewItem("FIDO2 PIN", "already set", "-", StepStatus.SKIP, "A PIN exists; recipes only set a PIN on keys without one")
                    false -> PreviewItem("FIDO2 PIN", "not set", "set (${pin.length} chars)", StepStatus.APPLY)
                    null -> PreviewItem("FIDO2 PIN", "unreadable", "set", StepStatus.WARN, "Could not read FIDO state (interface disabled?)")
                }
            }
        }

        // OATH password
        r.oathPassword?.let {
            if (!k.supports(Capability.OATH)) {
                items += PreviewItem("OATH password", "-", "-", StepStatus.SKIP, "No OATH on this key")
            } else {
                val locked = runCatching { core.smartCard(device) { OathSession(it).isAccessKeySet } }.getOrNull()
                items += when (locked) {
                    true -> PreviewItem("OATH password", "already set", "-", StepStatus.SKIP, "Recipes only set a password where none exists")
                    false -> PreviewItem("OATH password", "none", "set", StepStatus.APPLY)
                    null -> PreviewItem("OATH password", "unreadable", "set", StepStatus.WARN, "Could not open OATH (interface disabled?)")
                }
            }
        }

        // PIV
        if (r.hasPiv) {
            if (!k.supports(Capability.PIV)) {
                items += PreviewItem("PIV", "-", "-", StepStatus.SKIP, "No PIV on this key")
            } else {
                val meta = runCatching {
                    core.smartCard(device) { c ->
                        val s = PivSession(c)
                        if (s.supports(PivSession.FEATURE_METADATA)) {
                            Triple(s.pinMetadata.isDefaultValue, s.pukMetadata.isDefaultValue, s.managementKeyMetadata.isDefaultValue)
                        } else null
                    }
                }.getOrNull()
                fun item(title: String, isDefault: Boolean?, planned: String) = when (isDefault) {
                    true -> PreviewItem(title, "factory default", planned, StepStatus.APPLY)
                    false -> PreviewItem(title, "already changed", "-", StepStatus.SKIP, "Recipes only change factory-default credentials")
                    null -> PreviewItem(title, "unknown (firmware < 5.3)", planned, StepStatus.WARN, "Will be attempted from the factory default")
                }
                r.pivPin?.let { items += item("PIV PIN", meta?.first, "set") }
                r.pivPuk?.let { items += item("PIV PUK", meta?.second, "set") }
                r.pivMgmtKeyHex?.let { items += item("PIV management key", meta?.third, if (it.isEmpty()) "random per key" else "set") }
            }
        }

        // OpenPGP
        if (r.hasPgp) {
            if (!k.supports(Capability.OPENPGP)) {
                items += PreviewItem("OpenPGP", "-", "-", StepStatus.SKIP, "No OpenPGP on this key")
            } else {
                r.pgpUserPin?.let { items += PreviewItem("OpenPGP user PIN", "assumed default 123456", "set", StepStatus.WARN, "Fails if the PIN was already changed") }
                r.pgpAdminPin?.let { items += PreviewItem("OpenPGP admin PIN", "assumed default 12345678", "set", StepStatus.WARN, "Fails if the PIN was already changed") }
            }
        }

        return RecipePreview(r.id, k.serial, k.name, items)
    }

    private fun capList(bits: Int, supported: Int): String {
        val names = Capability.entries.filter { supported and it.bit != 0 }.map { c ->
            capShort(c) + if (bits and c.bit != 0) "" else " (off)"
        }
        return names.joinToString(", ")
    }

    private fun capShort(c: Capability) = when (c) {
        Capability.OTP -> "OTP"; Capability.U2F -> "U2F"; Capability.FIDO2 -> "FIDO2"; Capability.OATH -> "OATH"
        Capability.PIV -> "PIV"; Capability.OPENPGP -> "OpenPGP"; Capability.HSMAUTH -> "HSMAuth"; Capability.FIDO_CCID -> "FIDO-CCID"
    }

    // ---------------------------------------------------------------- apply

    /** Apply the recipe to the connected key, step by step; failures do not stop later steps. */
    fun apply(recipe: Recipe) {
        core.run("apply the recipe") { device ->
            val info = core.keyInfo.value ?: throw UserFacingException("Key information is not available yet")
            val serial = info.serial
            val steps = mutableListOf<StepResult>()
            suspend fun step(title: String, block: suspend () -> Pair<String, String?>) {
                try {
                    val (msg, secrets) = block()
                    steps += StepResult(title, true, msg, secrets)
                } catch (e: UserFacingException) {
                    steps += StepResult(title, false, e.message ?: "failed")
                } catch (e: Throwable) {
                    steps += StepResult(title, false, YubiKeyCore.describe(e))
                }
            }

            // 1. OTP slots (before any configuration change that could disable OTP)
            if (recipe.hasSlots && info.supports(Capability.OTP)) {
                listOf(Slot.ONE to (recipe.slot1 to recipe.deleteSlot1), Slot.TWO to (recipe.slot2 to recipe.deleteSlot2)).forEach { (slot, pair) ->
                    val (s, del) = pair
                    if (s != null) step("Slot ${slot.num}: ${s.summary}") {
                        val r = otp.programOn(device, slot, s.program, SlotWriteOptions(s.appendEnter, recipe.currentAccessCodeHex, s.newAccessCodeHex, s.output), serial)
                        ("Programmed as ${r.type.label}" + r.details.entries.joinToString("") { "; ${it.key} ${it.value}" }) to r.secrets
                    } else if (del) step("Slot ${slot.num}: delete") {
                        otp.deleteOn(device, slot, recipe.currentAccessCodeHex, serial)
                        "Deleted" to null
                    }
                }
            }

            // 2. FIDO2 PIN
            recipe.fidoPin?.let { pin ->
                if (info.supports(Capability.FIDO2)) step("FIDO2 PIN") {
                    core.fido(device) { s ->
                        val i = s.cachedInfo
                        if (i.options["clientPin"] == true) throw UserFacingException("A PIN is already set; skipped")
                        if (pin.length < i.minPinLength) throw UserFacingException("PIN must be at least ${i.minPinLength} characters")
                        val proto = if (i.pinUvAuthProtocols.contains(2)) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()
                        ClientPin(s, proto).setPin(pin.toCharArray())
                    }
                    "PIN set" to null
                }
            }

            // 3. OATH password
            recipe.oathPassword?.let { pw ->
                if (info.supports(Capability.OATH)) step("OATH password") {
                    core.smartCard(device) { c ->
                        val s = OathSession(c)
                        if (s.isAccessKeySet) throw UserFacingException("A password is already set; skipped")
                        s.setAccessKey(s.deriveAccessKey(pw.toCharArray()))
                    }
                    "Password set" to null
                }
            }

            // 4. PIV credentials
            if (recipe.hasPiv && info.supports(Capability.PIV)) {
                recipe.pivMgmtKeyHex?.let { hex ->
                    step("PIV management key") {
                        var generated: String? = null
                        core.smartCard(device) { c ->
                            val s = PivSession(c)
                            val type = if (s.supports(PivSession.FEATURE_METADATA)) {
                                val m = s.managementKeyMetadata
                                if (!m.isDefaultValue) throw UserFacingException("Management key already changed; skipped")
                                if (s.supports(PivSession.FEATURE_AES_KEY)) ManagementKeyType.AES192 else m.keyType
                            } else ManagementKeyType.TDES
                            val newKey = if (hex.isEmpty()) Encoding.randomBytes(type.keyLength).also { generated = Encoding.toHex(it) }
                                else Encoding.fromHex(hex)
                            if (newKey.size != type.keyLength) throw UserFacingException("Key must be ${type.keyLength} bytes for ${type.name}")
                            s.authenticate(Encoding.fromHex(PivFeature.DEFAULT_MGMT_KEY))
                            s.setManagementKey(type, newKey, false)
                        }
                        (if (generated != null) "Random management key set (saved to batch log)" else "Management key set") to generated?.let { "PIV management key: $it" }
                    }
                }
                recipe.pivPin?.let { pin ->
                    step("PIV PIN") {
                        core.smartCard(device) { c ->
                            val s = PivSession(c)
                            if (s.supports(PivSession.FEATURE_METADATA) && !s.pinMetadata.isDefaultValue) throw UserFacingException("PIN already changed; skipped")
                            s.changePin("123456".toCharArray(), pin.toCharArray())
                        }
                        "PIN set" to null
                    }
                }
                recipe.pivPuk?.let { puk ->
                    step("PIV PUK") {
                        core.smartCard(device) { c ->
                            val s = PivSession(c)
                            if (s.supports(PivSession.FEATURE_METADATA) && !s.pukMetadata.isDefaultValue) throw UserFacingException("PUK already changed; skipped")
                            s.changePuk("12345678".toCharArray(), puk.toCharArray())
                        }
                        "PUK set" to null
                    }
                }
            }

            // 5. OpenPGP PINs
            if (recipe.hasPgp && info.supports(Capability.OPENPGP)) {
                recipe.pgpUserPin?.let { pin ->
                    step("OpenPGP user PIN") {
                        core.smartCard(device) { c -> OpenPgpFeature.openSession(c).changeUserPin("123456".toCharArray(), pin.toCharArray()) }
                        "User PIN set" to null
                    }
                }
                recipe.pgpAdminPin?.let { pin ->
                    step("OpenPGP admin PIN") {
                        core.smartCard(device) { c -> OpenPgpFeature.openSession(c).changeAdminPin("12345678".toCharArray(), pin.toCharArray()) }
                        "Admin PIN set" to null
                    }
                }
            }

            // 6. Device configuration last: it may reboot the key / disable interfaces used above
            if (recipe.hasConfig) {
                step("Device configuration") {
                    val msg = mgmt.applyConfigOn(device, info, recipe.usbCaps, recipe.nfcCaps, recipe.chalrespTimeout, recipe.autoEjectTimeout, recipe.lockCodeHex)
                    msg to null
                }
            }

            val result = ApplyResult(recipe.name, serial, info.name, System.currentTimeMillis(), steps)
            _lastResult.value = result
            _log.value = _log.value + result
            _preview.value = null
            if (steps.isEmpty()) core.toast("Nothing in this recipe applies to this key")
        }
    }

    // ---------------------------------------------------------------- batch log

    fun exportLog() {
        val sb = StringBuilder("time,recipe,serial,key,step,result,message,secrets\n")
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        _log.value.forEach { r ->
            r.steps.forEach { s ->
                sb.append(listOf(fmt.format(Date(r.at)), r.recipeName, r.serial?.toString() ?: "", r.keyName, s.title,
                    if (s.ok) "ok" else "failed", s.message, s.secrets ?: "").joinToString(",") { csv(it) }).append('\n')
            }
        }
        core.offerExport(ExportFile("ykmanager-batch-${SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date())}.csv", "text/csv", sb.toString().toByteArray()))
    }

    fun clearLog() { _log.value = emptyList() }

    private fun csv(v: String) = "\"" + v.replace("\"", "\"\"") + "\""
}
