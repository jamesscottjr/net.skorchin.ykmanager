package net.skorchin.ykmanager.yubi

import android.content.Context
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.yubiotp.HmacSha1SlotConfiguration
import com.yubico.yubikit.yubiotp.HotpSlotConfiguration
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.StaticPasswordSlotConfiguration
import com.yubico.yubikit.yubiotp.YubiOtpSession
import com.yubico.yubikit.yubiotp.YubiOtpSlotConfiguration
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import java.nio.ByteBuffer
import java.text.DateFormat
import java.util.Date

/** The type of credential stored in an OTP slot. */
enum class SlotType(val label: String) {
    YUBICO_OTP("Yubico OTP"),
    HOTP("OATH-HOTP"),
    STATIC("Static password"),
    CHALRESP("Challenge-response (HMAC-SHA1)"),
    CHALRESP_OTHER("Challenge-response (not HMAC-SHA1)"),
    KEYBOARD_UNKNOWN("Keyboard output (type not identified yet)"),
}

/** How we know a slot's type. */
enum class Evidence(val label: String) {
    HARDWARE("reported by the YubiKey"),
    OUTPUT("identified from the slot's output"),
    PROBE("verified by a challenge-response test"),
    HISTORY("recorded when programmed by this app"),
}

/** Everything the app knows about one slot. */
data class SlotView(
    val slot: Slot,
    val configured: Boolean?,          // null = firmware too old to tell
    val touchTriggered: Boolean?,      // null = unknown / not configured
    val type: SlotType?,
    val evidence: Evidence?,
    val details: List<Pair<String, String>>,
    val history: SlotHistory?,
)

/** Metadata (never secrets) about a slot this app programmed. */
data class SlotHistory(
    val type: SlotType,
    val programmedAt: Long,
    val details: Map<String, String>,
) {
    fun toJson(): String = JSONObject().apply {
        put("type", type.name)
        put("at", programmedAt)
        put("details", JSONObject(details as Map<*, *>))
    }.toString()

    companion object {

        fun fromJson(s: String): SlotHistory? = runCatching {
            val o = JSONObject(s)
            val d = o.getJSONObject("details")
            SlotHistory(
                SlotType.valueOf(o.getString("type")),
                o.getLong("at"),
                d.keys().asSequence().associateWith { d.getString(it) },
            )
        }.getOrNull()
    }
}

/** Result of identifying a slot from its output. */
data class Identification(val type: SlotType, val evidence: Evidence, val details: List<Pair<String, String>>)

/** User-entered parameters for programming a slot. */
sealed interface SlotProgram {
    data class YubicoOtp(
        val publicIdModhex: String?,   // null = random / serial-based
        val useSerialAsPublicId: Boolean,
        val privateIdHex: String?,     // null = random
        val keyHex: String?,           // null = random
    ) : SlotProgram

    data class Hotp(val secretBase32: String, val digits8: Boolean, val initialCounter: Int) : SlotProgram
    data class StaticPassword(
        val password: String?,       // null = generate randomly
        val generateLength: Int,
        val modhexOnly: Boolean = false,   // layout-independent characters only
    ) : SlotProgram
    data class ChallengeResponse(val secretHex: String?, val requireTouch: Boolean) : SlotProgram
}

/** Options shared by all slot writes. */
data class SlotWriteOptions(
    val appendEnter: Boolean = true,
    val currentAccessCodeHex: String = "",
    val newAccessCodeHex: String = "",
)

class SlotHistoryStore(context: Context) {
    private val prefs = context.getSharedPreferences("slot_history", Context.MODE_PRIVATE)

    private fun key(serial: Int?, slot: Slot) = "${serial ?: "unknown"}:${slot.name}"

    fun get(serial: Int?, slot: Slot): SlotHistory? =
        prefs.getString(key(serial, slot), null)?.let(SlotHistory::fromJson)

    fun put(serial: Int?, slot: Slot, h: SlotHistory?) {
        prefs.edit().apply {
            if (h == null) remove(key(serial, slot)) else putString(key(serial, slot), h.toJson())
        }.apply()
    }

    fun swap(serial: Int?) {
        val one = get(serial, Slot.ONE)
        val two = get(serial, Slot.TWO)
        put(serial, Slot.ONE, two)
        put(serial, Slot.TWO, one)
    }
}

class OtpFeature(private val core: YubiKeyCore, context: Context) {

    private val history = SlotHistoryStore(context)

    /** Identification results gathered this session, keyed by serial + slot. */
    private val identified = mutableMapOf<String, Identification>()

    private val _slots = MutableStateFlow<List<SlotView>>(emptyList())
    val slots: StateFlow<List<SlotView>> = _slots.asStateFlow()

    private val _ndefSlot = MutableStateFlow<String?>(null)

    private fun idKey(serial: Int?, slot: Slot) = "${serial ?: "unknown"}:${slot.name}"

    /** Rebuild slot views from the latest hardware state. */
    fun rebuild() {
        val info = core.keyInfo.value
        val state = info?.otpState
        val serial = info?.serial
        _slots.value = listOf(Slot.ONE, Slot.TWO).map { slot ->
            val configured = state?.let { runCatching { it.isConfigured(slot) }.getOrNull() }
            val touch = if (configured == true) {
                state.let { runCatching { it.isTouchTriggered(slot) }.getOrNull() }
            } else null
            val hist = if (configured == false) null else history.get(serial, slot)
            val ident = if (configured == false) null else identified[idKey(serial, slot)]

            // Pick the best available evidence.
            var type: SlotType? = null
            var evidence: Evidence? = null
            val details = mutableListOf<Pair<String, String>>()
            when {
                ident != null -> {
                    type = ident.type; evidence = ident.evidence; details += ident.details
                }
                hist != null && consistent(hist.type, touch) -> {
                    type = hist.type; evidence = Evidence.HISTORY
                }
                configured == true && touch == true -> {
                    type = SlotType.KEYBOARD_UNKNOWN; evidence = Evidence.HARDWARE
                }
                configured == true && touch == false -> {
                    type = SlotType.CHALRESP; evidence = Evidence.HARDWARE
                }
            }
            SlotView(slot, configured, touch, type, evidence, details, hist)
        }
    }

    private fun consistent(t: SlotType, touch: Boolean?): Boolean = when (touch) {
        null -> true
        true -> t != SlotType.CHALRESP && t != SlotType.CHALRESP_OTHER
        false -> t == SlotType.CHALRESP || t == SlotType.CHALRESP_OTHER
    }

    // ------------------------------------------------------------------
    // Identification
    // ------------------------------------------------------------------

    /** Classify text typed by the YubiKey when a slot is triggered. */
    fun identifyFromOutput(slot: Slot, rawOutput: String) {
        val ident = classifyOutput(rawOutput, core.keyInfo.value?.serial)
        if (ident == null) {
            core.error("Nothing was captured. Touch the YubiKey while the field is focused.")
            return
        }
        identified[idKey(core.keyInfo.value?.serial, slot)] = ident
        rebuild()
        core.toast("Slot ${slot.num}: ${ident.type.label}")
    }

    /** Over NFC, read the NDEF message, which carries the output of the NDEF slot. */
    fun identifyViaNdef(ndefSlot: Slot) {
        core.run("read the NFC (NDEF) output") { device ->
            val nfc = device as? NfcYubiKeyDevice
                ?: throw UserFacingException("Reading NDEF output requires an NFC tap.")
            val raw = nfc.readNdef()
            val text = parseNdefPayload(raw)
            val ident = classifyOutput(text, core.keyInfo.value?.serial)
                ?: throw UserFacingException("The NDEF message did not contain an OTP.")
            identified[idKey(core.keyInfo.value?.serial, ndefSlot)] = ident.copy(
                details = ident.details + ("NDEF payload" to text.take(80))
            )
        }
    }

    /** Read the NDEF record the key emits to phones and show it, without leaving the app. */
    fun showNdefOutput() {
        core.run("read the NFC (NDEF) output", refresh = false) { device ->
            val content = try {
                core.smartCard(device) { NdefReader.read(it) }
            } catch (e: Exception) {
                if (e is UserFacingException) throw e
                throw UserFacingException(
                    "Could not read the NDEF record: ${e.message}. Reading it works over NFC; over USB the key may not expose the tag.")
            }
            val isStatic = content.staticPassword != null
            val body = buildString {
                append(if (content.isUri) "Link: " else "Text: ").append(content.value)
                append("\n\nSlot output: ").append(content.otp)
                if (isStatic) append("\n\nThe slot holds a static password. Over NFC the key sends raw keyboard scan codes; they were translated with the US keyboard layout.")
                else if (content.otp.length in 32..48 && content.otp.all { it in "cbdefghijklnrtuv" }) append("\n\nThis is a Yubico OTP (ModHex).")
                else if (content.otp.length in 6..8 && content.otp.all { it.isDigit() }) append("\n\nThis is an OATH-HOTP code.")
                append("\n\nEach read makes the key generate a new value.")
            }
            core.showDialog(InfoDialog("NFC (NDEF) output", body, content.otp))
        }
    }

    /** For non-touch slots: send a challenge to see if the slot answers HMAC-SHA1. */
    fun probeChallengeResponse(slot: Slot) {
        core.run("test slot ${slot.num}") { device ->
            val challenge = Encoding.randomBytes(32)
            val result = runCatching {
                core.showTouchPrompt(true)
                core.otp(device) { it.calculateHmacSha1(slot, challenge, core.touchState()) }
            }
            core.showTouchPrompt(false)
            val serial = core.keyInfo.value?.serial
            identified[idKey(serial, slot)] = result.fold(
                onSuccess = { resp ->
                    Identification(
                        SlotType.CHALRESP, Evidence.PROBE,
                        listOf("Test response" to Encoding.toHex(resp).take(16) + "…")
                    )
                },
                onFailure = {
                    Identification(
                        SlotType.CHALRESP_OTHER, Evidence.PROBE,
                        listOf("HMAC test" to "no valid response (likely Yubico OTP challenge-response)")
                    )
                },
            )
        }
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    fun program(slot: Slot, program: SlotProgram, opts: SlotWriteOptions) {
        core.run("program slot ${slot.num}") { device ->
            val r = programOn(device, slot, program, opts, core.keyInfo.value?.serial)
            r.dialog?.let(core::showDialog) ?: core.toast("Slot ${slot.num} programmed as ${r.type.label}")
        }
    }

    /** Outcome of writing a slot; [secrets] holds generated values the user must save. */
    data class SlotResult(val type: SlotType, val details: Map<String, String>, val secrets: String?, val dialog: InfoDialog?)

    /** Program [slot] on an already-connected [device]. Shared by the slot screen and recipes. */
    suspend fun programOn(device: YubiKeyDevice, slot: Slot, program: SlotProgram, opts: SlotWriteOptions, serial: Int?): SlotResult {
        run {
            val curAcc = parseAccessCode(opts.currentAccessCodeHex)
            val newAcc = parseAccessCode(opts.newAccessCodeHex) ?: curAcc
            val details = linkedMapOf<String, String>()
            var dialog: InfoDialog? = null

            val type: SlotType
            val write: (YubiOtpSession) -> Unit

            when (program) {
                is SlotProgram.YubicoOtp -> {
                    type = SlotType.YUBICO_OTP
                    val publicId = when {
                        program.useSerialAsPublicId -> {
                            val s = serial ?: throw UserFacingException(
                                "The serial number is not readable, so it cannot be used as the public ID."
                            )
                            ByteBuffer.allocate(6).put(0xff.toByte()).put(0).putInt(s).array()
                        }
                        !program.publicIdModhex.isNullOrBlank() -> Encoding.fromModhex(program.publicIdModhex)
                        else -> ByteArray(6).also {
                            Encoding.randomBytes(5).copyInto(it, 1); it[0] = 0xff.toByte()
                        }
                    }
                    if (publicId.size > 16) throw UserFacingException("Public ID can be at most 16 bytes")
                    val privateId = program.privateIdHex?.takeIf { it.isNotBlank() }
                        ?.let(Encoding::fromHex) ?: Encoding.randomBytes(6)
                    val key = program.keyHex?.takeIf { it.isNotBlank() }
                        ?.let(Encoding::fromHex) ?: Encoding.randomBytes(16)
                    if (privateId.size != 6) throw UserFacingException("Private ID must be 6 bytes (12 hex digits)")
                    if (key.size != 16) throw UserFacingException("Secret key must be 16 bytes (32 hex digits)")
                    val pubMod = Encoding.toModhex(publicId)
                    details["Public ID"] = pubMod
                    write = { s ->
                        s.putConfiguration(
                            slot,
                            YubiOtpSlotConfiguration(publicId, privateId, key).appendCr(opts.appendEnter),
                            newAcc, curAcc,
                        )
                    }
                    dialog = InfoDialog(
                        "Slot ${slot.num}: Yubico OTP programmed",
                        "Public ID: $pubMod\nPrivate ID: ${Encoding.toHex(privateId)}\n" +
                            "Secret key: ${Encoding.toHex(key)}\n\n" +
                            "These values are not stored by the app and cannot be read back from " +
                            "the YubiKey. Save them now if you will upload this credential to a " +
                            "validation server.",
                        copyValue = "${serial ?: ""},$pubMod,${Encoding.toHex(privateId)},${Encoding.toHex(key)}",
                    )
                }

                is SlotProgram.Hotp -> {
                    type = SlotType.HOTP
                    val secret = Encoding.fromBase32(program.secretBase32)
                    if (secret.size > 20) throw UserFacingException("HOTP secret must be at most 20 bytes")
                    details["Digits"] = if (program.digits8) "8" else "6"
                    write = { s ->
                        var c = HotpSlotConfiguration(secret).digits8(program.digits8).appendCr(opts.appendEnter)
                        if (program.initialCounter > 0) c = c.imf(program.initialCounter)
                        s.putConfiguration(slot, c, newAcc, curAcc)
                    }
                }

                is SlotProgram.StaticPassword -> {
                    type = SlotType.STATIC
                    val pw = program.password?.takeIf { it.isNotEmpty() }
                        ?: if (program.modhexOnly) Encoding.randomModhex(program.generateLength)
                           else Encoding.randomPassword(program.generateLength)
                    if (pw.length > 38) throw UserFacingException("Static passwords can be at most 38 characters")
                    val codes = Encoding.passwordToScanCodes(pw)
                    details["Length"] = pw.length.toString()
                    write = { s ->
                        s.putConfiguration(
                            slot, StaticPasswordSlotConfiguration(codes).appendCr(opts.appendEnter), newAcc, curAcc
                        )
                    }
                    if (program.password.isNullOrEmpty()) {
                        dialog = InfoDialog(
                            "Slot ${slot.num}: static password programmed",
                            "Generated password: $pw\n\nThe app does not keep a copy.",
                            copyValue = pw,
                        )
                    }
                }

                is SlotProgram.ChallengeResponse -> {
                    type = SlotType.CHALRESP
                    val secret = program.secretHex?.takeIf { it.isNotBlank() }
                        ?.let(Encoding::fromHex) ?: Encoding.randomBytes(20)
                    if (secret.size > 64) throw UserFacingException("HMAC secret must be at most 64 bytes")
                    details["Require touch"] = if (program.requireTouch) "yes" else "no"
                    write = { s ->
                        s.putConfiguration(
                            slot,
                            HmacSha1SlotConfiguration(secret).requireTouch(program.requireTouch).lt64(true),
                            newAcc, curAcc,
                        )
                    }
                    if (program.secretHex.isNullOrBlank()) {
                        dialog = InfoDialog(
                            "Slot ${slot.num}: challenge-response programmed",
                            "Generated secret: ${Encoding.toHex(secret)}\n\nThe app does not keep a copy.",
                            copyValue = Encoding.toHex(secret),
                        )
                    }
                }
            }

            core.otp(device) { write(it) }
            if (newAcc != null) details["Access code"] = "set"
            history.put(serial, slot, SlotHistory(type, System.currentTimeMillis(), details))
            identified.remove(idKey(serial, slot))
            return SlotResult(type, details, dialog?.copyValue, dialog)
        }
    }

    /** Delete [slot] on an already-connected [device]. */
    suspend fun deleteOn(device: YubiKeyDevice, slot: Slot, accessCodeHex: String, serial: Int?) {
        core.otp(device) { it.deleteConfiguration(slot, parseAccessCode(accessCodeHex)) }
        history.put(serial, slot, null)
        identified.remove(idKey(serial, slot))
    }

    fun delete(slot: Slot, accessCodeHex: String) {
        core.run("delete slot ${slot.num}") { device ->
            core.otp(device) { it.deleteConfiguration(slot, parseAccessCode(accessCodeHex)) }
            val serial = core.keyInfo.value?.serial
            history.put(serial, slot, null)
            identified.remove(idKey(serial, slot))
            core.toast("Slot ${slot.num} deleted")
        }
    }

    fun deleteBoth() {
        core.run("delete both OTP slots") { device ->
            val serial = core.keyInfo.value?.serial
            val state = core.otp(device) { it.configurationState }
            val failed = mutableListOf<Int>()
            for (slot in listOf(Slot.ONE, Slot.TWO)) {
                if (runCatching { state.isConfigured(slot) }.getOrDefault(true)) {
                    runCatching { core.otp(device) { it.deleteConfiguration(slot, null) } }
                        .onFailure { failed += slot.num }
                }
                if (slot.num !in failed) {
                    history.put(serial, slot, null); identified.remove(idKey(serial, slot))
                }
            }
            if (failed.isEmpty()) core.toast("Both OTP slots are now empty")
            else core.error("Could not delete slot ${failed.joinToString()} (protected by an access code?)")
        }
    }

    fun swap() {
        core.run("swap the slots") { device ->
            core.otp(device) { it.swapConfigurations() }
            val serial = core.keyInfo.value?.serial
            history.swap(serial)
            val a = identified.remove(idKey(serial, Slot.ONE))
            val b = identified.remove(idKey(serial, Slot.TWO))
            a?.let { identified[idKey(serial, Slot.TWO)] = it }
            b?.let { identified[idKey(serial, Slot.ONE)] = it }
            core.toast("Slots swapped")
        }
    }

    fun calculateHmac(slot: Slot, challengeHex: String) {
        core.run("calculate a response") { device ->
            val challenge = if (challengeHex.isBlank()) ByteArray(0) else Encoding.fromHex(challengeHex)
            if (challenge.size > 64) throw UserFacingException("Challenge can be at most 64 bytes")
            core.showTouchPrompt(true)
            val resp = core.otp(device) { it.calculateHmacSha1(slot, challenge, core.touchState()) }
            core.showTouchPrompt(false)
            core.showDialog(InfoDialog("HMAC-SHA1 response (slot ${slot.num})", Encoding.toHex(resp), Encoding.toHex(resp)))
        }
    }

    /**
     * Point the NFC (NDEF) tag at [slot], prefixed with [prefix] as a URI or as
     * plain text.
     *
     * YubiKit's setNdefConfiguration() insists on parsing a 6-byte status from
     * the reply. Over the smart card interface (NFC, or USB when the keyboard
     * interface is off) the key acknowledges the NDEF command with an empty
     * body, which made that call throw IndexOutOfBoundsException after the
     * write had already succeeded. The command is therefore sent directly
     * here and the reply is only checked for a success status word.
     */
    fun setNdef(slot: Slot, prefix: String, asText: Boolean, accessCodeHex: String) {
        core.run("configure NFC output") { device ->
            val acc = parseAccessCode(accessCodeHex)
            val data = buildNdefConfig(prefix.trim(), asText) + (acc ?: ByteArray(6))
            val cmd: Byte = if (slot == Slot.ONE) 0x08 else 0x09
            val usb = device as? com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
            if (usb != null && usb.supportsConnection(com.yubico.yubikit.core.otp.OtpConnection::class.java)) {
                // Keyboard (HID) interface: YubiKit's own implementation is fine here.
                try {
                    core.otp(device) { it.setNdefConfiguration(slot, if (asText) null else prefix.trim().ifBlank { null }, acc) }
                } catch (e: IndexOutOfBoundsException) {
                    // Status could not be parsed but the key accepted the frame.
                }
                if (asText) throw UserFacingException(
                    "Plain-text NDEF can only be written over NFC or the smart card interface. Tap the key over NFC instead.")
            } else {
                core.smartCard(device) { c ->
                    val p = com.yubico.yubikit.core.smartcard.SmartCardProtocol(c)
                    p.select(com.yubico.yubikit.core.smartcard.AppId.OTP)
                    // Throws ApduException on any non-9000 status word; the body may be empty.
                    p.sendAndReceive(com.yubico.yubikit.core.smartcard.Apdu(0, 0x01, cmd.toInt(), 0, data))
                }
            }
            core.toast("NFC (NDEF) output now uses slot ${slot.num}" +
                (if (asText) " as text" else "") + (if (prefix.isBlank()) "" else " with prefix \"${prefix.trim()}\""))
        }
    }

    private fun buildNdefConfig(prefix: String, asText: Boolean): ByteArray {
        val payload: ByteArray
        val type: Byte
        if (asText) {
            // NFC Forum text record: status byte (UTF-8, language length) + language code + text
            val lang = "en".toByteArray()
            payload = byteArrayOf(lang.size.toByte()) + lang + prefix.toByteArray(Charsets.UTF_8)
            type = 'T'.code.toByte()
        } else {
            var uri = prefix.ifBlank { YubiOtpSession.DEFAULT_NDEF_URI }
            var idCode = 0
            for ((i, pfx) in NDEF_URL_PREFIXES.withIndex()) {
                if (uri.startsWith(pfx)) { idCode = i + 1; uri = uri.substring(pfx.length); break }
            }
            payload = byteArrayOf(idCode.toByte()) + uri.toByteArray(Charsets.UTF_8)
            type = 'U'.code.toByte()
        }
        if (payload.size > NDEF_DATA_SIZE) throw UserFacingException(
            "The NDEF prefix is too long (max ${NDEF_DATA_SIZE - (if (asText) 3 else 1)} characters after the standard URI prefix)")
        return ByteBuffer.allocate(2 + NDEF_DATA_SIZE).put(payload.size.toByte()).put(type).put(payload).array()
    }

    private fun parseAccessCode(hex: String): ByteArray? {
        val t = hex.trim()
        if (t.isEmpty()) return null
        val b = Encoding.fromHex(t)
        if (b.size != 6) throw UserFacingException("Access codes are 6 bytes (12 hex digits)")
        return b
    }

    companion object {
        private const val NDEF_DATA_SIZE = 54
        private val NDEF_URL_PREFIXES get() = NdefReader.URL_PREFIXES
        private const val MODHEX = "cbdefghijklnrtuv"

        fun classifyOutput(raw: String, serial: Int?): Identification? {
            val s = raw.trim().trim('\r', '\n', '\t')
            if (s.isEmpty()) return null
            val details = mutableListOf<Pair<String, String>>()

            val isModhex = s.all { it in MODHEX }
            if (isModhex && s.length in 32..64 && s.length % 2 == 0) {
                val pub = s.substring(0, s.length - 32)
                details += "Public ID" to (pub.ifEmpty { "(none)" })
                if (serial != null && pub == Encoding.toModhex(
                        ByteBuffer.allocate(6).put(0xff.toByte()).put(0).putInt(serial).array()
                    )
                ) details += "Public ID source" to "derived from the serial number"
                else if (pub.startsWith("cc")) details += "Origin" to "factory credential (YubiCloud)"
                else if (pub.startsWith("vv")) details += "Origin" to "user-programmed credential"
                details += "OTP length" to "${s.length} characters"
                return Identification(SlotType.YUBICO_OTP, Evidence.OUTPUT, details)
            }

            val hotp = Regex("^([cbdefghijklnrtuv0-9]{0,12}?)(\\d{6}|\\d{8})$").find(s)
            if (hotp != null && s.length <= 20) {
                details += "Digits" to hotp.groupValues[2].length.toString()
                if (hotp.groupValues[1].isNotEmpty()) details += "Token ID" to hotp.groupValues[1]
                return Identification(SlotType.HOTP, Evidence.OUTPUT, details)
            }

            details += "Output length" to "${s.length} characters"
            return Identification(SlotType.STATIC, Evidence.OUTPUT, details)
        }

        /** Extract the OTP from a YubiKey NDEF message (URI or text record). */
        fun parseNdefPayload(raw: ByteArray): String {
            val msg = android.nfc.NdefMessage(raw)
            val rec = msg.records.firstOrNull() ?: return ""
            val uri = runCatching { rec.toUri()?.toString() }.getOrNull()
            val text = uri ?: String(rec.payload, Charsets.UTF_8).drop(3)
            // The OTP is the trailing token after '#', '/', or '='.
            return text.split('#', '/', '=', '?').last()
        }

        fun formatTime(t: Long): String = DateFormat.getDateTimeInstance().format(Date(t))
    }
}

val Slot.num: Int get() = if (this == Slot.ONE) 1 else 2
