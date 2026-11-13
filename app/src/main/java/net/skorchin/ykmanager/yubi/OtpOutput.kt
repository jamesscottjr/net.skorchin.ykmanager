package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.yubiotp.OtpFlagAccess
import com.yubico.yubikit.yubiotp.SlotConfiguration
import org.json.JSONObject

/** Keystroke pacing (PACING_10MS / PACING_20MS flags), the "Output speed throttling" setting. */
enum class OtpPacing(val label: String, val p10: Boolean, val p20: Boolean) {
    STANDARD("Standard speed", false, false),
    SLOW_10("Add ~10 ms between keystrokes", true, false),
    SLOW_20("Add ~20 ms between keystrokes", false, true),
    SLOW_30("Add ~30 ms between keystrokes (slowest)", true, true),
}

/**
 * Output and device settings applied when programming an OTP slot, matching the Settings tab
 * of the Windows YubiKey Personalization Tool: output characters (tabs, Enter), delays, speed
 * throttling, numeric keypad, serial number visibility and update permissions.
 *
 * Defaults are YubiKit's defaults (and what YK Manager wrote before these settings existed):
 * Enter appended, fast trigger, serial visible to API calls, updates allowed.
 */
data class OtpOutputSettings(
    // Output characters: [Tab] first part [Tab] second part [Tab] [Enter]
    val tabFirst: Boolean = false,
    val tabAfterFirst: Boolean = false,
    val tabAfterSecond: Boolean = false,
    val appendEnter: Boolean = true,
    // Delays
    val delayAfterFirst: Boolean = false,
    val delayAfterSecond: Boolean = false,
    val pacing: OtpPacing = OtpPacing.STANDARD,
    // Keyboard behaviour
    val numericKeypad: Boolean = false,
    val fastTrigger: Boolean = true,
    val sendReference: Boolean = false,  // Yubico OTP only
    // Device
    val invertLed: Boolean = false,
    val serialButton: Boolean = false,
    val serialUsb: Boolean = false,
    val serialApi: Boolean = true,
    val allowUpdate: Boolean = true,
) {
    val isDefault: Boolean get() = this == OtpOutputSettings()

    /**
     * What a touch types, e.g. "Tab · public ID · Tab · OTP · Enter". [firstPart] is the fixed
     * prefix (public ID for Yubico OTP); null when the slot type has none.
     */
    fun outputPattern(firstPart: String? = "public ID", secondPart: String = "OTP"): String = buildList {
        if (tabFirst) add("Tab")
        firstPart?.let { add(it) }
        if (delayAfterFirst) add("0.5 s pause")
        if (tabAfterFirst) add("Tab")
        add(secondPart)
        if (delayAfterSecond) add("0.5 s pause")
        if (tabAfterSecond) add("Tab")
        if (appendEnter) add("Enter")
    }.joinToString(" · ")

    /** Short list of the non-default choices, for recipe summaries and confirmations. */
    fun changesFromDefault(): List<String> {
        val d = OtpOutputSettings()
        return buildList {
            if (tabFirst) add("tab first")
            if (tabAfterFirst) add("tab after first part")
            if (tabAfterSecond) add("tab after OTP")
            if (appendEnter != d.appendEnter) add(if (appendEnter) "Enter" else "no Enter")
            if (delayAfterFirst) add("delay after first part")
            if (delayAfterSecond) add("delay after OTP")
            if (pacing != d.pacing) add(pacing.label.lowercase())
            if (numericKeypad) add("numeric keypad")
            if (!fastTrigger) add("no fast trigger")
            if (sendReference) add("reference string")
            if (invertLed) add("inverted LED")
            if (serialButton) add("serial at startup")
            if (serialUsb) add("serial in USB descriptor")
            if (!serialApi) add("serial hidden from API")
            if (!allowUpdate) add("updates locked")
        }
    }

    /**
     * Writes these settings into a YubiKit [config].
     * @param keyboard the slot types text (Yubico OTP, HOTP, static); false for challenge-response,
     *   which only takes the device flags.
     * @param yubicoOtp the reference-string flag is only valid for Yubico OTP.
     */
    fun applyTo(config: SlotConfiguration, keyboard: Boolean, yubicoOtp: Boolean = false) {
        fun set(name: String, v: Boolean) = OtpFlagAccess.set(config, name, v)
        set("EXTFLAG_SERIAL_BTN_VISIBLE", serialButton)
        set("EXTFLAG_SERIAL_USB_VISIBLE", serialUsb)
        set("EXTFLAG_SERIAL_API_VISIBLE", serialApi)
        set("EXTFLAG_ALLOW_UPDATE", allowUpdate)
        set("EXTFLAG_LED_INV", invertLed)
        set("TKTFLAG_TAB_FIRST", keyboard && tabFirst)
        set("TKTFLAG_APPEND_TAB1", keyboard && tabAfterFirst)
        set("TKTFLAG_APPEND_TAB2", keyboard && tabAfterSecond)
        set("TKTFLAG_APPEND_DELAY1", keyboard && delayAfterFirst)
        set("TKTFLAG_APPEND_DELAY2", keyboard && delayAfterSecond)
        set("TKTFLAG_APPEND_CR", keyboard && appendEnter)
        set("CFGFLAG_PACING_10MS", keyboard && pacing.p10)
        set("CFGFLAG_PACING_20MS", keyboard && pacing.p20)
        set("EXTFLAG_USE_NUMERIC_KEYPAD", keyboard && numericKeypad)
        set("EXTFLAG_FAST_TRIG", keyboard && fastTrigger)
        if (yubicoOtp) set("CFGFLAG_SEND_REF", sendReference)
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("tabFirst", tabFirst); put("tab1", tabAfterFirst); put("tab2", tabAfterSecond); put("cr", appendEnter)
        put("delay1", delayAfterFirst); put("delay2", delayAfterSecond); put("pacing", pacing.name)
        put("numeric", numericKeypad); put("fastTrig", fastTrigger); put("sendRef", sendReference)
        put("ledInv", invertLed); put("serialBtn", serialButton); put("serialUsb", serialUsb)
        put("serialApi", serialApi); put("allowUpdate", allowUpdate)
    }

    companion object {
        fun fromJson(o: JSONObject?): OtpOutputSettings {
            if (o == null) return OtpOutputSettings()
            val d = OtpOutputSettings()
            return OtpOutputSettings(
                tabFirst = o.optBoolean("tabFirst", d.tabFirst),
                tabAfterFirst = o.optBoolean("tab1", d.tabAfterFirst),
                tabAfterSecond = o.optBoolean("tab2", d.tabAfterSecond),
                appendEnter = o.optBoolean("cr", d.appendEnter),
                delayAfterFirst = o.optBoolean("delay1", d.delayAfterFirst),
                delayAfterSecond = o.optBoolean("delay2", d.delayAfterSecond),
                pacing = OtpPacing.values().firstOrNull { it.name == o.optString("pacing") } ?: d.pacing,
                numericKeypad = o.optBoolean("numeric", d.numericKeypad),
                fastTrigger = o.optBoolean("fastTrig", d.fastTrigger),
                sendReference = o.optBoolean("sendRef", d.sendReference),
                invertLed = o.optBoolean("ledInv", d.invertLed),
                serialButton = o.optBoolean("serialBtn", d.serialButton),
                serialUsb = o.optBoolean("serialUsb", d.serialUsb),
                serialApi = o.optBoolean("serialApi", d.serialApi),
                allowUpdate = o.optBoolean("allowUpdate", d.allowUpdate),
            )
        }
    }
}
