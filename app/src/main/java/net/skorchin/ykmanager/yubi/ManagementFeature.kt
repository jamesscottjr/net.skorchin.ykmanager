package net.skorchin.ykmanager.yubi

import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.UsbInterface
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.management.DeviceConfig

class ManagementFeature(private val core: YubiKeyCore) {

    private fun lockCode(hex: String): ByteArray? {
        val t = hex.trim()
        if (t.isEmpty()) return null
        val b = Encoding.fromHex(t)
        if (b.size != 16) throw UserFacingException("Lock codes are 16 bytes (32 hex digits)")
        return b
    }

    private fun copyConfig(current: DeviceConfig, usb: Int?, nfc: Int?, chalrespTimeout: Int?, autoEject: Int?): DeviceConfig {
        val b = DeviceConfig.Builder()
        current.deviceFlags?.let { b.deviceFlags(it) }
        (autoEject?.toShort() ?: current.autoEjectTimeout)?.let { b.autoEjectTimeout(it) }
        (chalrespTimeout?.toByte() ?: current.challengeResponseTimeout)?.let { b.challengeResponseTimeout(it) }
        current.nfcRestricted?.let { b.nfcRestricted(it) }
        for (t in Transport.values()) current.getEnabledCapabilities(t)?.let { b.enabledCapabilities(t, it) }
        usb?.let { b.enabledCapabilities(Transport.USB, it) }
        nfc?.let { b.enabledCapabilities(Transport.NFC, it) }
        return b.build()
    }

    /**
     * Apply device configuration on an already-connected [device]. Handles both
     * YubiKey 5 (updateDeviceConfig) and YubiKey 4 / NEO (setMode). Returns a
     * short description of what was written.
     */
    suspend fun applyConfigOn(
        device: YubiKeyDevice, info: KeyInfo,
        usb: Int?, nfc: Int?, chalrespTimeout: Int?, autoEject: Int?, lockCodeHex: String,
    ): String {
        if (usb == 0) throw UserFacingException("At least one application must stay enabled over USB")
        if (info.hasDeviceConfig) {
            val code = lockCode(lockCodeHex)
            core.management(device) { s ->
                val cur = s.deviceInfo.config
                val nfcArg = if (s.deviceInfo.hasTransport(Transport.NFC)) nfc else null
                val cfg = copyConfig(cur, usb, nfcArg, chalrespTimeout, autoEject)
                val reboot = usb != null && usb != (cur.getEnabledCapabilities(Transport.USB) ?: usb)
                s.updateDeviceConfig(cfg, reboot, code, null)
            }
            return "Device configuration written"
        }
        if (info.hasLegacyMode) {
            val caps = usb ?: return "Nothing to change"
            val interfaces = (if (caps and Capability.OTP.bit != 0) UsbInterface.OTP else 0) or
                (if (caps and (Capability.U2F.bit or Capability.FIDO2.bit) != 0) UsbInterface.FIDO else 0) or
                (if (caps and (Capability.OATH.bit or Capability.PIV.bit or Capability.OPENPGP.bit or Capability.HSMAUTH.bit) != 0) UsbInterface.CCID else 0)
            val mode = UsbInterface.Mode.getMode(interfaces)
            core.management(device) { s ->
                s.setMode(mode, (chalrespTimeout ?: 15).coerceIn(0, 255).toByte(), ((autoEject ?: 0) / 10).coerceIn(0, 65535).toShort())
            }
            return "USB mode set to ${mode.name.replace('_', '+')}"
        }
        throw UserFacingException("This key has no configurable applications")
    }

    fun applyApplications(usb: Int, nfc: Int?, lockCodeHex: String) {
        if (usb == 0) return core.error("At least one application must stay enabled over USB")
        core.run("apply the application settings") { device ->
            val code = lockCode(lockCodeHex)
            core.management(device) { s ->
                val cfg = copyConfig(s.deviceInfo.config, usb, nfc, null, null)
                s.updateDeviceConfig(cfg, true, code, null)
            }
            core.toast("Settings applied. The YubiKey restarted.")
        }
    }

    fun applyTimeouts(chalrespTimeout: Int, autoEject: Int, lockCodeHex: String) {
        core.run("apply the timeouts") { device ->
            val code = lockCode(lockCodeHex)
            core.management(device) { s ->
                val cfg = copyConfig(s.deviceInfo.config, null, null, chalrespTimeout, autoEject)
                s.updateDeviceConfig(cfg, false, code, null)
            }
            core.toast("Timeouts saved")
        }
    }

    /** Set, change or (with an empty new code) remove the configuration lock code. */
    fun setLockCode(currentHex: String, newHex: String?) {
        core.run("update the lock code") { device ->
            val current = lockCode(currentHex)
            val generated = newHex == null
            val new = when {
                newHex == null -> Encoding.randomBytes(16)
                newHex.isBlank() -> ByteArray(16)   // all zeros clears the lock code
                else -> lockCode(newHex)!!
            }
            core.management(device) { s ->
                val cfg = copyConfig(s.deviceInfo.config, null, null, null, null)
                s.updateDeviceConfig(cfg, false, current, new)
            }
            if (new.all { it.toInt() == 0 }) core.toast("Configuration lock code removed")
            else core.showDialog(
                InfoDialog(
                    "Lock code set",
                    (if (generated) "Generated lock code:\n" else "Lock code:\n") + Encoding.toHex(new) +
                        "\n\nYou need this code to change which applications are enabled. " +
                        "If you lose it, the configuration can never be changed again.",
                    Encoding.toHex(new),
                )
            )
        }
    }

    // ------------------------------------------------------------------
    // Legacy keys (YubiKey NEO, YubiKey 4): USB interface mode
    // ------------------------------------------------------------------

    /**
     * Pre-5.0 firmware has no per-application configuration; instead the USB
     * interfaces (OTP keyboard, FIDO HID, CCID smart card) are switched on or
     * off as a "mode". NFC and the lock code do not exist on these keys.
     */
    fun applyLegacyMode(otp: Boolean, fido: Boolean, ccid: Boolean, chalrespTimeout: Int, autoEject: Int) {
        val interfaces = (if (otp) UsbInterface.OTP else 0) or
            (if (fido) UsbInterface.FIDO else 0) or
            (if (ccid) UsbInterface.CCID else 0)
        if (interfaces == 0) return core.error("At least one interface must stay enabled")
        val mode = UsbInterface.Mode.getMode(interfaces)
        core.run("apply the USB mode") { device ->
            core.management(device) { s ->
                // Auto-eject is in units of 10 seconds for legacy keys and only applies to CCID-only mode.
                s.setMode(mode, chalrespTimeout.coerceIn(0, 255).toByte(), (autoEject / 10).coerceIn(0, 65535).toShort())
            }
            core.toast("USB mode set to ${mode.name.replace('_', '+')}. Unplug and reinsert the key.")
        }
    }

    // ------------------------------------------------------------------
    // YubiKey Bio Multi-protocol Edition: device-wide reset
    // ------------------------------------------------------------------

    fun deviceReset() {
        core.run("reset the device") { device ->
            core.management(device) { s -> s.deviceReset() }
            core.toast("Device reset complete. All applications are back to factory state.")
        }
    }
}
