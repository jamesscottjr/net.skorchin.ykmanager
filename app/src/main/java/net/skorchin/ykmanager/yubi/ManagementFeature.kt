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

    /**
     * Build a configuration containing only the fields that actually change.
     *
     * Re-sending the whole current configuration (device flags, timeouts,
     * NFC-restricted flag) made the YubiKey answer 0x6A80 "wrong data" when
     * toggling an application, because some fields are only accepted in
     * particular combinations. ykman and Yubico Authenticator send just the
     * changed values, so this does the same.
     */
    private fun changedConfig(current: DeviceConfig, usb: Int?, nfc: Int?, chalrespTimeout: Int?, autoEject: Int?): DeviceConfig? {
        val b = DeviceConfig.Builder()
        var any = false
        if (usb != null && usb != current.getEnabledCapabilities(Transport.USB)) { b.enabledCapabilities(Transport.USB, usb); any = true }
        if (nfc != null && nfc != current.getEnabledCapabilities(Transport.NFC)) { b.enabledCapabilities(Transport.NFC, nfc); any = true }
        if (chalrespTimeout != null && chalrespTimeout.toByte() != current.challengeResponseTimeout) {
            b.challengeResponseTimeout(chalrespTimeout.toByte()); any = true
        }
        if (autoEject != null && autoEject.toShort() != current.autoEjectTimeout) { b.autoEjectTimeout(autoEject.toShort()); any = true }
        return if (any) b.build() else null
    }

    private fun describeConfigError(e: Throwable): Nothing {
        if (e is com.yubico.yubikit.core.smartcard.ApduException && e.sw == 0x6A80.toShort()) throw UserFacingException(
            "The YubiKey rejected the configuration (0x6A80). Make sure every application you enable is " +
                "supported on that interface and that the configuration lock code is correct.")
        throw e
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
            val written = core.management(device) { s ->
                val cur = s.deviceInfo.config
                val nfcArg = if (s.deviceInfo.hasTransport(Transport.NFC)) nfc else null
                val cfg = changedConfig(cur, usb, nfcArg, chalrespTimeout, autoEject) ?: return@management false
                val reboot = usb != null && usb != (cur.getEnabledCapabilities(Transport.USB) ?: usb)
                try { s.updateDeviceConfig(cfg, reboot, code, null) } catch (e: Exception) { describeConfigError(e) }
                true
            }
            return if (written) "Device configuration written" else "Already configured, nothing to change"
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
            val written = core.management(device) { s ->
                val cfg = changedConfig(s.deviceInfo.config, usb, nfc, null, null) ?: return@management false
                try { s.updateDeviceConfig(cfg, true, code, null) } catch (e: Exception) { describeConfigError(e) }
                true
            }
            core.toast(if (written) "Settings applied. The YubiKey restarted." else "Nothing to change")
        }
    }

    fun applyTimeouts(chalrespTimeout: Int, autoEject: Int, lockCodeHex: String) {
        core.run("apply the timeouts") { device ->
            val code = lockCode(lockCodeHex)
            val written = core.management(device) { s ->
                val cfg = changedConfig(s.deviceInfo.config, null, null, chalrespTimeout, autoEject) ?: return@management false
                try { s.updateDeviceConfig(cfg, false, code, null) } catch (e: Exception) { describeConfigError(e) }
                true
            }
            core.toast(if (written) "Timeouts saved" else "Nothing to change")
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
                // An otherwise empty configuration: only the lock code fields are sent.
                try { s.updateDeviceConfig(DeviceConfig.Builder().build(), false, current, new) } catch (e: Exception) { describeConfigError(e) }
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
