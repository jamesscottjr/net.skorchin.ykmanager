package net.skorchin.ykmanager.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.skorchin.ykmanager.yubi.AppViewModel
import net.skorchin.ykmanager.yubi.KeyInfo
import net.skorchin.ykmanager.yubi.Screen
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.management.Capability

// ----------------------------------------------------------------------
// Home
// ----------------------------------------------------------------------

@Composable
fun HomeScreen(vm: AppViewModel) {
    val info by vm.core.keyInfo.collectAsStateWithLifecycle()
    val nfc by vm.core.nfcAvailable.collectAsStateWithLifecycle()
    ScreenColumn {
        val k = info
        if (k == null) {
            NeedsKey("device information") { vm.core.refreshNow() }
            if (nfc == false) Hint("NFC is off or not available on this phone. USB still works with an OTG-capable port.")
            return@ScreenColumn
        }
        val d = k.deviceInfo
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            androidx.compose.foundation.layout.Column(Modifier.padding(20.dp)) {
                Text(
                    k.name,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Connected over ${if (k.transport == Transport.USB) "USB" else "NFC"}" +
                        (d?.let { " · " + formFactorName(it.formFactor) } ?: ""),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        SectionCard {
            SectionTitle("Device")
            Spacer(Modifier.height(6.dp))
            InfoRow("Firmware", d?.version?.toString() ?: k.otpVersion?.toString() ?: "unknown")
            InfoRow("Serial number", (d?.serialNumber ?: k.serial)?.toString() ?: "hidden")
            d?.partNumber?.takeIf { it.isNotBlank() }?.let { InfoRow("Part number", it) }
            if (d != null) {
                if (d.isFips) InfoRow("FIPS series", "yes")
                if (d.isSky) InfoRow("Security Key", "yes")
                if (k.isBio) InfoRow("Fingerprint sensor", "yes" + (d.fpsVersion?.let { " (sensor fw $it)" } ?: ""))
                if (d.pinComplexity) InfoRow("PIN complexity", "enforced")
                if (k.hasDeviceConfig) InfoRow("Config locked", if (d.isLocked) "yes (lock code set)" else "no")
                d.config.autoEjectTimeout?.let { InfoRow("Auto-eject", if (it.toInt() == 0) "off" else "${it}s") }
                d.config.challengeResponseTimeout?.let { InfoRow("Chal-resp timeout", "${it}s") }
            }
        }
        if (d != null) {
            for (t in listOf(Transport.USB, Transport.NFC)) {
                if (!d.hasTransport(t)) continue
                SectionCard {
                    SectionTitle(if (t == Transport.USB) "USB applications" else "NFC applications")
                    Spacer(Modifier.height(6.dp))
                    val supported = d.getSupportedCapabilities(t)
                    val enabled = d.config.getEnabledCapabilities(t) ?: 0
                    Capability.entries.filter { supported and it.bit != 0 }.forEach { c ->
                        InfoRow(capLabel(c), if (enabled and c.bit != 0) "enabled" else "disabled")
                    }
                }
            }
        }
        generationHint(k)?.let { Hint(it) }
        SectionCard {
            SectionTitle("Manage")
            Spacer(Modifier.height(6.dp))
            ButtonRow {
                Screen.entries
                    .filter { it != Screen.HOME && it != Screen.ABOUT && it != Screen.RESET && it != Screen.RECIPES && it.availableFor(k) }
                    .forEach { s -> SmallButton(s.title) { vm.navigate(s) } }
            }
        }
    }
}

/** A one-line note about what this generation of key can and cannot do in the app. */
private fun generationHint(k: KeyInfo): String? {
    val v = k.version ?: return null
    val d = k.deviceInfo
    return when {
        k.isFidoOnly && k.isBio -> "YubiKey Bio FIDO Edition: this key supports passkeys and fingerprints only."
        k.isFidoOnly -> "FIDO-only key: passkeys are the only application on this key."
        v.major < 3 -> "Firmware ${v}: this generation supports the two OTP slots only. " +
            "Smart card applications and device configuration are not available."
        v.major in 3..4 && d != null && !k.supports(Capability.FIDO2) && k.supports(Capability.U2F) ->
            "Firmware ${v}: FIDO U2F is supported but has nothing to manage; passkeys (FIDO2) need firmware 5. " +
            "USB interfaces are switched as a mode instead of per application."
        v.major in 3..4 -> "Firmware ${v}: USB interfaces are switched as a mode instead of per application; NFC and the lock code cannot be configured."
        else -> null
    }
}

// ----------------------------------------------------------------------
// Applications (enable/disable interfaces, timeouts, lock code)
// ----------------------------------------------------------------------

@Composable
fun ApplicationsScreen(vm: AppViewModel) {
    val info by vm.core.keyInfo.collectAsStateWithLifecycle()
    val d = info?.deviceInfo
    val k = info
    ScreenColumn {
        if (d == null || k == null) {
            NeedsKey("the application settings") { vm.core.refreshNow() }
            return@ScreenColumn
        }
        if (!k.hasDeviceConfig) {
            if (k.hasLegacyMode) LegacyModeSection(vm, k)
            else Hint("This key (firmware ${k.version}) has no configurable applications or interfaces.")
            return@ScreenColumn
        }
        var usb by remember(d) { mutableIntStateOf(d.config.getEnabledCapabilities(Transport.USB) ?: 0) }
        var nfc by remember(d) { mutableIntStateOf(d.config.getEnabledCapabilities(Transport.NFC) ?: 0) }
        var lock by remember { mutableStateOf("") }
        var lockDialog by remember { mutableStateOf(false) }
        var timeoutDialog by remember { mutableStateOf(false) }
        val usbSupported = d.getSupportedCapabilities(Transport.USB)
        val nfcSupported = d.getSupportedCapabilities(Transport.NFC)
        val hasNfc = d.hasTransport(Transport.NFC)

        SectionCard {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Application", Modifier.weight(1f), style = MaterialTheme.typography.labelLarge)
                Text("USB", Modifier.width(64.dp), style = MaterialTheme.typography.labelLarge)
                if (hasNfc) Text("NFC", Modifier.width(64.dp), style = MaterialTheme.typography.labelLarge)
            }
            HorizontalDivider(Modifier.padding(vertical = 6.dp))
            Capability.entries.filter { (usbSupported or nfcSupported) and it.bit != 0 }.forEach { c ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(capLabel(c), Modifier.weight(1f))
                    Row(Modifier.width(64.dp)) {
                        if (usbSupported and c.bit != 0) Switch(
                            checked = usb and c.bit != 0,
                            onCheckedChange = { on -> usb = if (on) usb or c.bit else usb and c.bit.inv() },
                        )
                    }
                    if (hasNfc) Row(Modifier.width(64.dp)) {
                        if (nfcSupported and c.bit != 0) Switch(
                            checked = nfc and c.bit != 0,
                            onCheckedChange = { on -> nfc = if (on) nfc or c.bit else nfc and c.bit.inv() },
                        )
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            if (d.isLocked) {
                androidx.compose.material3.OutlinedTextField(
                    value = lock, onValueChange = { lock = it },
                    label = { Text("Configuration lock code (32 hex digits)") },
                    singleLine = true, modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
            }
            Hint("Applying restarts the YubiKey. Over NFC, keep it on the phone until it finishes.")
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { vm.mgmt.applyApplications(usb, if (hasNfc) nfc else null, lock) }) {
                    Text("Apply")
                }
                OutlinedButton(onClick = {
                    usb = d.config.getEnabledCapabilities(Transport.USB) ?: 0
                    nfc = d.config.getEnabledCapabilities(Transport.NFC) ?: 0
                }) { Text("Revert") }
            }
        }

        SectionCard {
            SectionTitle("Configuration lock code")
            Spacer(Modifier.height(4.dp))
            InfoRow("Status", if (d.isLocked) "set" else "not set")
            Hint("A lock code prevents anyone from changing which applications are enabled without it.")
            Spacer(Modifier.height(8.dp))
            SmallButton(if (d.isLocked) "Change or remove" else "Set lock code") { lockDialog = true }
        }

        SectionCard {
            SectionTitle("Timeouts")
            Spacer(Modifier.height(4.dp))
            InfoRow("Auto-eject", d.config.autoEjectTimeout?.let { "${it}s" } ?: "default")
            InfoRow("Chal-resp touch", d.config.challengeResponseTimeout?.let { "${it}s" } ?: "default")
            Spacer(Modifier.height(8.dp))
            SmallButton("Edit timeouts") { timeoutDialog = true }
        }

        if (lockDialog) FormDialog(
            title = "Configuration lock code",
            fields = listOfNotNull(
                if (d.isLocked) Field.Text("cur", "Current lock code (hex)") else null,
                Field.Check("gen", "Generate a random lock code", initial = !d.isLocked),
                Field.Text("new", "New lock code (hex)", supporting = "32 hex digits. Leave empty to remove the lock code."),
            ),
            confirmLabel = "Save",
            onDismiss = { lockDialog = false },
        ) { v ->
            vm.mgmt.setLockCode(v.text("cur"), if (v.check("gen")) null else v.text("new"))
            null
        }

        if (timeoutDialog) FormDialog(
            title = "Timeouts",
            fields = listOfNotNull(
                Field.Text("eject", "Auto-eject timeout (seconds, 0 = off)",
                    (d.config.autoEjectTimeout ?: 0).toString(), numeric = true),
                Field.Text("cr", "Challenge-response touch timeout (seconds)",
                    (d.config.challengeResponseTimeout ?: 15).toString(), numeric = true),
                if (d.isLocked) Field.Text("lock", "Configuration lock code (hex)") else null,
            ),
            confirmLabel = "Save",
            onDismiss = { timeoutDialog = false },
        ) { v ->
            val e = v.int("eject", -1); val c = v.int("cr", -1)
            if (e !in 0..65535 || c !in 1..255) return@FormDialog "Enter valid numbers"
            vm.mgmt.applyTimeouts(c, e, v.text("lock"))
            null
        }
    }
}

/**
 * YubiKey NEO and YubiKey 4: the USB interfaces (OTP keyboard, FIDO HID,
 * CCID smart card) are enabled as a combined "mode". Applications cannot be
 * toggled individually and there is no NFC configuration or lock code.
 */
@Composable
private fun LegacyModeSection(vm: AppViewModel, k: KeyInfo) {
    val d = k.deviceInfo!!
    val enabled = d.config.getEnabledCapabilities(Transport.USB) ?: d.getSupportedCapabilities(Transport.USB)
    val supported = d.getSupportedCapabilities(Transport.USB)
    val ccidBits = Capability.OATH.bit or Capability.PIV.bit or Capability.OPENPGP.bit or Capability.HSMAUTH.bit
    val fidoBits = Capability.U2F.bit or Capability.FIDO2.bit
    var otp by remember(d) { mutableStateOf(enabled and Capability.OTP.bit != 0) }
    var fido by remember(d) { mutableStateOf(enabled and fidoBits != 0) }
    var ccid by remember(d) { mutableStateOf(enabled and ccidBits != 0) }
    var cr by remember(d) { mutableStateOf((d.config.challengeResponseTimeout ?: 15).toString()) }
    var eject by remember(d) { mutableStateOf((d.config.autoEjectTimeout ?: 0).toString()) }

    SectionCard {
        SectionTitle("USB interfaces (mode)")
        Spacer(Modifier.height(4.dp))
        Hint("Firmware ${k.version}: this key switches whole USB interfaces rather than individual applications.")
        Spacer(Modifier.height(8.dp))
        @Composable
        fun row(label: String, detail: String, available: Boolean, checked: Boolean, onChange: (Boolean) -> Unit) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.foundation.layout.Column(Modifier.weight(1f)) {
                    Text(label)
                    Hint(detail)
                }
                Switch(checked = checked, onCheckedChange = onChange, enabled = available)
            }
        }
        row("OTP (keyboard)", "Yubico OTP, static password, challenge-response", supported and Capability.OTP.bit != 0, otp) { otp = it }
        row("FIDO (U2F)", "Security key functions", supported and fidoBits != 0, fido) { fido = it }
        row("CCID (smart card)", "OATH, PIV, OpenPGP", supported and ccidBits != 0, ccid) { ccid = it }
        Spacer(Modifier.height(8.dp))
        androidx.compose.material3.OutlinedTextField(
            value = cr, onValueChange = { cr = it.filter(Char::isDigit) },
            label = { Text("Challenge-response touch timeout (seconds)") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        androidx.compose.material3.OutlinedTextField(
            value = eject, onValueChange = { eject = it.filter(Char::isDigit) },
            label = { Text("Auto-eject timeout (seconds, CCID-only mode, 0 = off)") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Hint("After applying, unplug the key and plug it back in for the new mode to take effect.")
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                vm.mgmt.applyLegacyMode(otp, fido, ccid, cr.toIntOrNull() ?: 15, eject.toIntOrNull() ?: 0)
            }) { Text("Apply") }
            OutlinedButton(onClick = {
                otp = enabled and Capability.OTP.bit != 0
                fido = enabled and fidoBits != 0
                ccid = enabled and ccidBits != 0
            }) { Text("Revert") }
        }
    }
}

// ----------------------------------------------------------------------
// Factory reset
// ----------------------------------------------------------------------

@Composable
fun ResetScreen(vm: AppViewModel) {
    var confirm by remember { mutableStateOf<String?>(null) }
    val info by vm.core.keyInfo.collectAsStateWithLifecycle()
    val k = info
    fun has(c: Capability) = k?.supports(c) ?: true
    ScreenColumn {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                "Resetting an application permanently deletes its credentials. This cannot be undone.",
                modifier = Modifier.padding(16.dp),
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
        }
        if (k?.hasDeviceReset == true) {
            ResetCard("Entire device (Bio Multi-protocol)", "Resets every application on this YubiKey Bio at once: passkeys, fingerprints, PIV, and the PINs. The key restarts afterwards.") { confirm = "Device" }
        }
        if (has(Capability.OATH)) ResetCard("OATH (Accounts)", "Deletes all TOTP/HOTP accounts and the password.") { confirm = "OATH" }
        if (has(Capability.FIDO2)) ResetCard("FIDO (Passkeys" + (if (k?.isBio == true) " and fingerprints" else "") + ")",
            "Deletes all passkeys" + (if (k?.isBio == true) ", fingerprints" else "") +
                " and the FIDO PIN. Must be done within a few seconds of plugging the key in (USB) and requires a touch.") { confirm = "FIDO" }
        if (has(Capability.PIV)) ResetCard("PIV (Certificates)", "Deletes all certificates and keys. PIN, PUK and management key return to defaults.") { confirm = "PIV" }
        if (has(Capability.OPENPGP)) ResetCard("OpenPGP", "Deletes all OpenPGP keys. PINs return to defaults.") { confirm = "OpenPGP" }
        if (has(Capability.OTP)) ResetCard("OTP slots", "Deletes both OTP slots (fails if a slot has an access code).") { confirm = "OTP" }
    }
    confirm?.let { what ->
        TypedConfirmDialog(
            title = "Reset $what?",
            text = if (what == "Device") "Every application on this key will be wiped and returned to factory state. This cannot be undone."
                else "All $what data on this YubiKey will be permanently deleted. This cannot be undone.",
            keyword = "RESET",
            confirmLabel = "Reset",
            onDismiss = { confirm = null },
        ) {
            when (what) {
                "OATH" -> vm.oath.reset()
                "FIDO" -> vm.fido.reset()
                "PIV" -> vm.piv.reset()
                "OpenPGP" -> vm.pgp.reset()
                "OTP" -> vm.otp.deleteBoth()
                "Device" -> vm.mgmt.deviceReset()
            }
        }
    }
}

@Composable
private fun ResetCard(title: String, text: String, onReset: () -> Unit) {
    SectionCard {
        SectionTitle(title)
        Spacer(Modifier.height(4.dp))
        Hint(text)
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onReset) { Text("Reset", color = MaterialTheme.colorScheme.error) }
    }
}
