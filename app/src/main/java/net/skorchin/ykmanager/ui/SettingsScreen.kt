package net.skorchin.ykmanager.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.skorchin.ykmanager.yubi.AppViewModel
import net.skorchin.ykmanager.yubi.NfcTapAction
import net.skorchin.ykmanager.yubi.OtpOutputSettings
import net.skorchin.ykmanager.yubi.OtpPacing
import androidx.compose.material3.OutlinedButton

@Composable
fun SettingsScreen(vm: AppViewModel) {
    val tap by vm.settings.nfcTapAction.collectAsStateWithLifecycle()
    val copyOnShow by vm.settings.copyOnShow.collectAsStateWithLifecycle()
    val nfcAvailable by vm.core.nfcAvailable.collectAsStateWithLifecycle()
    val out by vm.settings.otpOutput.collectAsStateWithLifecycle()

    ScreenColumn {
        SectionTitle("NFC tap")
        SectionCard {
            Text(
                "What happens when you tap a YubiKey while the app is open and no action is waiting for it. " +
                    "Actions you start in the app (unlocking, writing, deleting) always take priority.",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (nfcAvailable == false) {
                Spacer(Modifier.height(8.dp))
                Hint("NFC is not available or is turned off on this phone.")
            }
            Spacer(Modifier.height(8.dp))
            HorizontalDivider()
            NfcTapAction.values().forEach { a ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable { vm.settings.setNfcTapAction(a) }
                        .padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = tap == a, onClick = { vm.settings.setNfcTapAction(a) })
                    Spacer(Modifier.width(4.dp))
                    Column(Modifier.fillMaxWidth()) {
                        Text(a.label, style = MaterialTheme.typography.bodyLarge)
                        Text(a.description, style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (tap == NfcTapAction.SHOW_OTP) {
                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                Row(
                    Modifier.fillMaxWidth().clickable { vm.settings.setCopyOnShow(!copyOnShow) },
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = copyOnShow, onCheckedChange = { vm.settings.setCopyOnShow(it) })
                    Text("Also copy the one-time password to the clipboard")
                }
            }
            Spacer(Modifier.height(8.dp))
            Hint(
                "The NDEF record is what the key sends to a phone that just reads it as a tag: by default a " +
                    "my.yubico.com link carrying a Yubico OTP from the slot chosen under OTP slots → NFC (NDEF) output. " +
                    "Reading it makes the key generate a new one-time password each time."
            )
        }
        OtpOutputSection(out) { vm.settings.setOtpOutput(it) }
    }
}

/**
 * The Settings tab of the Windows YubiKey Personalization Tool: output characters, delays,
 * speed throttling, keyboard options, serial number visibility and update permission.
 */
@Composable
private fun OtpOutputSection(out: OtpOutputSettings, set: (OtpOutputSettings) -> Unit) {
    SectionTitle("OTP output")
    SectionCard {
        Text(
            "Used whenever this app programs a Yubico OTP, OATH-HOTP or static password slot, and when you " +
                "add a slot step to a recipe. Existing slots keep their settings until you use Update settings " +
                "on the OTP slots screen.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(8.dp))
        Text("Output", style = MaterialTheme.typography.labelLarge)
        Text(out.outputPattern(), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
        Text("HOTP and static passwords have no public ID part; their tab/delay \"after first part\" options still apply.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        SubHeading("Output characters")
        CheckRow("Tab before the output", out.tabFirst) { set(out.copy(tabFirst = it)) }
        CheckRow("Tab after the first part (public ID)", out.tabAfterFirst) { set(out.copy(tabAfterFirst = it)) }
        CheckRow("Tab after the OTP / password", out.tabAfterSecond) { set(out.copy(tabAfterSecond = it)) }
        CheckRow("Enter at the end", out.appendEnter) { set(out.copy(appendEnter = it)) }

        SubHeading("Output speed")
        CheckRow("0.5 s pause after the first part", out.delayAfterFirst) { set(out.copy(delayAfterFirst = it)) }
        CheckRow("0.5 s pause after the OTP / password", out.delayAfterSecond) { set(out.copy(delayAfterSecond = it)) }
        OtpPacing.values().forEach { p ->
            Row(
                Modifier.fillMaxWidth().clickable { set(out.copy(pacing = p)) }.padding(vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = out.pacing == p, onClick = { set(out.copy(pacing = p)) })
                Spacer(Modifier.width(4.dp))
                Text(p.label, style = MaterialTheme.typography.bodyMedium)
            }
        }
        Hint("Slow the typing down if a computer, remote desktop session or KVM drops characters.")

        SubHeading("Keyboard")
        CheckRow("Use the numeric keypad for digits", out.numericKeypad,
            "Sends digits as keypad keys, which some keyboard layouts need (firmware 2.3+)") { set(out.copy(numericKeypad = it)) }
        CheckRow("Fast trigger", out.fastTrigger,
            "When only slot 1 is programmed, output starts on touch without waiting to see if it is a long press (firmware 2.3+)") { set(out.copy(fastTrigger = it)) }
        CheckRow("Send reference string first (Yubico OTP)", out.sendReference,
            "Types \"0123456789abcdef\" before the OTP, for checking keyboard mapping") { set(out.copy(sendReference = it)) }

        SubHeading("Serial number visibility")
        CheckRow("Typed when the button is held at insertion", out.serialButton,
            "Hold the touch area while plugging in the key to type its serial number (firmware 2.2+)") { set(out.copy(serialButton = it)) }
        CheckRow("In the USB descriptor", out.serialUsb, "Shows the serial number to the computer's USB stack (firmware 2.2+)") { set(out.copy(serialUsb = it)) }
        CheckRow("Readable by apps (API)", out.serialApi, "Lets apps such as this one read the serial number") { set(out.copy(serialApi = it)) }

        SubHeading("Device")
        CheckRow("Invert LED", out.invertLed, "LED is off when idle instead of on (firmware 2.4+)") { set(out.copy(invertLed = it)) }
        CheckRow("Allow update", out.allowUpdate,
            "Lets these settings be changed later without reprogramming the credential. Turning it off locks them.") { set(out.copy(allowUpdate = it)) }

        Spacer(Modifier.height(8.dp))
        Hint("Options the key's firmware does not support make programming fail with an explanation. " +
            "These flags cannot be read back from a YubiKey, so this app shows what it last wrote.")
        if (!out.isDefault) {
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { set(OtpOutputSettings()) }) { Text("Reset to defaults") }
        }
    }
}

@Composable
private fun SubHeading(text: String) {
    HorizontalDivider(Modifier.padding(top = 10.dp, bottom = 4.dp))
    Text(text, style = MaterialTheme.typography.labelLarge)
}

@Composable
private fun CheckRow(label: String, checked: Boolean, help: String? = null, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Column(Modifier.fillMaxWidth()) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            help?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
