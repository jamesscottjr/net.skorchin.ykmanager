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

@Composable
fun SettingsScreen(vm: AppViewModel) {
    val tap by vm.settings.nfcTapAction.collectAsStateWithLifecycle()
    val copyOnShow by vm.settings.copyOnShow.collectAsStateWithLifecycle()
    val nfcAvailable by vm.core.nfcAvailable.collectAsStateWithLifecycle()

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
    }
}
