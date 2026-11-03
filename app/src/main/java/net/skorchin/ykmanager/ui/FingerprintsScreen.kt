package net.skorchin.ykmanager.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.skorchin.ykmanager.yubi.AppViewModel
import net.skorchin.ykmanager.yubi.Fingerprint
import net.skorchin.ykmanager.yubi.Link

private enum class FpDialog { UNLOCK, ADD }

@Composable
fun FingerprintsScreen(vm: AppViewModel) {
    val st by vm.fido.state.collectAsStateWithLifecycle()
    val enroll by vm.fido.enroll.collectAsStateWithLifecycle()
    val link by vm.core.link.collectAsStateWithLifecycle()
    var dialog by remember { mutableStateOf<FpDialog?>(null) }
    var toRename by remember { mutableStateOf<Fingerprint?>(null) }
    var toDelete by remember { mutableStateOf<Fingerprint?>(null) }

    ScreenColumn {
        if (!st.loaded) {
            NeedsKey("fingerprint information") { vm.core.refreshNow() }
            return@ScreenColumn
        }
        if (!st.bioSupported) {
            Hint("This key has no fingerprint sensor.")
            return@ScreenColumn
        }
        SectionCard {
            SectionTitle("Fingerprint sensor")
            Spacer(Modifier.height(4.dp))
            InfoRow("Fingerprints enrolled", if (st.bioEnrolled) "yes" else "none yet")
            InfoRow("PIN", if (st.pinSet) "set" else "not set")
            st.fingerprints?.let { InfoRow("Stored", "${it.size} of 5") }
            Hint("Up to 5 fingerprints can be stored. Enrollment and changes need the FIDO2 PIN and a USB connection.")
        }

        SectionTitle("Fingerprints")
        when {
            !st.pinSet -> Hint("Set a FIDO2 PIN under Passkeys first. Fingerprints are protected by the PIN.")
            st.fingerprints == null -> SectionCard {
                Hint("Enter your FIDO2 PIN to list and manage fingerprints.")
                Spacer(Modifier.height(8.dp))
                SmallButton("Unlock with PIN") { dialog = FpDialog.UNLOCK }
            }
            else -> {
                val list = st.fingerprints!!
                if (list.isEmpty()) Hint("No fingerprints are enrolled yet.")
                list.forEach { fp ->
                    Card(Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Fingerprint, contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
                            Column(Modifier.weight(1f).padding(start = 12.dp)) {
                                Text(fp.name, fontWeight = FontWeight.Medium)
                                Text(fp.id, style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            IconButton(onClick = { toRename = fp }) {
                                Icon(Icons.Filled.Edit, contentDescription = "Rename")
                            }
                            IconButton(onClick = { toDelete = fp }) {
                                Icon(Icons.Filled.Delete, contentDescription = "Delete",
                                    tint = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                ButtonRow {
                    if (list.size < 5) {
                        SmallButton("Add fingerprint", enabled = link == Link.USB) {
                            dialog = FpDialog.ADD
                        }
                    }
                    SmallButton("Lock") { vm.fido.lock() }
                }
                if (link != Link.USB) {
                    Hint("Connect over USB to enroll a new fingerprint; the sensor is not powered over NFC.")
                }
            }
        }
    }

    when (dialog) {
        FpDialog.UNLOCK -> FormDialog(
            title = "FIDO2 PIN",
            fields = listOf(Field.Text("pin", "FIDO2 PIN", secret = true)),
            confirmLabel = "Unlock",
            onDismiss = { dialog = null },
        ) { v -> vm.fido.unlock(v.chars("pin")); null }

        FpDialog.ADD -> FormDialog(
            title = "Add fingerprint",
            fields = listOf(
                Field.Text("name", "Name", supporting = "For example \"Right thumb\" (max ${st.maxFingerprintName} characters)"),
            ),
            confirmLabel = "Start",
            onDismiss = { dialog = null },
        ) { v ->
            val n = v.text("name").trim()
            if (n.isEmpty()) return@FormDialog "Enter a name"
            if (n.length > st.maxFingerprintName) return@FormDialog "Name is too long"
            vm.fido.enrollFingerprint(n)
            null
        }

        null -> Unit
    }

    toRename?.let { fp ->
        FormDialog(
            title = "Rename fingerprint",
            fields = listOf(Field.Text("name", "Name", fp.name)),
            confirmLabel = "Save",
            onDismiss = { toRename = null },
        ) { v ->
            val n = v.text("name").trim()
            if (n.isEmpty()) return@FormDialog "Enter a name"
            if (n.length > st.maxFingerprintName) return@FormDialog "Name is too long"
            vm.fido.renameFingerprint(fp, n)
            null
        }
    }

    toDelete?.let { fp ->
        ConfirmDialog(
            title = "Delete fingerprint?",
            text = "\"${fp.name}\" will no longer unlock this key.",
            confirmLabel = "Delete",
            onDismiss = { toDelete = null },
        ) { vm.fido.deleteFingerprint(fp) }
    }

    enroll?.let { p ->
        AlertDialog(
            onDismissRequest = {},
            icon = { Icon(Icons.Filled.Fingerprint, contentDescription = null) },
            title = { Text(if (p.done) "Fingerprint enrolled" else if (p.failed != null) "Enrollment failed" else "Enrolling \"${p.name}\"") },
            text = {
                Column {
                    when {
                        p.failed != null -> Text(p.failed, color = MaterialTheme.colorScheme.error)
                        p.done -> Text("\"${p.name}\" is ready to use.")
                        else -> {
                            Text("Touch the sensor repeatedly, lifting your finger between touches. " +
                                "Shift the finger slightly each time so the whole print is captured.")
                            Spacer(Modifier.height(12.dp))
                            val total = p.total
                            val remaining = p.remaining
                            if (total != null && remaining != null && total > 0) {
                                LinearProgressIndicator(
                                    progress = { (total - remaining).toFloat() / total },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(4.dp))
                                Text("$remaining more touch${if (remaining == 1) "" else "es"} needed",
                                    style = MaterialTheme.typography.bodySmall)
                            } else {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                                    Spacer(Modifier.padding(4.dp))
                                    Text("Waiting for the sensor…", style = MaterialTheme.typography.bodySmall)
                                }
                            }
                            p.feedback?.let {
                                Spacer(Modifier.height(8.dp))
                                Text(it, fontWeight = FontWeight.Medium,
                                    color = if (it == "Good sample") MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                if (p.done || p.failed != null) Button(onClick = { vm.fido.dismissEnroll() }) { Text("Done") }
            },
            dismissButton = {
                if (!p.done && p.failed == null) TextButton(onClick = { vm.fido.cancelEnroll() }) { Text("Cancel") }
            },
        )
    }
}
