package net.skorchin.ykmanager.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import net.skorchin.ykmanager.yubi.InfoSection
import net.skorchin.ykmanager.yubi.Passkey
import net.skorchin.ykmanager.yubi.PasskeyInfo

/**
 * Everything the YubiKey reports about one discoverable credential: relying party,
 * user account, credential ID, protection policy, large-blob state and public key.
 */
@Composable
fun PasskeyDetailsDialog(
    passkey: Passkey,
    onDelete: () -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val sections = remember(passkey) { PasskeyInfo.describe(passkey) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Column {
                Text(passkey.rpId, fontWeight = FontWeight.SemiBold)
                Text(
                    listOfNotNull(passkey.displayName?.takeIf { it != passkey.userName }, passkey.userName).joinToString(" · "),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                sections.forEachIndexed { i, section ->
                    if (i > 0) HorizontalDivider(Modifier.padding(vertical = 10.dp))
                    DetailSection(section, onCopy = { label, value -> copyToClipboard(context, label, value) })
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
        dismissButton = {
            Row {
                TextButton(onClick = {
                    copyToClipboard(context, "Passkey ${passkey.rpId}", asText(passkey, sections))
                }) { Text("Copy all") }
                TextButton(onClick = { onDismiss(); onDelete() }) {
                    Text("Delete", color = MaterialTheme.colorScheme.error)
                }
            }
        },
    )
}

@Composable
private fun DetailSection(section: InfoSection, onCopy: (String, String) -> Unit) {
    Text(
        section.title,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(bottom = 4.dp),
    )
    section.items.forEach { item ->
        Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Text(item.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                SelectionContainer {
                    Text(
                        item.value,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = if (item.copyable) FontFamily.Monospace else FontFamily.Default,
                    )
                }
                item.note?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (item.copyable) {
                IconButton(onClick = { onCopy(item.label, item.value) }, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy ${item.label}", modifier = Modifier.size(18.dp))
                }
            }
        }
    }
    Spacer(Modifier.height(2.dp))
}

/** Plain-text rendering for "Copy all" (no notes, one `label: value` per line). */
private fun asText(p: Passkey, sections: List<InfoSection>): String = buildString {
    appendLine("Passkey on YubiKey – ${p.rpId} (${p.userName})")
    for (s in sections) {
        appendLine()
        appendLine("[${s.title}]")
        for (i in s.items) appendLine("${i.label}: ${i.value}")
    }
}.trimEnd()
