package net.skorchin.ykmanager.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Nfc
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.management.FormFactor

fun capabilityNames(bits: Int): String =
    Capability.entries.filter { bits and it.bit != 0 }.joinToString { capLabel(it) }.ifEmpty { "none" }

fun capLabel(c: Capability): String = when (c) {
    Capability.OTP -> "Yubico OTP"
    Capability.U2F -> "FIDO U2F"
    Capability.FIDO2 -> "FIDO2"
    Capability.OATH -> "OATH"
    Capability.PIV -> "PIV"
    Capability.OPENPGP -> "OpenPGP"
    Capability.HSMAUTH -> "YubiHSM Auth"
    Capability.FIDO_CCID -> "FIDO over smart card"
}

fun formFactorName(f: FormFactor): String = when (f) {
    FormFactor.UNKNOWN -> "YubiKey"
    FormFactor.USB_A_KEYCHAIN -> "YubiKey (USB-A keychain)"
    FormFactor.USB_A_NANO -> "YubiKey Nano (USB-A)"
    FormFactor.USB_C_KEYCHAIN -> "YubiKey (USB-C keychain)"
    FormFactor.USB_C_NANO -> "YubiKey Nano (USB-C)"
    FormFactor.USB_C_LIGHTNING -> "YubiKey 5Ci (USB-C / Lightning)"
    FormFactor.USB_A_BIO -> "YubiKey Bio (USB-A)"
    FormFactor.USB_C_BIO -> "YubiKey Bio (USB-C)"
}

@Composable
fun ScreenColumn(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        content = content,
    )
}

@Composable
fun SectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
fun SectionCard(content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), content = content)
    }
}

@Composable
fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp)
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(140.dp),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/** Shown on feature screens when there is no data yet. */
@Composable
fun NeedsKey(what: String, onRead: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(Icons.Filled.Nfc, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            Text(
                "Plug in your YubiKey, or tap Read and hold it against the phone, to load $what.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(12.dp))
            Button(onClick = onRead) { Text("Read YubiKey") }
        }
    }
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun ButtonRow(content: @Composable () -> Unit) {
    androidx.compose.foundation.layout.FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) { content() }
}

@Composable
fun SmallButton(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, enabled = enabled) { Text(text) }
}

// ----------------------------------------------------------------------
// Generic form dialog
// ----------------------------------------------------------------------

sealed class Field(val key: String) {
    class Text(
        key: String,
        val label: String,
        val initial: String = "",
        val secret: Boolean = false,
        val numeric: Boolean = false,
        val supporting: String? = null,
    ) : Field(key)

    class Check(key: String, val label: String, val initial: Boolean = false) : Field(key)

    class Choice(key: String, val label: String, val options: List<String>, val initial: Int = 0) : Field(key)

    class Note(val text: String) : Field("_note_${text.hashCode()}")
}

class FormValues(private val map: Map<String, String>) {
    fun text(k: String): String = map[k].orEmpty()
    fun chars(k: String): CharArray = text(k).toCharArray()
    fun check(k: String): Boolean = map[k] == "true"
    fun choice(k: String): Int = map[k]?.toIntOrNull() ?: 0
    fun int(k: String, default: Int): Int = text(k).trim().toIntOrNull() ?: default
}

/**
 * A dialog showing [fields]. [onConfirm] returns an error message to keep the
 * dialog open, or null to close it.
 */
@Composable
fun FormDialog(
    title: String,
    fields: List<Field>,
    confirmLabel: String = "OK",
    destructive: Boolean = false,
    onDismiss: () -> Unit,
    onConfirm: (FormValues) -> String?,
) {
    val values = remember {
        mutableStateMapOf<String, String>().apply {
            fields.forEach {
                when (it) {
                    is Field.Text -> put(it.key, it.initial)
                    is Field.Check -> put(it.key, it.initial.toString())
                    is Field.Choice -> put(it.key, it.initial.toString())
                    is Field.Note -> Unit
                }
            }
        }
    }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                fields.forEach { f ->
                    when (f) {
                        is Field.Text -> OutlinedTextField(
                            value = values[f.key].orEmpty(),
                            onValueChange = { values[f.key] = it },
                            label = { Text(f.label) },
                            singleLine = true,
                            visualTransformation = if (f.secret) PasswordVisualTransformation()
                            else androidx.compose.ui.text.input.VisualTransformation.None,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = when {
                                    f.secret && f.numeric -> KeyboardType.NumberPassword
                                    f.secret -> KeyboardType.Password
                                    f.numeric -> KeyboardType.Number
                                    else -> KeyboardType.Text
                                }
                            ),
                            supportingText = f.supporting?.let { s -> { Text(s) } },
                            modifier = Modifier.fillMaxWidth(),
                        )

                        is Field.Check -> Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { values[f.key] = (values[f.key] != "true").toString() },
                        ) {
                            Checkbox(
                                checked = values[f.key] == "true",
                                onCheckedChange = { values[f.key] = it.toString() },
                            )
                            Text(f.label, style = MaterialTheme.typography.bodyMedium)
                        }

                        is Field.Choice -> ChoiceField(
                            label = f.label,
                            options = f.options,
                            selected = values[f.key]?.toIntOrNull() ?: 0,
                            onSelect = { values[f.key] = it.toString() },
                        )

                        is Field.Note -> Hint(f.text)
                    }
                }
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                error = try {
                    onConfirm(FormValues(values.toMap()))
                } catch (e: Exception) {
                    e.message ?: "Invalid input"
                }
                if (error == null) onDismiss()
            }) {
                Text(
                    confirmLabel,
                    color = if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                )
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
fun ChoiceField(label: String, options: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        OutlinedTextField(
            value = options.getOrElse(selected) { "" },
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { Icon(Icons.Filled.ArrowDropDown, contentDescription = null) },
            modifier = Modifier.fillMaxWidth(),
        )
        // Transparent overlay so the whole field opens the menu.
        Box(
            modifier = Modifier
                .matchParentSize()
                .clickable { open = true }
        )
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEachIndexed { i, o ->
                DropdownMenuItem(text = { Text(o) }, onClick = { onSelect(i); open = false })
            }
        }
    }
}

@Composable
fun ConfirmDialog(
    title: String,
    text: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            TextButton(onClick = { onConfirm(); onDismiss() }) {
                Text(confirmLabel, color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/**
 * Destructive confirmation that stays disabled until the user types [keyword]
 * exactly (case-sensitive). Used for factory resets.
 */
@Composable
fun TypedConfirmDialog(
    title: String,
    text: String,
    keyword: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    var typed by remember { mutableStateOf("") }
    val ok = typed == keyword
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(text)
                Spacer(Modifier.height(12.dp))
                Text("Type $keyword to confirm:", fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = typed,
                    onValueChange = { typed = it },
                    singleLine = true,
                    placeholder = { Text(keyword) },
                    isError = typed.isNotEmpty() && !ok,
                    supportingText = {
                        if (typed.isNotEmpty() && !ok) Text("Must match $keyword exactly (upper case)")
                    },
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Characters,
                        autoCorrectEnabled = false,
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(); onDismiss() }, enabled = ok) {
                Text(confirmLabel, color = if (ok) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Require matching new PIN fields. */
fun requireMatch(values: FormValues, a: String, b: String, minLen: Int = 1): String? {
    val x = values.text(a)
    return when {
        x.length < minLen -> "Must be at least $minLen characters"
        x != values.text(b) -> "The new values do not match"
        else -> null
    }
}
