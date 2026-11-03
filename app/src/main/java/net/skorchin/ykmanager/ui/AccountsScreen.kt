package net.skorchin.ykmanager.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.skorchin.ykmanager.yubi.AppViewModel
import net.skorchin.ykmanager.yubi.NewAccount
import net.skorchin.ykmanager.yubi.OathEntry
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.yubico.yubikit.oath.HashAlgorithm
import com.yubico.yubikit.oath.OathType
import kotlinx.coroutines.delay

private enum class AccDialog { ADD, URI, SET_PW, CHANGE_PW, REMOVE_PW, UNLOCK }

@Composable
fun AccountsScreen(vm: AppViewModel) {
    val st by vm.oath.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var dialog by remember { mutableStateOf<AccDialog?>(null) }
    var scannedUri by remember { mutableStateOf("") }
    var renameEntry by remember { mutableStateOf<OathEntry?>(null) }
    var deleteEntry by remember { mutableStateOf<OathEntry?>(null) }
    var filter by remember { mutableStateOf("") }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) { while (true) { now = System.currentTimeMillis(); delay(500) } }

    val scanner = androidx.activity.compose.rememberLauncherForActivityResult(ScanContract()) { result ->
        val text = result.contents ?: return@rememberLauncherForActivityResult
        if (text.startsWith("otpauth://")) { scannedUri = text; dialog = AccDialog.URI }
        else vm.core.error("That QR code is not an otpauth:// account")
    }

    ScreenColumn {
        if (!st.loaded) {
            NeedsKey("your accounts") { vm.core.refreshNow() }
            return@ScreenColumn
        }
        if (st.locked) {
            SectionCard {
                SectionTitle("Accounts are password protected")
                Spacer(Modifier.height(8.dp))
                SmallButton("Unlock") { dialog = AccDialog.UNLOCK }
            }
        } else {
            ButtonRow {
                SmallButton("Scan QR code") {
                    scanner.launch(
                        ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            .setPrompt("Scan the account's QR code").setBeepEnabled(false).setOrientationLocked(false)
                    )
                }
                SmallButton("Add manually") { dialog = AccDialog.ADD }
                SmallButton("Paste URI") { scannedUri = ""; dialog = AccDialog.URI }
            }
            if (st.entries.size > 6) OutlinedTextField(
                value = filter, onValueChange = { filter = it }, label = { Text("Search") },
                singleLine = true, modifier = Modifier.fillMaxWidth(),
            )
            val shown = st.entries
                .filter { filter.isBlank() || "${it.issuer} ${it.name}".contains(filter, ignoreCase = true) }
                .sortedBy { (it.issuer ?: it.name).lowercase() }
            if (shown.isEmpty()) Hint("No accounts yet. Scan a QR code from a website's two-factor setup page to add one.")
            shown.forEach { e ->
                AccountRow(
                    e, now,
                    onCalculate = { vm.oath.calculate(e) },
                    onCopy = { e.code?.value?.let { copyToClipboard(context, "Code", it) } },
                    onRename = { renameEntry = e },
                    onDelete = { deleteEntry = e },
                )
            }
        }

        SectionCard {
            SectionTitle("OATH application")
            Spacer(Modifier.height(4.dp))
            st.version?.let { InfoRow("Version", it.toString()) }
            InfoRow("Accounts", if (st.locked) "locked" else st.entries.size.toString())
            InfoRow("Password", if (st.hasPassword) "set" else "not set")
            Spacer(Modifier.height(8.dp))
            ButtonRow {
                if (!st.hasPassword) SmallButton("Set password") { dialog = AccDialog.SET_PW }
                else {
                    SmallButton("Change password") { dialog = AccDialog.CHANGE_PW }
                    SmallButton("Remove password") { dialog = AccDialog.REMOVE_PW }
                    SmallButton("Forget remembered") { vm.oath.forgetPassword() }
                }
            }
        }
    }

    when (dialog) {
        AccDialog.ADD -> FormDialog(
            "Add account",
            listOf(
                Field.Text("issuer", "Issuer (e.g. GitHub)"),
                Field.Text("name", "Account name"),
                Field.Text("secret", "Secret key (base32)", secret = true),
                Field.Choice("type", "Type", listOf("TOTP (time-based)", "HOTP (counter-based)")),
                Field.Choice("alg", "Algorithm", listOf("SHA1", "SHA256", "SHA512")),
                Field.Choice("digits", "Digits", listOf("6", "7", "8")),
                Field.Text("period", "Period (seconds)", "30", numeric = true),
                Field.Check("touch", "Require touch"),
            ),
            confirmLabel = "Add",
            onDismiss = { dialog = null },
        ) { v ->
            if (v.text("name").isBlank()) return@FormDialog "Enter an account name"
            if (v.text("secret").isBlank()) return@FormDialog "Enter the secret key"
            vm.oath.add(
                NewAccount(
                    issuer = v.text("issuer").trim(), name = v.text("name").trim(),
                    secretBase32 = v.text("secret"),
                    type = if (v.choice("type") == 0) OathType.TOTP else OathType.HOTP,
                    algorithm = listOf(HashAlgorithm.SHA1, HashAlgorithm.SHA256, HashAlgorithm.SHA512)[v.choice("alg")],
                    digits = 6 + v.choice("digits"), period = v.int("period", 30),
                    requireTouch = v.check("touch"),
                )
            ); null
        }

        AccDialog.URI -> FormDialog(
            "Add from otpauth:// URI",
            listOf(
                Field.Text("uri", "otpauth:// URI", scannedUri),
                Field.Check("touch", "Require touch"),
            ),
            confirmLabel = "Add",
            onDismiss = { dialog = null },
        ) { v ->
            if (!v.text("uri").trim().startsWith("otpauth://")) return@FormDialog "The URI must start with otpauth://"
            vm.oath.addFromUri(v.text("uri"), v.check("touch")); null
        }

        AccDialog.UNLOCK -> FormDialog(
            "Unlock accounts",
            listOf(Field.Text("pw", "Password", secret = true), Field.Check("rem", "Remember on this phone")),
            confirmLabel = "Unlock",
            onDismiss = { dialog = null },
        ) { v -> vm.oath.unlock(v.chars("pw"), v.check("rem")); null }

        AccDialog.SET_PW -> FormDialog(
            "Set password",
            listOf(Field.Text("new", "New password", secret = true), Field.Text("rep", "Repeat password", secret = true)),
            confirmLabel = "Set",
            onDismiss = { dialog = null },
        ) { v -> requireMatch(v, "new", "rep") ?: run { vm.oath.setPassword(null, v.chars("new")); null } }

        AccDialog.CHANGE_PW -> FormDialog(
            "Change password",
            listOf(
                Field.Text("cur", "Current password", secret = true),
                Field.Text("new", "New password", secret = true),
                Field.Text("rep", "Repeat password", secret = true),
            ),
            confirmLabel = "Change",
            onDismiss = { dialog = null },
        ) { v -> requireMatch(v, "new", "rep") ?: run { vm.oath.setPassword(v.chars("cur"), v.chars("new")); null } }

        AccDialog.REMOVE_PW -> FormDialog(
            "Remove password",
            listOf(Field.Text("cur", "Current password", secret = true)),
            confirmLabel = "Remove", destructive = true,
            onDismiss = { dialog = null },
        ) { v -> vm.oath.removePassword(v.chars("cur")); null }

        null -> Unit
    }

    renameEntry?.let { e ->
        FormDialog(
            "Rename account",
            listOf(Field.Text("issuer", "Issuer", e.issuer.orEmpty()), Field.Text("name", "Account name", e.name)),
            confirmLabel = "Save",
            onDismiss = { renameEntry = null },
        ) { v ->
            if (v.text("name").isBlank()) return@FormDialog "Enter an account name"
            vm.oath.rename(e, v.text("issuer").trim(), v.text("name").trim()); null
        }
    }
    deleteEntry?.let { e ->
        ConfirmDialog(
            "Delete account?",
            "${e.issuer?.let { "$it: " } ?: ""}${e.name} will be removed from the YubiKey. Make sure you have another way to sign in.",
            "Delete",
            onDismiss = { deleteEntry = null },
        ) { vm.oath.delete(e) }
    }
}

@Composable
private fun AccountRow(
    e: OathEntry, now: Long,
    onCalculate: () -> Unit, onCopy: () -> Unit, onRename: () -> Unit, onDelete: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    val code = e.code
    val valid = code != null && (!e.isTotp || code.validUntil > now)
    Card(Modifier.fillMaxWidth().clickable { if (valid) onCopy() else onCalculate() }) {
        Row(Modifier.padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(e.issuer ?: e.name, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                if (e.issuer != null) Text(e.name, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(4.dp))
                if (valid) Text(
                    code!!.value.chunked(if (code.value.length == 8) 4 else 3).joinToString(" "),
                    fontFamily = FontFamily.Monospace, fontSize = 26.sp, color = MaterialTheme.colorScheme.primary,
                ) else Row(verticalAlignment = Alignment.CenterVertically) {
                    if (e.credential.isTouchRequired) Icon(Icons.Filled.TouchApp, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(
                        if (e.credential.isTouchRequired) "Tap to generate (touch required)" else "Tap to generate",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
            if (valid && e.isTotp) {
                val period = e.credential.period * 1000f
                val left = ((code!!.validUntil - now) / period).coerceIn(0f, 1f)
                Box(contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(progress = { left }, modifier = Modifier.size(28.dp), strokeWidth = 3.dp)
                    Text("${((code.validUntil - now) / 1000).coerceAtLeast(0)}", style = MaterialTheme.typography.labelSmall)
                }
            }
            if (valid) IconButton(onClick = onCopy) { Icon(Icons.Filled.ContentCopy, "Copy") }
            Box {
                IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, "More") }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text("Generate code") }, onClick = { menu = false; onCalculate() })
                    DropdownMenuItem(text = { Text("Rename") }, onClick = { menu = false; onRename() })
                    DropdownMenuItem(text = { Text("Delete") }, onClick = { menu = false; onDelete() })
                }
            }
        }
    }
}
