package net.skorchin.ykmanager.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.yubiotp.Slot
import net.skorchin.ykmanager.yubi.AppViewModel
import net.skorchin.ykmanager.yubi.ApplyResult
import net.skorchin.ykmanager.yubi.KeyInfo
import net.skorchin.ykmanager.yubi.Recipe
import net.skorchin.ykmanager.yubi.RecipePreview
import net.skorchin.ykmanager.yubi.SlotStep
import net.skorchin.ykmanager.yubi.StepStatus
import net.skorchin.ykmanager.yubi.num
import java.text.DateFormat
import java.util.Date

private sealed interface Mode {
    data object List : Mode
    data class Edit(val recipe: Recipe?) : Mode
    data class Detail(val id: String) : Mode
}

@Composable
fun RecipesScreen(vm: AppViewModel) {
    val recipes by vm.recipes.recipes.collectAsStateWithLifecycle()
    var mode by remember { mutableStateOf<Mode>(Mode.List) }

    when (val m = mode) {
        Mode.List -> RecipeList(vm, recipes, onNew = { mode = Mode.Edit(null) }, onOpen = { mode = Mode.Detail(it.id) })
        is Mode.Edit -> RecipeEditor(vm, m.recipe, onDone = { saved ->
            mode = if (saved != null) Mode.Detail(saved.id) else (m.recipe?.let { Mode.Detail(it.id) } ?: Mode.List)
        })
        is Mode.Detail -> {
            val r = recipes.firstOrNull { it.id == m.id }
            if (r == null) mode = Mode.List
            else RecipeDetail(vm, r, onEdit = { mode = Mode.Edit(r) }, onBack = { vm.recipes.clearPreview(); mode = Mode.List })
        }
    }
}

// ----------------------------------------------------------------------
// List
// ----------------------------------------------------------------------

@Composable
private fun RecipeList(vm: AppViewModel, recipes: List<Recipe>, onNew: () -> Unit, onOpen: (Recipe) -> Unit) {
    val log by vm.recipes.log.collectAsStateWithLifecycle()
    var toDelete by remember { mutableStateOf<Recipe?>(null) }
    ScreenColumn {
        Hint("A recipe is a saved set of settings you can apply to many keys one after another: " +
            "preview what would change on the connected key, confirm, then plug in the next key and repeat. " +
            "Recipes are stored encrypted on this phone.")
        Spacer(Modifier.height(4.dp))
        if (recipes.isEmpty()) {
            SectionCard { Hint("No recipes yet.") }
        }
        recipes.forEach { r ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(start = 16.dp, end = 4.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(r.name, fontWeight = FontWeight.Medium)
                        Text(recipeSummary(r), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = { onOpen(r) }) { Text("Open") }
                    IconButton(onClick = { toDelete = r }) {
                        Icon(Icons.Filled.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        ButtonRow {
            SmallButton("New recipe", onClick = onNew)
            if (log.isNotEmpty()) {
                SmallButton("Export batch log (${log.size})") { vm.recipes.exportLog() }
                SmallButton("Clear log") { vm.recipes.clearLog() }
            }
        }
        if (log.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            SectionTitle("Applied this session")
            log.asReversed().take(10).forEach { r ->
                InfoRow("${r.keyName}${r.serial?.let { " #$it" } ?: ""}",
                    "${r.recipeName}: ${r.steps.size - r.failures}/${r.steps.size} ok")
            }
            Hint("Generated secrets (random OTP keys, passwords, management keys) are only in the batch log. Export it before closing the app.")
        }
    }
    toDelete?.let { r ->
        ConfirmDialog("Delete recipe?", "\"${r.name}\" will be removed from this phone.", "Delete",
            onDismiss = { toDelete = null }) { vm.recipes.delete(r) }
    }
}

private fun recipeSummary(r: Recipe): String {
    val parts = mutableListOf<String>()
    if (r.hasConfig) parts += "applications"
    r.slot1?.let { parts += "slot 1" }; if (r.deleteSlot1) parts += "delete slot 1"
    r.slot2?.let { parts += "slot 2" }; if (r.deleteSlot2) parts += "delete slot 2"
    if (r.fidoPin != null) parts += "FIDO2 PIN"
    if (r.oathPassword != null) parts += "OATH password"
    if (r.hasPiv) parts += "PIV credentials"
    if (r.hasPgp) parts += "OpenPGP PINs"
    return if (parts.isEmpty()) "empty recipe" else parts.joinToString(" · ")
}

// ----------------------------------------------------------------------
// Detail: preview + apply
// ----------------------------------------------------------------------

@Composable
private fun RecipeDetail(vm: AppViewModel, r: Recipe, onEdit: () -> Unit, onBack: () -> Unit) {
    val info by vm.core.keyInfo.collectAsStateWithLifecycle()
    val preview by vm.recipes.preview.collectAsStateWithLifecycle()
    val result by vm.recipes.lastResult.collectAsStateWithLifecycle()
    val busy by vm.core.busy.collectAsStateWithLifecycle()
    var confirm by remember { mutableStateOf(false) }
    val k = info
    val p = preview?.takeIf { it.recipeId == r.id && it.serial == k?.serial }

    ScreenColumn {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(r.name, style = MaterialTheme.typography.titleLarge)
                if (r.notes.isNotBlank()) Hint(r.notes)
            }
            IconButton(onClick = onEdit) { Icon(Icons.Filled.Edit, contentDescription = "Edit") }
        }

        SectionCard {
            SectionTitle("Steps (${r.stepCount})")
            Spacer(Modifier.height(4.dp))
            recipeSteps(r).forEach { (t, v) -> InfoRow(t, v) }
            if (r.containsSecrets) Hint("Contains secrets (stored encrypted on this phone).")
        }

        SectionTitle("Target key")
        if (k == null) {
            NeedsKey("the key to program") { vm.core.refreshNow() }
        } else {
            SectionCard {
                InfoRow("Key", k.name)
                InfoRow("Serial", k.serial?.toString() ?: "unknown")
                InfoRow("Firmware", k.version?.toString() ?: "unknown")
                Spacer(Modifier.height(8.dp))
                ButtonRow {
                    SmallButton(if (p == null) "Preview changes" else "Refresh preview", enabled = !busy) { vm.recipes.preview(r) }
                }
            }
            p?.let { pv ->
                SectionTitle("Preview")
                if (pv.items.isEmpty()) Hint("Nothing in this recipe applies to this key.")
                pv.items.forEach { PreviewRow(it) }
                Spacer(Modifier.height(8.dp))
                val n = pv.items.count { it.status == StepStatus.APPLY }
                val w = pv.items.count { it.status == StepStatus.WARN }
                Button(onClick = { confirm = true }, enabled = !busy && (n + w) > 0, modifier = Modifier.fillMaxWidth()) {
                    Text("Apply $n change${if (n == 1) "" else "s"}" + if (w > 0) " ($w with warnings)" else "")
                }
                Hint("Skipped items are already as configured or not supported on this key. After applying, plug in the next key and preview again.")
            }
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = onBack) { Text("Back to recipes") }
    }

    if (confirm && p != null && k != null) {
        val apply = p.items.filter { it.status != StepStatus.SKIP }
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Apply \"${r.name}\"?") },
            text = {
                Column(Modifier.heightIn(max = 380.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${k.name}${k.serial?.let { " · serial $it" } ?: ""}", fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(4.dp))
                    apply.forEach { Text("• ${it.title}: ${it.planned}", style = MaterialTheme.typography.bodyMedium) }
                    if (apply.any { it.title.startsWith("Slot") && it.note?.contains("overwritten") == true }) {
                        Spacer(Modifier.height(6.dp))
                        Text("Existing slot credentials will be overwritten and cannot be recovered.",
                            color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = { Button(onClick = { confirm = false; vm.recipes.apply(r) }) { Text("Apply") } },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
    }

    result?.let { res -> ResultDialog(res) { vm.recipes.clearResult() } }
}

private fun recipeSteps(r: Recipe): List<Pair<String, String>> {
    val out = mutableListOf<Pair<String, String>>()
    r.slot1?.let { out += "Slot 1" to it.summary }; if (r.deleteSlot1) out += "Slot 1" to "delete"
    r.slot2?.let { out += "Slot 2" to it.summary }; if (r.deleteSlot2) out += "Slot 2" to "delete"
    if (r.fidoPin != null) out += "FIDO2 PIN" to "set if none"
    if (r.oathPassword != null) out += "OATH password" to "set if none"
    if (r.pivMgmtKeyHex != null) out += "PIV management key" to (if (r.pivMgmtKeyHex.isEmpty()) "random per key" else "fixed")
    if (r.pivPin != null) out += "PIV PIN" to "set from default"
    if (r.pivPuk != null) out += "PIV PUK" to "set from default"
    if (r.pgpUserPin != null) out += "OpenPGP user PIN" to "set from default"
    if (r.pgpAdminPin != null) out += "OpenPGP admin PIN" to "set from default"
    r.usbCaps?.let { out += "USB applications" to capNames(it) }
    r.nfcCaps?.let { out += "NFC applications" to capNames(it) }
    r.chalrespTimeout?.let { out += "Challenge-response timeout" to "$it s" }
    r.autoEjectTimeout?.let { out += "Auto-eject timeout" to "$it s" }
    return out
}

private fun capNames(bits: Int) = Capability.values().filter { bits and it.bit != 0 }.joinToString(", ") { capLabel(it) }.ifEmpty { "none" }

@Composable
private fun PreviewRow(it: net.skorchin.ykmanager.yubi.PreviewItem) {
    val (icon, tint) = when (it.status) {
        StepStatus.APPLY -> Icons.Filled.Check to MaterialTheme.colorScheme.primary
        StepStatus.WARN -> Icons.Filled.Warning to MaterialTheme.colorScheme.tertiary
        StepStatus.SKIP -> Icons.Filled.Close to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(
        containerColor = if (it.status == StepStatus.SKIP) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.surface)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
            Icon(icon, contentDescription = it.status.name, tint = tint, modifier = Modifier.size(20.dp).padding(top = 2.dp))
            Column(Modifier.padding(start = 10.dp)) {
                Text(it.title, fontWeight = FontWeight.Medium)
                Text("Now: ${it.current}", style = MaterialTheme.typography.bodySmall)
                if (it.status != StepStatus.SKIP) Text("After: ${it.planned}", style = MaterialTheme.typography.bodySmall)
                it.note?.let { n -> Text(n, style = MaterialTheme.typography.bodySmall, color = tint) }
            }
        }
    }
}

@Composable
private fun ResultDialog(res: ApplyResult, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (res.failures == 0) "Recipe applied" else "Applied with ${res.failures} failure${if (res.failures == 1) "" else "s"}") },
        text = {
            Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("${res.keyName}${res.serial?.let { " · serial $it" } ?: ""} · ${DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(res.at))}",
                    style = MaterialTheme.typography.bodySmall)
                res.steps.forEach { s ->
                    Row(verticalAlignment = Alignment.Top) {
                        Icon(if (s.ok) Icons.Filled.Check else Icons.Filled.Close, contentDescription = null,
                            tint = if (s.ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(18.dp))
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(s.title, fontWeight = FontWeight.Medium, style = MaterialTheme.typography.bodyMedium)
                            Text(s.message, style = MaterialTheme.typography.bodySmall)
                            s.secrets?.let { Text(it, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold) }
                        }
                    }
                }
                if (res.steps.any { it.secrets != null }) {
                    HorizontalDivider(Modifier.padding(vertical = 4.dp))
                    Text("Generated values above are recorded in the batch log (Recipes → Export batch log). They cannot be read back from the key.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Text("Ready for the next key: unplug this one, plug in the next and tap Preview changes.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { Button(onClick = onDismiss) { Text("OK") } },
    )
}

// ----------------------------------------------------------------------
// Editor
// ----------------------------------------------------------------------

@Composable
private fun RecipeEditor(vm: AppViewModel, existing: Recipe?, onDone: (Recipe?) -> Unit) {
    val info by vm.core.keyInfo.collectAsStateWithLifecycle()
    var name by remember { mutableStateOf(existing?.name ?: "") }
    var notes by remember { mutableStateOf(existing?.notes ?: "") }

    // Applications
    var cfgOn by remember { mutableStateOf(existing?.hasConfig ?: false) }
    var usbOn by remember { mutableStateOf(existing?.usbCaps != null) }
    var usbCaps by remember { mutableStateOf(existing?.usbCaps ?: ALL_CAPS) }
    var nfcOn by remember { mutableStateOf(existing?.nfcCaps != null) }
    var nfcCaps by remember { mutableStateOf(existing?.nfcCaps ?: ALL_CAPS) }
    var cr by remember { mutableStateOf(existing?.chalrespTimeout?.toString() ?: "") }
    var ae by remember { mutableStateOf(existing?.autoEjectTimeout?.toString() ?: "") }
    var lock by remember { mutableStateOf(existing?.lockCodeHex ?: "") }

    // Slots
    var slot1 by remember { mutableStateOf(existing?.slot1) }
    var slot2 by remember { mutableStateOf(existing?.slot2) }
    var del1 by remember { mutableStateOf(existing?.deleteSlot1 ?: false) }
    var del2 by remember { mutableStateOf(existing?.deleteSlot2 ?: false) }
    var curAcc by remember { mutableStateOf(existing?.currentAccessCodeHex ?: "") }
    var slotDialog by remember { mutableStateOf<Pair<Slot, Prog>?>(null) }
    val otpOut by vm.settings.otpOutput.collectAsStateWithLifecycle()
    var pickKind by remember { mutableStateOf<Slot?>(null) }

    // Credentials
    var fidoOn by remember { mutableStateOf(existing?.fidoPin != null) }
    var fidoPin by remember { mutableStateOf(existing?.fidoPin ?: "") }
    var oathOn by remember { mutableStateOf(existing?.oathPassword != null) }
    var oathPw by remember { mutableStateOf(existing?.oathPassword ?: "") }
    var pivPinOn by remember { mutableStateOf(existing?.pivPin != null) }
    var pivPin by remember { mutableStateOf(existing?.pivPin ?: "") }
    var pivPukOn by remember { mutableStateOf(existing?.pivPuk != null) }
    var pivPuk by remember { mutableStateOf(existing?.pivPuk ?: "") }
    var pivMkOn by remember { mutableStateOf(existing?.pivMgmtKeyHex != null) }
    var pivMkRandom by remember { mutableStateOf(existing?.pivMgmtKeyHex?.isEmpty() ?: true) }
    var pivMk by remember { mutableStateOf(existing?.pivMgmtKeyHex ?: "") }
    var pgpUserOn by remember { mutableStateOf(existing?.pgpUserPin != null) }
    var pgpUser by remember { mutableStateOf(existing?.pgpUserPin ?: "") }
    var pgpAdminOn by remember { mutableStateOf(existing?.pgpAdminPin != null) }
    var pgpAdmin by remember { mutableStateOf(existing?.pgpAdminPin ?: "") }
    var error by remember { mutableStateOf<String?>(null) }

    ScreenColumn {
        Text(if (existing == null) "New recipe" else "Edit recipe", style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(notes, { notes = it }, label = { Text("Notes (optional)") }, modifier = Modifier.fillMaxWidth())
        Hint("Turn on only the parts you want. Everything else on the key is left untouched. Parts a key does not support are skipped automatically.")

        // ---- OTP slots
        SectionCard {
            SectionTitle("OTP slots")
            Spacer(Modifier.height(4.dp))
            listOf(Slot.ONE to slot1, Slot.TWO to slot2).forEach { (slot, step) ->
                val del = if (slot == Slot.ONE) del1 else del2
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Slot ${slot.num}", fontWeight = FontWeight.Medium)
                        Hint(step?.summary ?: if (del) "Delete" else "Leave unchanged")
                    }
                    if (step != null || del) {
                        IconButton(onClick = {
                            if (slot == Slot.ONE) { slot1 = null; del1 = false } else { slot2 = null; del2 = false }
                        }) { Icon(Icons.Filled.Close, contentDescription = "Clear") }
                    }
                }
                ButtonRow {
                    SmallButton(if (step == null) "Program…" else "Change…") { pickKind = slot }
                    if (!del && step == null) SmallButton("Delete slot") {
                        if (slot == Slot.ONE) del1 = true else del2 = true
                    }
                }
                Spacer(Modifier.height(6.dp))
            }
            if (slot1 != null || slot2 != null || del1 || del2) {
                OutlinedTextField(curAcc, { curAcc = it }, label = { Text("Current access code on the keys (hex, if set)") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
            }
        }

        // ---- Credentials
        SectionCard {
            SectionTitle("PINs and passwords")
            Hint("Applied only where the key still has factory defaults (or no PIN/password yet). Keys already personalised are skipped.")
            Spacer(Modifier.height(4.dp))
            ToggleField("FIDO2 PIN", fidoOn, { fidoOn = it }, fidoPin, { fidoPin = it }, "PIN (4+ characters)")
            ToggleField("OATH password", oathOn, { oathOn = it }, oathPw, { oathPw = it }, "Password")
            ToggleField("PIV PIN", pivPinOn, { pivPinOn = it }, pivPin, { pivPin = it }, "PIN (6-8 characters)")
            ToggleField("PIV PUK", pivPukOn, { pivPukOn = it }, pivPuk, { pivPuk = it }, "PUK (6-8 characters)")
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("PIV management key", Modifier.weight(1f))
                Switch(pivMkOn, { pivMkOn = it })
            }
            if (pivMkOn) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) { Text("Random key per key", style = MaterialTheme.typography.bodyMedium); Hint("Recorded in the batch log") }
                    Switch(pivMkRandom, { pivMkRandom = it })
                }
                if (!pivMkRandom) OutlinedTextField(pivMk, { pivMk = it }, label = { Text("Management key (hex: 48 digits TDES/AES192, 32 AES128, 64 AES256)") },
                    singleLine = true, modifier = Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation())
            }
            ToggleField("OpenPGP user PIN", pgpUserOn, { pgpUserOn = it }, pgpUser, { pgpUser = it }, "User PIN (6+ characters)")
            ToggleField("OpenPGP admin PIN", pgpAdminOn, { pgpAdminOn = it }, pgpAdmin, { pgpAdmin = it }, "Admin PIN (8+ characters)")
        }

        // ---- Applications
        SectionCard {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                SectionTitle("Applications and timeouts"); Spacer(Modifier.weight(1f)); Switch(cfgOn, { cfgOn = it })
            }
            if (cfgOn) {
                Hint("Applied last, because changing USB applications restarts the key. On YubiKey 4 / NEO this becomes a USB mode.")
                Spacer(Modifier.height(6.dp))
                CapPicker("USB applications", usbOn, { usbOn = it }, usbCaps, { usbCaps = it }, info)
                CapPicker("NFC applications", nfcOn, { nfcOn = it }, nfcCaps, { nfcCaps = it }, info)
                OutlinedTextField(cr, { cr = it.filter(Char::isDigit) }, label = { Text("Challenge-response timeout (s, empty = unchanged)") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(ae, { ae = it.filter(Char::isDigit) }, label = { Text("Auto-eject timeout (s, empty = unchanged)") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(lock, { lock = it }, label = { Text("Lock code if the keys are locked (hex, optional)") },
                    singleLine = true, modifier = Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation())
            }
        }

        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                val err = validate(name, fidoOn, fidoPin, oathOn, oathPw, pivPinOn, pivPin, pivPukOn, pivPuk, pivMkOn, pivMkRandom, pivMk,
                    pgpUserOn, pgpUser, pgpAdminOn, pgpAdmin, cfgOn, usbOn, usbCaps, lock)
                if (err != null) { error = err; return@Button }
                val r = Recipe(
                    id = existing?.id ?: java.util.UUID.randomUUID().toString(),
                    name = name.trim(), notes = notes.trim(), createdAt = existing?.createdAt ?: System.currentTimeMillis(),
                    usbCaps = if (cfgOn && usbOn) usbCaps else null,
                    nfcCaps = if (cfgOn && nfcOn) nfcCaps else null,
                    chalrespTimeout = if (cfgOn) cr.toIntOrNull() else null,
                    autoEjectTimeout = if (cfgOn) ae.toIntOrNull() else null,
                    lockCodeHex = if (cfgOn) lock.trim() else "",
                    slot1 = slot1, slot2 = slot2, deleteSlot1 = del1 && slot1 == null, deleteSlot2 = del2 && slot2 == null,
                    currentAccessCodeHex = curAcc.trim(),
                    fidoPin = if (fidoOn) fidoPin else null,
                    oathPassword = if (oathOn) oathPw else null,
                    pivPin = if (pivPinOn) pivPin else null,
                    pivPuk = if (pivPukOn) pivPuk else null,
                    pivMgmtKeyHex = if (pivMkOn) (if (pivMkRandom) "" else pivMk.trim()) else null,
                    pgpUserPin = if (pgpUserOn) pgpUser else null,
                    pgpAdminPin = if (pgpAdminOn) pgpAdmin else null,
                )
                vm.recipes.save(r)
                onDone(r)
            }) { Text("Save recipe") }
            OutlinedButton(onClick = { onDone(null) }) { Text("Cancel") }
        }
    }

    pickKind?.let { slot ->
        AlertDialog(
            onDismissRequest = { pickKind = null },
            title = { Text("Slot ${slot.num}: credential type") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Prog.values().forEach { k ->
                        TextButton(onClick = { pickKind = null; slotDialog = slot to k }, modifier = Modifier.fillMaxWidth()) { Text(k.title) }
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { pickKind = null }) { Text("Cancel") } },
        )
    }

    slotDialog?.let { (slot, kind) ->
        FormDialog("${kind.title} · slot ${slot.num}", slotProgramFields(kind, null, false, forRecipe = true, defaultEnter = otpOut.appendEnter, output = otpOut), "Add to recipe",
            onDismiss = { slotDialog = null }) { v ->
            val (err, parsed) = parseSlotProgram(kind, v)
            if (err != null || parsed == null) return@FormDialog err ?: "Invalid input"
            val step = SlotStep(kind.name, parsed.first, parsed.second.appendEnter, parsed.second.newAccessCodeHex,
                otpOut)
            if (slot == Slot.ONE) { slot1 = step; del1 = false } else { slot2 = step; del2 = false }
            null
        }
    }
}

private val ALL_CAPS = Capability.values().fold(0) { a, c -> a or c.bit }

private fun validate(
    name: String, fidoOn: Boolean, fidoPin: String, oathOn: Boolean, oathPw: String,
    pivPinOn: Boolean, pivPin: String, pivPukOn: Boolean, pivPuk: String,
    pivMkOn: Boolean, pivMkRandom: Boolean, pivMk: String,
    pgpUserOn: Boolean, pgpUser: String, pgpAdminOn: Boolean, pgpAdmin: String,
    cfgOn: Boolean, usbOn: Boolean, usbCaps: Int, lock: String,
): String? {
    if (name.isBlank()) return "Give the recipe a name"
    if (fidoOn && fidoPin.length < 4) return "FIDO2 PIN must be at least 4 characters"
    if (oathOn && oathPw.isEmpty()) return "Enter an OATH password"
    if (pivPinOn && pivPin.length !in 6..8) return "PIV PIN must be 6-8 characters"
    if (pivPukOn && pivPuk.length !in 6..8) return "PIV PUK must be 6-8 characters"
    if (pivMkOn && !pivMkRandom) {
        val h = pivMk.trim()
        if (h.length !in listOf(32, 48, 64) || !h.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return "Management key must be 32, 48 or 64 hex digits"
    }
    if (pgpUserOn && pgpUser.length < 6) return "OpenPGP user PIN must be at least 6 characters"
    if (pgpAdminOn && pgpAdmin.length < 8) return "OpenPGP admin PIN must be at least 8 characters"
    if (cfgOn && usbOn && usbCaps == 0) return "At least one USB application must stay enabled"
    if (cfgOn && lock.isNotBlank() && (lock.trim().length != 32 || !lock.trim().all { it.isDigit() || it.lowercaseChar() in 'a'..'f' })) return "Lock code must be 32 hex digits"
    return null
}

@Composable
private fun ToggleField(label: String, on: Boolean, onToggle: (Boolean) -> Unit, value: String, onValue: (String) -> Unit, hint: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(on, onToggle)
    }
    if (on) {
        OutlinedTextField(value, onValue, label = { Text(hint) }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            visualTransformation = PasswordVisualTransformation())
        Spacer(Modifier.height(4.dp))
    }
}

@Composable
private fun CapPicker(label: String, on: Boolean, onToggle: (Boolean) -> Unit, caps: Int, onCaps: (Int) -> Unit, info: KeyInfo?) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(on, onToggle)
    }
    if (on) {
        Capability.values().forEach { c ->
            Row(Modifier.fillMaxWidth().padding(start = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(capLabel(c), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                Switch(caps and c.bit != 0, { onCaps(if (it) caps or c.bit else caps and c.bit.inv()) })
            }
        }
        Hint("Applications a particular key does not have are ignored when applying.")
        Spacer(Modifier.height(4.dp))
    }
}
