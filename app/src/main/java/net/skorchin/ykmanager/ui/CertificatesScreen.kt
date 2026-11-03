package net.skorchin.ykmanager.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.skorchin.ykmanager.yubi.AppViewModel
import net.skorchin.ykmanager.yubi.CertOutput
import net.skorchin.ykmanager.yubi.PivFeature
import net.skorchin.ykmanager.yubi.PivSlotView
import com.yubico.yubikit.piv.KeyType
import com.yubico.yubikit.piv.ManagementKeyType
import com.yubico.yubikit.piv.PinPolicy
import com.yubico.yubikit.piv.Slot
import com.yubico.yubikit.piv.TouchPolicy
import java.text.DateFormat

private enum class PivDialog { CHANGE_PIN, CHANGE_PUK, UNBLOCK, MGMT_KEY, RETRIES }

private val KEY_TYPES = listOf(KeyType.ECCP256, KeyType.ECCP384, KeyType.RSA2048, KeyType.RSA3072, KeyType.RSA4096)
private val PIN_POLICIES = listOf(PinPolicy.DEFAULT, PinPolicy.NEVER, PinPolicy.ONCE, PinPolicy.ALWAYS)
private val TOUCH_POLICIES = listOf(TouchPolicy.DEFAULT, TouchPolicy.NEVER, TouchPolicy.ALWAYS, TouchPolicy.CACHED)

private fun policyLabel(e: Enum<*>) = e.name.lowercase().replaceFirstChar { it.uppercase() }

@Composable
fun CertificatesScreen(vm: AppViewModel) {
    val st by vm.piv.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var dialog by remember { mutableStateOf<PivDialog?>(null) }
    var generateFor by remember { mutableStateOf<Slot?>(null) }
    var importFor by remember { mutableStateOf<Slot?>(null) }
    var importBytes by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }
    var deleteFor by remember { mutableStateOf<PivSlotView?>(null) }
    var showRetired by remember { mutableStateOf(vm.piv.showRetired) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) { importFor = null; return@rememberLauncherForActivityResult }
        val bytes = runCatching { context.contentResolver.openInputStream(uri)?.use { it.readBytes() } }.getOrNull()
        if (bytes == null) { vm.core.error("Could not read the file"); importFor = null }
        else importBytes = (uri.lastPathSegment?.substringAfterLast('/') ?: "file") to bytes
    }

    ScreenColumn {
        if (!st.loaded) {
            NeedsKey("certificates") { vm.core.refreshNow() }
            return@ScreenColumn
        }
        SectionCard {
            SectionTitle("PIV application")
            Spacer(Modifier.height(4.dp))
            st.version?.let { InfoRow("Version", it.toString()) }
            val pin = st.pin
            if (pin != null) {
                InfoRow("PIN", "${pin.attemptsRemaining}/${pin.totalAttempts} tries" + if (pin.isDefaultValue) " · DEFAULT" else "")
            } else st.pinAttempts?.let { InfoRow("PIN tries left", it.toString()) }
            st.puk?.let { InfoRow("PUK", "${it.attemptsRemaining}/${it.totalAttempts} tries" + if (it.isDefaultValue) " · DEFAULT" else "") }
            st.managementKey?.let {
                InfoRow("Management key", it.keyType.name + (if (it.isDefaultValue) " · DEFAULT" else "") +
                    if (it.touchPolicy != TouchPolicy.NEVER && it.touchPolicy != TouchPolicy.DEFAULT) " · touch" else "")
            }
            if (st.pin?.isDefaultValue == true || st.managementKey?.isDefaultValue == true) {
                Text("Default credentials are in use. Change them to protect your keys.",
                    color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            ButtonRow {
                SmallButton("Change PIN") { dialog = PivDialog.CHANGE_PIN }
                SmallButton("Change PUK") { dialog = PivDialog.CHANGE_PUK }
                SmallButton("Unblock PIN") { dialog = PivDialog.UNBLOCK }
                SmallButton("Management key") { dialog = PivDialog.MGMT_KEY }
                SmallButton("Retry counts") { dialog = PivDialog.RETRIES }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Show retired slots (82–95)", Modifier.weight(1f))
            Switch(checked = showRetired, onCheckedChange = {
                showRetired = it; vm.piv.showRetired = it; vm.core.refreshNow()
            })
        }

        st.slots.forEach { v ->
            if (st.includesRetired || !v.slot.name.startsWith("RETIRED")) SlotCard(
                v,
                onGenerate = { generateFor = v.slot },
                onImport = { importFor = v.slot; picker.launch(arrayOf("*/*")) },
                onExport = { vm.piv.exportCertificate(v) },
                onDelete = { deleteFor = v },
            )
        }
    }

    // Dialogs ---------------------------------------------------------------
    val mgmtField = Field.Text("mk", "Management key (hex)", PivFeature.DEFAULT_MGMT_KEY,
        supporting = "Pre-filled with the factory default key")

    when (dialog) {
        PivDialog.CHANGE_PIN -> FormDialog("Change PIN", listOf(
            Field.Text("cur", "Current PIN", secret = true), Field.Text("new", "New PIN (6–8)", secret = true),
            Field.Text("rep", "Repeat", secret = true)), "Change", onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 6) ?: run { vm.piv.changePin(v.chars("cur"), v.chars("new")); null }
        }
        PivDialog.CHANGE_PUK -> FormDialog("Change PUK", listOf(
            Field.Text("cur", "Current PUK", secret = true), Field.Text("new", "New PUK (6–8)", secret = true),
            Field.Text("rep", "Repeat", secret = true)), "Change", onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 6) ?: run { vm.piv.changePuk(v.chars("cur"), v.chars("new")); null }
        }
        PivDialog.UNBLOCK -> FormDialog("Unblock PIN", listOf(
            Field.Text("cur", "PUK", secret = true), Field.Text("new", "New PIN (6–8)", secret = true),
            Field.Text("rep", "Repeat", secret = true)), "Unblock", onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 6) ?: run { vm.piv.unblockPin(v.chars("cur"), v.chars("new")); null }
        }
        PivDialog.MGMT_KEY -> {
            val types = listOf(ManagementKeyType.AES192, ManagementKeyType.TDES, ManagementKeyType.AES128, ManagementKeyType.AES256)
            FormDialog("Change management key", listOf(
                Field.Text("cur", "Current management key (hex)", PivFeature.DEFAULT_MGMT_KEY),
                Field.Choice("t", "New key type", types.map { it.name }),
                Field.Check("gen", "Generate a random key", true),
                Field.Text("new", "New key (hex, if not generating)"),
                Field.Check("touch", "Require touch to use the management key"),
                Field.Note("AES192 is the default on firmware 5.7+. Older keys may only support TDES."),
            ), "Change", onDismiss = { dialog = null }) { v ->
                if (!v.check("gen") && v.text("new").isBlank()) return@FormDialog "Enter a new key or choose Generate"
                vm.piv.changeManagementKey(v.text("cur"), types[v.choice("t")],
                    if (v.check("gen")) null else v.text("new"), v.check("touch")); null
            }
        }
        PivDialog.RETRIES -> FormDialog("PIN and PUK retry counts", listOf(
            Field.Note("This resets the PIN to 123456 and the PUK to 12345678."),
            Field.Text("p", "PIN retries", "3", numeric = true),
            Field.Text("u", "PUK retries", "3", numeric = true),
            mgmtField, Field.Text("pin", "Current PIN", secret = true),
        ), "Set", destructive = true, onDismiss = { dialog = null }) { v ->
            val p = v.int("p", -1); val u = v.int("u", -1)
            if (p !in 1..255 || u !in 1..255) return@FormDialog "Retries must be 1–255"
            vm.piv.setRetries(p, u, v.text("mk"), v.chars("pin")); null
        }
        null -> Unit
    }

    generateFor?.let { slot ->
        FormDialog("Generate key in ${PivFeature.slotName(slot)}", listOf(
            Field.Choice("kt", "Key type", KEY_TYPES.map { it.name }),
            Field.Choice("out", "Output", listOf("Self-signed certificate", "Certificate signing request (CSR)")),
            Field.Text("subj", "Subject", "CN=YubiKey PIV", supporting = "e.g. CN=Jane Doe,O=Example"),
            Field.Text("days", "Validity (days, self-signed)", "365", numeric = true),
            Field.Choice("pp", "PIN policy", PIN_POLICIES.map(::policyLabel)),
            Field.Choice("tp", "Touch policy", TOUCH_POLICIES.map(::policyLabel)),
            mgmtField, Field.Text("pin", "PIN (to sign the certificate/CSR)", secret = true),
            Field.Note("Any existing key in this slot is replaced. RSA 3072/4096 need firmware 5.7+ and can take a minute."),
        ), "Generate", onDismiss = { generateFor = null }) { v ->
            if (v.text("pin").isBlank()) return@FormDialog "Enter the PIN"
            vm.piv.generate(slot, KEY_TYPES[v.choice("kt")], PIN_POLICIES[v.choice("pp")], TOUCH_POLICIES[v.choice("tp")],
                v.text("subj").trim(), v.int("days", 365),
                if (v.choice("out") == 0) CertOutput.SELF_SIGNED else CertOutput.CSR, v.text("mk"), v.chars("pin")); null
        }
    }

    val slot = importFor
    val file = importBytes
    if (slot != null && file != null) {
        FormDialog("Import into ${PivFeature.slotName(slot)}", listOf(
            Field.Note("File: ${file.first} (${file.second.size} bytes). PKCS#12, PEM and DER are supported."),
            Field.Text("pw", "File password (if any)", secret = true),
            Field.Choice("pp", "PIN policy (private key)", PIN_POLICIES.map(::policyLabel)),
            Field.Choice("tp", "Touch policy (private key)", TOUCH_POLICIES.map(::policyLabel)),
            mgmtField,
        ), "Import", onDismiss = { importFor = null; importBytes = null }) { v ->
            vm.piv.import(slot, file.second, v.text("pw").takeIf { it.isNotEmpty() }?.toCharArray(),
                PIN_POLICIES[v.choice("pp")], TOUCH_POLICIES[v.choice("tp")], v.text("mk")); null
        }
    }

    deleteFor?.let { v ->
        FormDialog("Delete ${PivFeature.slotName(v.slot)}?", listOf(
            Field.Check("key", "Also delete the private key (firmware 5.7+)"),
            mgmtField,
        ), "Delete", destructive = true, onDismiss = { deleteFor = null }) { f ->
            vm.piv.delete(v.slot, f.check("key"), f.text("mk")); null
        }
    }
}

@Composable
private fun SlotCard(v: PivSlotView, onGenerate: () -> Unit, onImport: () -> Unit, onExport: () -> Unit, onDelete: () -> Unit) {
    val df = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }
    SectionCard {
        Text(PivFeature.slotName(v.slot), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(4.dp))
        val c = v.certificate
        if (v.isEmpty) InfoRow("Status", "empty")
        if (c != null) {
            InfoRow("Subject", c.subjectX500Principal.name)
            InfoRow("Issuer", if (c.issuerX500Principal == c.subjectX500Principal) "self-signed" else c.issuerX500Principal.name)
            InfoRow("Serial", c.serialNumber.toString(16).uppercase())
            InfoRow("Valid from", df.format(c.notBefore))
            InfoRow("Valid to", df.format(c.notAfter) + if (c.notAfter.time < System.currentTimeMillis()) " (EXPIRED)" else "")
            InfoRow("Algorithm", c.sigAlgName)
            InfoRow("SHA-256", PivFeature.fingerprint(c))
        } else if (v.metadata != null) InfoRow("Certificate", "none (key only)")
        v.metadata?.let { m ->
            InfoRow("Key type", m.keyType.name)
            InfoRow("Origin", if (m.isGenerated) "generated on YubiKey" else "imported")
            InfoRow("PIN policy", policyLabel(m.pinPolicy))
            InfoRow("Touch policy", policyLabel(m.touchPolicy))
        }
        Spacer(Modifier.height(8.dp))
        ButtonRow {
            SmallButton("Generate") { onGenerate() }
            SmallButton("Import") { onImport() }
            if (c != null) SmallButton("Export") { onExport() }
            if (!v.isEmpty) SmallButton("Delete") { onDelete() }
        }
    }
}
