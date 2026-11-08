package net.skorchin.ykmanager.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
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
import net.skorchin.ykmanager.yubi.OtpFeature
import net.skorchin.ykmanager.yubi.Passkey
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.Uif

// ----------------------------------------------------------------------
// Passkeys (FIDO2)
// ----------------------------------------------------------------------

private enum class FidoDialog { SET_PIN, CHANGE_PIN, UNLOCK }

@Composable
fun PasskeysScreen(vm: AppViewModel) {
    val st by vm.fido.state.collectAsStateWithLifecycle()
    var dialog by remember { mutableStateOf<FidoDialog?>(null) }
    var toDelete by remember { mutableStateOf<Passkey?>(null) }

    ScreenColumn {
        PasskeyProviderCard()
        if (!st.loaded) {
            NeedsKey("FIDO2 information") { vm.core.refreshNow() }
            return@ScreenColumn
        }
        SectionCard {
            SectionTitle("FIDO2 / passkeys")
            Spacer(Modifier.height(4.dp))
            InfoRow("Versions", st.versions.joinToString())
            st.aaguid?.let { InfoRow("AAGUID", it) }
            InfoRow("PIN", if (st.pinSet) "set" else "not set")
            st.pinRetries?.let { InfoRow("PIN retries left", it.toString()) }
            InfoRow("Min PIN length", st.minPinLength.toString())
            st.alwaysUv?.let { InfoRow("Always require UV", if (it) "on" else "off") }
            st.existingCount?.let { InfoRow("Passkeys stored", it.toString()) }
            st.remainingCredentials?.let { InfoRow("Free passkey slots", it.toString()) }
            if (st.forcePinChange) Text("The key requires you to change the PIN before use.",
                color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
            ButtonRow {
                if (!st.pinSet) SmallButton("Set PIN") { dialog = FidoDialog.SET_PIN }
                else SmallButton("Change PIN") { dialog = FidoDialog.CHANGE_PIN }
            }
        }

        SectionTitle("Passkeys")
        when {
            !st.credMgmtSupported -> Hint("This YubiKey does not support listing passkeys (firmware 5.2 or newer is needed).")
            !st.pinSet -> Hint("Set a PIN to manage passkeys. Passkeys stored on the key require one.")
            st.passkeys == null -> SectionCard {
                Hint("Enter your FIDO2 PIN to list the passkeys stored on this YubiKey.")
                Spacer(Modifier.height(8.dp))
                SmallButton("Unlock with PIN") { dialog = FidoDialog.UNLOCK }
            }
            st.passkeys!!.isEmpty() -> Hint("No passkeys are stored on this YubiKey.")
            else -> {
                st.passkeys!!.sortedBy { it.rpId }.forEach { p ->
                    Card(Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(start = 16.dp, top = 10.dp, bottom = 10.dp, end = 4.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(p.rpId, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                                Text(listOfNotNull(p.displayName?.takeIf { it != p.userName }, p.userName).joinToString(" · "),
                                    style = MaterialTheme.typography.bodySmall)
                            }
                            IconButton(onClick = { toDelete = p }) { Icon(Icons.Filled.Delete, "Delete") }
                        }
                    }
                }
                SmallButton("Lock") { vm.fido.lock() }
            }
        }
    }

    when (dialog) {
        FidoDialog.SET_PIN -> FormDialog(
            "Set FIDO2 PIN",
            listOf(Field.Text("new", "New PIN", secret = true), Field.Text("rep", "Repeat PIN", secret = true)),
            "Set", onDismiss = { dialog = null },
        ) { v -> requireMatch(v, "new", "rep", st.minPinLength) ?: run { vm.fido.setPin(v.chars("new")); null } }

        FidoDialog.CHANGE_PIN -> FormDialog(
            "Change FIDO2 PIN",
            listOf(
                Field.Text("cur", "Current PIN", secret = true),
                Field.Text("new", "New PIN", secret = true),
                Field.Text("rep", "Repeat PIN", secret = true),
            ),
            "Change", onDismiss = { dialog = null },
        ) { v -> requireMatch(v, "new", "rep", st.minPinLength) ?: run { vm.fido.changePin(v.chars("cur"), v.chars("new")); null } }

        FidoDialog.UNLOCK -> FormDialog(
            "Unlock passkeys",
            listOf(Field.Text("pin", "FIDO2 PIN", secret = true)),
            "Unlock", onDismiss = { dialog = null },
        ) { v -> vm.fido.unlock(v.chars("pin")); null }

        null -> Unit
    }
    toDelete?.let { p ->
        ConfirmDialog("Delete passkey?",
            "The passkey for ${p.rpId} (${p.userName}) will be permanently deleted. You won't be able to sign in with it anymore.",
            "Delete", onDismiss = { toDelete = null }) { vm.fido.delete(p) }
    }
}

// ----------------------------------------------------------------------
// OpenPGP
// ----------------------------------------------------------------------

private enum class PgpDialog { USER_PIN, ADMIN_PIN, RESET_CODE, UNBLOCK_RC, UNBLOCK_ADMIN, RETRIES }

private fun keyRefName(r: KeyRef) = when (r) {
    KeyRef.SIG -> "Signature"
    KeyRef.DEC -> "Encryption"
    KeyRef.AUT -> "Authentication"
    KeyRef.ATT -> "Attestation"
}

private fun uifName(u: Uif?) = when (u) {
    null -> "not supported"
    Uif.OFF -> "off"
    Uif.ON -> "on"
    Uif.FIXED -> "on (fixed)"
    Uif.CACHED -> "cached"
    Uif.CACHED_FIXED -> "cached (fixed)"
}

@Composable
fun OpenPgpScreen(vm: AppViewModel) {
    val st by vm.pgp.state.collectAsStateWithLifecycle()
    var dialog by remember { mutableStateOf<PgpDialog?>(null) }
    var touchFor by remember { mutableStateOf<KeyRef?>(null) }

    ScreenColumn {
        if (!st.loaded) {
            NeedsKey("OpenPGP information") { vm.core.refreshNow() }
            return@ScreenColumn
        }
        SectionCard {
            SectionTitle("OpenPGP application")
            Spacer(Modifier.height(4.dp))
            st.version?.let { InfoRow("Version", it.toString()) }
            InfoRow("PIN attempts", listOf(
                "user ${st.userAttempts ?: "?"}", "reset ${st.resetAttempts ?: "?"}", "admin ${st.adminAttempts ?: "?"}"
            ).joinToString(", "))
            st.signatureCounter?.let { InfoRow("Signatures made", it.toString()) }
            st.signaturePinPolicy?.let { InfoRow("Signature PIN", if (it == "once") "once per session" else "every signature") }
            Spacer(Modifier.height(8.dp))
            ButtonRow {
                SmallButton("Change PIN") { dialog = PgpDialog.USER_PIN }
                SmallButton("Change admin PIN") { dialog = PgpDialog.ADMIN_PIN }
                SmallButton("Set reset code") { dialog = PgpDialog.RESET_CODE }
                SmallButton("Unblock PIN (reset code)") { dialog = PgpDialog.UNBLOCK_RC }
                SmallButton("Unblock PIN (admin)") { dialog = PgpDialog.UNBLOCK_ADMIN }
                SmallButton("Retry counts") { dialog = PgpDialog.RETRIES }
            }
        }
        SectionTitle("Keys")
        st.keys.forEach { k ->
            SectionCard {
                Text(keyRefName(k.ref), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                k.algorithm?.let { InfoRow("Algorithm", it) }
                if (k.fingerprint == null) InfoRow("Status", "empty")
                else {
                    InfoRow("Fingerprint", k.fingerprint.chunked(4).joinToString(" "))
                    k.created?.let { InfoRow("Created", OtpFeature.formatTime(it)) }
                    k.status?.let { InfoRow("Origin", it.replace('_', ' ')) }
                }
                InfoRow("Touch", uifName(k.touch))
                if (k.touch != null && k.touch != Uif.FIXED && k.touch != Uif.CACHED_FIXED) {
                    Spacer(Modifier.height(6.dp))
                    SmallButton("Change touch policy") { touchFor = k.ref }
                }
            }
        }
        Hint("Key generation and import for OpenPGP are best done with GnuPG on a computer; this app manages PINs and policies.")
    }

    val pinFields = { cur: String, new: String ->
        listOf(Field.Text("cur", cur, secret = true), Field.Text("new", new, secret = true),
            Field.Text("rep", "Repeat", secret = true))
    }
    when (dialog) {
        PgpDialog.USER_PIN -> FormDialog("Change PIN", pinFields("Current PIN", "New PIN (6+)"), "Change",
            onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 6) ?: run { vm.pgp.changeUserPin(v.chars("cur"), v.chars("new")); null }
        }
        PgpDialog.ADMIN_PIN -> FormDialog("Change admin PIN", pinFields("Current admin PIN", "New admin PIN (8+)"), "Change",
            onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 8) ?: run { vm.pgp.changeAdminPin(v.chars("cur"), v.chars("new")); null }
        }
        PgpDialog.RESET_CODE -> FormDialog("Set reset code", pinFields("Admin PIN", "New reset code (8+)"), "Set",
            onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 8) ?: run { vm.pgp.setResetCode(v.chars("cur"), v.chars("new")); null }
        }
        PgpDialog.UNBLOCK_RC -> FormDialog("Unblock PIN", pinFields("Reset code", "New PIN (6+)"), "Unblock",
            onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 6) ?: run { vm.pgp.unblockWithResetCode(v.chars("cur"), v.chars("new")); null }
        }
        PgpDialog.UNBLOCK_ADMIN -> FormDialog("Unblock PIN", pinFields("Admin PIN", "New PIN (6+)"), "Unblock",
            onDismiss = { dialog = null }) { v ->
            requireMatch(v, "new", "rep", 6) ?: run { vm.pgp.unblockWithAdmin(v.chars("cur"), v.chars("new")); null }
        }
        PgpDialog.RETRIES -> FormDialog(
            "PIN retry counts",
            listOf(
                Field.Note("Changing retry counts resets all PINs to their defaults (PIN 123456, admin 12345678) and removes the reset code."),
                Field.Text("admin", "Admin PIN", secret = true),
                Field.Text("u", "User PIN retries", "3", numeric = true),
                Field.Text("r", "Reset code retries", "0", numeric = true),
                Field.Text("a", "Admin PIN retries", "3", numeric = true),
            ),
            "Set", destructive = true, onDismiss = { dialog = null },
        ) { v ->
            val u = v.int("u", -1); val r = v.int("r", -1); val a = v.int("a", -1)
            if (u !in 1..99 || r !in 0..99 || a !in 1..99) return@FormDialog "Retries must be 1–99 (reset code 0–99)"
            vm.pgp.setRetries(v.chars("admin"), u, r, a); null
        }
        null -> Unit
    }

    touchFor?.let { ref ->
        val options = listOf(Uif.OFF, Uif.ON, Uif.CACHED, Uif.FIXED, Uif.CACHED_FIXED)
        FormDialog(
            "Touch policy: ${keyRefName(ref)}",
            listOf(
                Field.Choice("p", "Policy", options.map { uifName(it) }),
                Field.Note("\"Fixed\" policies can never be changed again without resetting OpenPGP."),
                Field.Text("admin", "Admin PIN", secret = true),
            ),
            "Apply", onDismiss = { touchFor = null },
        ) { v -> vm.pgp.setTouch(v.chars("admin"), ref, options[v.choice("p")]); null }
    }
}
