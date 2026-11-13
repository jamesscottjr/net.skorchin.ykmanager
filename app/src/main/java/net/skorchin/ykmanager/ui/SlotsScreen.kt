package net.skorchin.ykmanager.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
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
import net.skorchin.ykmanager.yubi.Evidence
import net.skorchin.ykmanager.yubi.OtpFeature
import net.skorchin.ykmanager.yubi.SlotProgram
import net.skorchin.ykmanager.yubi.SlotType
import net.skorchin.ykmanager.yubi.SlotView
import net.skorchin.ykmanager.yubi.SlotWriteOptions
import net.skorchin.ykmanager.yubi.OtpOutputSettings
import net.skorchin.ykmanager.yubi.DecodedOtp
import net.skorchin.ykmanager.yubi.OtpDecoder
import net.skorchin.ykmanager.yubi.num
import com.yubico.yubikit.yubiotp.Slot
import kotlinx.coroutines.delay

enum class Prog(val title: String) {
    YUBICO_OTP("Yubico OTP"), CHALRESP("Challenge-response"), STATIC("Static password"), HOTP("OATH-HOTP")
}

private sealed interface SlotAction {
    data class Pick(val slot: Slot) : SlotAction
    data class Program(val slot: Slot, val kind: Prog) : SlotAction
    data class Delete(val slot: Slot) : SlotAction
    data class Hmac(val slot: Slot) : SlotAction
    data class UpdateOutput(val slot: Slot) : SlotAction
    data object Swap : SlotAction
    data object Ndef : SlotAction
}

@Composable
fun SlotsScreen(vm: AppViewModel) {
    val slots by vm.otp.slots.collectAsStateWithLifecycle()
    val info by vm.core.keyInfo.collectAsStateWithLifecycle()
    var action by remember { mutableStateOf<SlotAction?>(null) }

    ScreenColumn {
        if (info == null) {
            NeedsKey("the OTP slot configuration") { vm.core.refreshNow() }
            return@ScreenColumn
        }
        if (info?.otpState == null) {
            SectionCard {
                Hint("The OTP application could not be read. Make sure Yubico OTP is enabled under Applications for this connection.")
            }
        }
        info?.otpVersion?.let { Hint("OTP application version $it") }
        slots.forEach { v -> SlotCard(vm, v, onAction = { action = it }) }

        SectionCard {
            SectionTitle("Both slots")
            Spacer(Modifier.height(6.dp))
            ButtonRow {
                SmallButton("Swap slots") { action = SlotAction.Swap }
                SmallButton("NFC (NDEF) output") { action = SlotAction.Ndef }
                SmallButton("Show NFC output") { vm.otp.showNdefOutput() }
            }
        }

        OtpDecoderCard(vm)

        NfcHandlingCard(vm)

        SectionCard {
            SectionTitle("About reading slot configuration")
            Spacer(Modifier.height(4.dp))
            Hint(
                "A YubiKey never reveals what is stored in a slot (secrets, keys, or even the exact type) - the desktop " +
                    "YubiKey Manager only shows Programmed or Empty. This app reads everything the key does report: " +
                    "whether each slot is programmed and whether it is touch-triggered (types text) or used by " +
                    "challenge-response. It then identifies the exact type from what the slot types, from the NFC tag, " +
                    "or with a challenge-response test, and remembers what this app programmed (never the secrets)."
            )
        }
    }

    when (val a = action) {
        is SlotAction.Pick -> AlertDialog(
            onDismissRequest = { action = null },
            title = { Text("Configure slot ${a.slot.num}") },
            text = {
                Column {
                    Hint("This replaces anything currently in the slot.")
                    Spacer(Modifier.height(8.dp))
                    Prog.values().forEach { p ->
                        OutlinedButton(onClick = { action = SlotAction.Program(a.slot, p) },
                            modifier = Modifier.fillMaxWidth()) { Text(p.title) }
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { action = null }) { Text("Cancel") } },
        )

        is SlotAction.Program -> ProgramDialog(vm, a.slot, a.kind, slots.firstOrNull { it.slot == a.slot }?.configured == true) {
            action = null
        }

        is SlotAction.Delete -> FormDialog("Delete slot ${a.slot.num}?", listOf(
            Field.Note("The credential in this slot will be permanently erased."),
            Field.Text("acc", "Access code (hex, if set)"),
        ), "Delete", destructive = true, onDismiss = { action = null }) { v ->
            vm.otp.delete(a.slot, v.text("acc")); null
        }

        is SlotAction.Hmac -> FormDialog("HMAC-SHA1 challenge (slot ${a.slot.num})", listOf(
            Field.Text("ch", "Challenge (hex, up to 64 bytes)", supporting = "Leave empty to send an empty challenge"),
        ), "Calculate", onDismiss = { action = null }) { v ->
            vm.otp.calculateHmac(a.slot, v.text("ch").replace(" ", "")); null
        }

        is SlotAction.UpdateOutput -> {
            val out by vm.settings.otpOutput.collectAsStateWithLifecycle()
            FormDialog("Update slot ${a.slot.num} settings", listOfNotNull(
                Field.Note("Rewrites only the output and device settings of this slot; the credential stays. " +
                    "The current settings cannot be read from the key, so all of them are replaced with the ones " +
                    "from Settings → OTP output:"),
                Field.Note("Types: " + out.outputPattern(firstPart = "first part", secondPart = "second part") +
                    " (the first part is the public ID for Yubico OTP; HOTP and static passwords have none)."),
                out.changesFromDefault().filterNot { it.startsWith("tab") || it.contains("Enter") }
                    .takeIf { it.isNotEmpty() }?.let { Field.Note("Options: " + it.joinToString()) },
                if (!out.allowUpdate) Field.Note("\"Allow update\" is off: after this, the slot's settings can only be changed by reprogramming it.") else null,
                Field.Text("acc", "Access code (hex, if set)"),
                Field.Note("Works only if the slot was programmed with \"Allow update\" (the default in this app) on firmware 2.3 or newer."),
            ), "Update", onDismiss = { action = null }) { v ->
                vm.otp.updateOutput(a.slot, out, v.text("acc")); null
            }
        }

        SlotAction.Swap -> ConfirmDialog("Swap slots?",
            "The configurations of slot 1 (short touch) and slot 2 (long touch) will be exchanged. " +
                "This fails if either slot has an access code.",
            "Swap", onDismiss = { action = null }) { vm.otp.swap() }

        SlotAction.Ndef -> FormDialog("NFC (NDEF) output", listOf(
            Field.Choice("slot", "Slot sent when tapped over NFC", listOf("Slot 1", "Slot 2")),
            Field.Choice("type", "Payload type", listOf("URI (opens a link)", "Plain text")),
            Field.Text("uri", "Prefix", "https://my.yubico.com/yk/#",
                supporting = "The OTP is appended to this. For URI, empty = Yubico's default; for text, empty = OTP only."),
            Field.Text("acc", "Access code (hex, if set)"),
            Field.Note("Only slots with Yubico OTP or OATH-HOTP produce a usable NDEF output."),
        ), "Save", onDismiss = { action = null }) { v ->
            vm.otp.setNdef(if (v.choice("slot") == 0) Slot.ONE else Slot.TWO, v.text("uri"), v.choice("type") == 1, v.text("acc")); null
        }

        null -> Unit
    }
}

@Composable
private fun SlotCard(vm: AppViewModel, v: SlotView, onAction: (SlotAction) -> Unit) {
    var capture by remember(v.slot) { mutableStateOf("") }
    LaunchedEffect(capture) {
        if (capture.isBlank()) return@LaunchedEffect
        delay(700)  // the YubiKey types the whole OTP within a few hundred ms
        vm.otp.identifyFromOutput(v.slot, capture)
        capture = ""
    }
    val status = when (v.configured) {
        true -> "Programmed"
        false -> "Empty"
        null -> "Unknown (firmware too old to report)"
    }
    Card(Modifier.fillMaxWidth(),
        colors = if (v.configured == true) CardDefaults.cardColors() else
            CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        if (v.slot == Slot.ONE) "Slot 1 · short touch" else "Slot 2 · long touch",
                        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    )
                    Text(status, style = MaterialTheme.typography.bodyMedium,
                        color = if (v.configured == true) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant)
                }
                v.type?.let { AssistChip(onClick = {}, label = { Text(shortType(it)) }) }
            }
            Spacer(Modifier.height(8.dp))

            if (v.configured == true) {
                v.touchTriggered?.let {
                    InfoRow("Triggered by", if (it) "touch (types text)" else "challenge from an app")
                }
                v.type?.let { InfoRow("Type", it.label) }
                v.evidence?.let { InfoRow("Determined", it.label) }
                v.details.forEach { (k, d) -> InfoRow(k, d) }
                v.history?.let { h ->
                    Spacer(Modifier.height(6.dp))
                    Text("Programmed by this app", style = MaterialTheme.typography.labelLarge)
                    InfoRow("Date", OtpFeature.formatTime(h.programmedAt))
                    if (v.evidence != Evidence.HISTORY) InfoRow("Recorded type", h.type.label)
                    h.details.forEach { (k, d) -> InfoRow(k, d) }
                }

                val keyboard = v.touchTriggered == true || v.type in listOf(SlotType.KEYBOARD_UNKNOWN,
                    SlotType.YUBICO_OTP, SlotType.HOTP, SlotType.STATIC)
                val chalresp = v.touchTriggered == false || v.type == SlotType.CHALRESP || v.type == SlotType.CHALRESP_OTHER
                if (keyboard && v.evidence != Evidence.OUTPUT) {
                    Spacer(Modifier.height(8.dp))
                    Text("Identify this slot", style = MaterialTheme.typography.labelLarge)
                    Hint(if (vm.core.isUsb)
                        "Tap the field below, then ${if (v.slot == Slot.ONE) "briefly touch" else "touch and hold (3 s)"} your YubiKey. It types its output here and the app works out the type."
                    else "Over NFC, the key sends the slot assigned to NFC output (slot 1 by default).")
                    if (vm.core.isUsb) OutlinedTextField(
                        value = capture, onValueChange = { capture = it },
                        label = { Text("Touch the key while this is focused") },
                        singleLine = true, modifier = Modifier.fillMaxWidth(),
                    )
                }
                Spacer(Modifier.height(8.dp))
                ButtonRow {
                    if (keyboard && !vm.core.isUsb) SmallButton("Read over NFC") { vm.otp.identifyViaNdef(v.slot) }
                    if (chalresp) SmallButton("Test challenge-response") { vm.otp.probeChallengeResponse(v.slot) }
                    if (v.type == SlotType.CHALRESP) SmallButton("Calculate HMAC") { onAction(SlotAction.Hmac(v.slot)) }
                    if (keyboard && !chalresp) SmallButton("Update settings") { onAction(SlotAction.UpdateOutput(v.slot)) }
                    SmallButton("Reconfigure") { onAction(SlotAction.Pick(v.slot)) }
                    SmallButton("Delete") { onAction(SlotAction.Delete(v.slot)) }
                }
            } else {
                Hint("Nothing is stored in this slot.")
                Spacer(Modifier.height(8.dp))
                SmallButton("Configure") { onAction(SlotAction.Pick(v.slot)) }
            }
        }
    }
}

private fun shortType(t: SlotType) = when (t) {
    SlotType.YUBICO_OTP -> "Yubico OTP"
    SlotType.HOTP -> "HOTP"
    SlotType.STATIC -> "Static"
    SlotType.CHALRESP -> "HMAC-SHA1"
    SlotType.CHALRESP_OTHER -> "Chal-resp"
    SlotType.KEYBOARD_UNKNOWN -> "Keyboard"
}

/** Form fields for programming a slot; shared by the slot screen and recipe editor. */
fun slotProgramFields(
    kind: Prog, slot: Slot?, overwriting: Boolean, forRecipe: Boolean = false,
    defaultEnter: Boolean = true, output: OtpOutputSettings? = null,
): List<Field> {
    val common = listOfNotNull(
        if (kind != Prog.CHALRESP) Field.Check("enter", "Append Enter after output", defaultEnter) else null,
        output?.let { o ->
            val extra = o.changesFromDefault().filterNot { it.startsWith("tab") || it.contains("Enter") }
            Field.Note(
                (if (kind != Prog.CHALRESP) "Output: " + o.outputPattern(
                    firstPart = if (kind == Prog.YUBICO_OTP) "public ID" else null,
                    secondPart = when (kind) { Prog.YUBICO_OTP -> "OTP"; Prog.HOTP -> "code"; else -> "password" },
                ) + ". " else "") +
                    (if (extra.isNotEmpty()) "Options: ${extra.joinToString()}. " else "") +
                    "Change these under Settings → OTP output."
            )
        },
        if (!forRecipe) Field.Text("cur", "Current access code (hex, if set)") else null,
        Field.Text("new", "New access code (hex, optional)", supporting = "6 bytes / 12 hex digits. Protects the slot from changes."),
        if (overwriting && slot != null) Field.Note("Slot ${slot.num} is programmed. Its current credential will be overwritten.") else null,
    )
    val randomNote = if (forRecipe) " Random values are generated separately for every key." else ""
    val specific: List<Field> = when (kind) {
        Prog.YUBICO_OTP -> listOf(
            Field.Choice("pub", "Public ID", listOf("Use serial number", "Random", "Enter manually")),
            Field.Text("pubv", "Public ID (modhex, if manual)"),
            Field.Text("priv", "Private ID (12 hex, empty = random)"),
            Field.Text("key", "Secret key (32 hex, empty = random)", secret = true),
            Field.Note("To use with Yubico's validation service, upload the credential at upload.yubico.com.$randomNote"),
        )
        Prog.CHALRESP -> listOf(
            Field.Text("sec", "Secret key (hex, up to 20 bytes, empty = random)", secret = true,
                supporting = if (forRecipe) "Enter a secret to program the same one on every key." else null),
            Field.Check("touch", "Require touch"),
        )
        Prog.STATIC -> listOf(
            Field.Text("pw", "Password (empty = generate)", secret = true,
                supporting = "US keyboard layout, case is preserved, up to 38 characters." +
                    (if (forRecipe) " Enter one to use the same password on every key." else "")),
            Field.Choice("set", "Generated character set",
                listOf("Full (upper/lowercase, digits, symbols)", "Modhex (layout independent)")),
            Field.Text("len", "Generated length", "38", numeric = true),
        )
        Prog.HOTP -> listOf(
            Field.Text("sec", "Secret key (base32)", secret = true),
            Field.Choice("dig", "Digits", listOf("6", "8")),
            Field.Text("ctr", "Initial counter", "0", numeric = true),
        )
    }
    return specific + common
}

/** Parse the values of [slotProgramFields]; returns an error message or the program and options. */
fun parseSlotProgram(kind: Prog, v: FormValues): Pair<String?, Pair<SlotProgram, SlotWriteOptions>?> {
    val program: SlotProgram = when (kind) {
        Prog.YUBICO_OTP -> {
            val mode = v.choice("pub")
            if (mode == 2 && v.text("pubv").isBlank()) return "Enter a public ID" to null
            SlotProgram.YubicoOtp(
                publicIdModhex = if (mode == 2) v.text("pubv").trim() else null,
                useSerialAsPublicId = mode == 0,
                privateIdHex = v.text("priv").trim().ifBlank { null },
                keyHex = v.text("key").trim().ifBlank { null },
            )
        }
        Prog.CHALRESP -> SlotProgram.ChallengeResponse(v.text("sec").replace(" ", "").ifBlank { null }, v.check("touch"))
        Prog.STATIC -> SlotProgram.StaticPassword(
            v.text("pw").ifEmpty { null }, v.int("len", 38), v.choice("set") == 1,
        )
        Prog.HOTP -> {
            if (v.text("sec").isBlank()) return "Enter the secret" to null
            SlotProgram.Hotp(v.text("sec"), v.choice("dig") == 1, v.int("ctr", 0))
        }
    }
    val opts = SlotWriteOptions(
        appendEnter = kind == Prog.CHALRESP || v.check("enter"),
        currentAccessCodeHex = v.text("cur"),
        newAccessCodeHex = v.text("new"),
    )
    return null to (program to opts)
}

@Composable
private fun ProgramDialog(vm: AppViewModel, slot: Slot, kind: Prog, overwriting: Boolean, onDone: () -> Unit) {
    val out by vm.settings.otpOutput.collectAsStateWithLifecycle()
    FormDialog("${kind.title} · slot ${slot.num}",
        slotProgramFields(kind, slot, overwriting, defaultEnter = out.appendEnter, output = out), "Write", onDismiss = onDone) { v ->
        val (err, parsed) = parseSlotProgram(kind, v)
        if (err != null || parsed == null) return@FormDialog err ?: "Invalid input"
        vm.otp.program(slot, parsed.first, parsed.second.copy(output = out))
        null
    }
}

@Suppress("unused")
private val spacer = Modifier.width(1.dp)

/**
 * Lets the user hand NFC taps to Android while on this screen, to test what the
 * phone does with the key's NDEF record. Everywhere else the app always keeps
 * reader mode, so a tap never leaves YK Manager.
 */
@Composable
private fun NfcHandlingCard(vm: AppViewModel) {
    val nfc by vm.core.nfcAvailable.collectAsStateWithLifecycle()
    if (nfc != true) return
    val activity = LocalContext.current.findActivity() ?: return
    val systemHandles by vm.core.systemHandlesNfc.collectAsStateWithLifecycle()
    // Leaving this screen always gives taps back to the app.
    DisposableEffect(Unit) { onDispose { if (vm.core.systemHandlesNfc.value) vm.core.setSystemHandlesNfc(activity, false) } }
    SectionCard {
        SectionTitle("NFC taps while on this screen")
        Spacer(Modifier.height(4.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = systemHandles, onCheckedChange = { vm.core.setSystemHandlesNfc(activity, it) })
            Spacer(Modifier.width(8.dp))
            Text(
                if (systemHandles) "Let the phone handle the tag (opens the NDEF link or text in another app) - for testing the NDEF output."
                else "YK Manager handles taps (default). Turn on to see what the phone itself does with the NDEF tag.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (!systemHandles) {
            Spacer(Modifier.height(4.dp))
            Hint("Use \"Show NFC output\" above to read the NDEF record in the app without leaving it.")
        }
    }
}

private tailrec fun android.content.Context.findActivity(): android.app.Activity? = when (this) {
    is android.app.Activity -> this
    is android.content.ContextWrapper -> baseContext.findActivity()
    else -> null
}

/**
 * Decrypts a Yubico OTP with the slot's AES key to show the private ID, counters and timer.
 * Everything stays in this composable's memory; nothing is saved or logged.
 */
@Composable
private fun OtpDecoderCard(vm: AppViewModel) {
    val context = LocalContext.current
    var otp by remember { mutableStateOf("") }
    var key by remember { mutableStateOf("") }
    var expected by remember { mutableStateOf("") }
    var showKey by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<DecodedOtp?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    fun decode() {
        runCatching { OtpDecoder.decode(otp, key, expected) }
            .onSuccess { result = it; error = null }
            .onFailure { result = null; error = it.message ?: "Could not decode the OTP" }
    }

    SectionCard {
        SectionTitle("OTP decoder")
        Spacer(Modifier.height(4.dp))
        Hint("Decrypts a Yubico OTP with the slot's AES key to show what the key encrypted: the private ID, " +
            "usage and session counters and the timer. Runs on this phone only; nothing is stored. " +
            "The YubiKey itself never outputs the private ID in the clear.")
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = otp, onValueChange = { otp = it; result = null; error = null },
            label = { Text("OTP") },
            supportingText = { Text(if (vm.core.isUsb) "Focus here and touch the key, or paste an OTP or my.yubico.com link"
                else "Paste an OTP or link, or use Read over NFC") },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = key, onValueChange = { key = it; result = null; error = null },
            label = { Text("AES key (32 hex characters)") },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
            visualTransformation = if (showKey) androidx.compose.ui.text.input.VisualTransformation.None
                else androidx.compose.ui.text.input.PasswordVisualTransformation(),
            keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                keyboardType = androidx.compose.ui.text.input.KeyboardType.Password, autoCorrectEnabled = false),
            trailingIcon = { TextButton(onClick = { showKey = !showKey }) { Text(if (showKey) "Hide" else "Show") } },
        )
        OutlinedTextField(
            value = expected, onValueChange = { expected = it; result = null; error = null },
            label = { Text("Expected private ID (optional, 12 hex)") },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        ButtonRow {
            SmallButton("Decode", enabled = otp.isNotBlank() && key.isNotBlank()) { decode() }
            if (!vm.core.isUsb) SmallButton("Read over NFC") {
                vm.otp.readNdefOtp { o -> otp = o; result = null; error = null; if (key.isNotBlank()) decode() }
            }
            SmallButton("Clear") { otp = ""; key = ""; expected = ""; result = null; error = null; showKey = false }
        }
        error?.let {
            Spacer(Modifier.height(6.dp))
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }
        result?.let { r ->
            Spacer(Modifier.height(8.dp))
            Text(
                if (r.crcValid) "Checksum OK: the AES key is correct" else
                    "Checksum failed: wrong AES key, or the OTP was mistyped. The values below are meaningless.",
                color = if (r.crcValid) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.labelLarge,
            )
            Spacer(Modifier.height(4.dp))
            InfoRow("Public ID", r.publicId.ifEmpty { "(none)" } + if (r.publicId.isNotEmpty()) " (hex ${r.publicIdHex})" else "")
            r.serialFromPublicId?.let { InfoRow("Serial in public ID", it.toString()) }
            InfoRow("Private ID", r.privateIdHex)
            r.privateIdMatches?.let { InfoRow("Matches expected", if (it) "Yes" else "No") }
            InfoRow("Usage counter", "${r.usageCounter} (power-ups)")
            InfoRow("Session counter", "${r.sessionCounter} (OTPs since power-up)")
            InfoRow("Timer", "${r.timestamp} (%.1f s since power-up + random start)".format(r.timestampSeconds))
            InfoRow("Random", "%04x".format(r.random))
            InfoRow("CRC", "%04x".format(r.crc))
            InfoRow("Decrypted block", r.plaintextHex)
            Spacer(Modifier.height(6.dp))
            ButtonRow {
                if (r.crcValid) SmallButton("Copy private ID") { copyToClipboard(context, "Private ID", r.privateIdHex) }
            }
            Hint("Validation servers reject an OTP whose usage/session counters are not higher than the last one they saw.")
        }
    }
}

