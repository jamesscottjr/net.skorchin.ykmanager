package net.skorchin.ykmanager.passkey

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.annotation.RequiresApi
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Nfc
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import net.skorchin.ykmanager.ui.theme.YkManagerTheme

/**
 * The sheet shown after the user picks a YubiKey entry in Android's
 * passkey prompt. Collects the PIN, waits for an NFC tap or USB key,
 * runs the ceremony, and hands the result back to Credential Manager.
 */
@RequiresApi(34)
class PasskeyActivity : ComponentActivity() {

    private var yubiKit: YubiKitManager? = null
    private lateinit var flow: PasskeyFlow
    private var finished = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT < 34) { finish(); return }
        if (intent.action == ACTION_SELF_TEST) {
            // Picked from the test sheet: report success back to YK Manager and close.
            val result = Intent()
            PendingIntentHandler.setGetCredentialException(
                result, androidx.credentials.exceptions.GetCredentialCancellationException(PASSKEY_SELF_TEST_OK))
            setResult(Activity.RESULT_OK, result)
            finish()
            return
        }
        PasskeyPromptState.active = true

        val isCreate = intent.action == ACTION_CREATE
        flow = PasskeyFlow(applicationContext, lifecycleScope, ::deliver)

        if (!parseAndStart(isCreate)) return

        setContent { YkManagerTheme { PasskeySheet(flow) } }

        yubiKit = YubiKitManager(this).also { kit ->
            kit.startUsbDiscovery(UsbConfiguration()) { device -> runOnUiThread { flow.onUsbAttached(device) } }
        }
    }

    private fun parseAndStart(isCreate: Boolean): Boolean {
        val preferred = intent.getStringExtra(EXTRA_CREDENTIAL_ID)
        if (isCreate) {
            val req = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            val call = req?.callingRequest as? CreatePublicKeyCredentialRequest
            if (req == null || call == null) {
                deliver(PasskeyResult.CreateFailed(CreateCredentialUnknownException("No passkey request found")))
                return false
            }
            flow.start(true, call.requestJson, call.clientDataHash, req.callingAppInfo, null)
        } else {
            val req = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            val option = req?.credentialOptions?.filterIsInstance<GetPublicKeyCredentialOption>()?.firstOrNull()
            if (req == null || option == null) {
                deliver(PasskeyResult.GetFailed(GetCredentialUnknownException("No passkey request found")))
                return false
            }
            flow.start(false, option.requestJson, option.clientDataHash, req.callingAppInfo, preferred)
        }
        return true
    }

    override fun onResume() {
        super.onResume()
        startNfc()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) startNfc() // re-arm reader mode after the keyboard or a system dialog
    }

    private fun startNfc() {
        val kit = yubiKit ?: return
        try {
            // skipNdefCheck keeps the system from opening the YubiKey's OTP link instead of this prompt.
            kit.startNfcDiscovery(NfcConfiguration().timeout(30_000).skipNdefCheck(true), this) { device ->
                runOnUiThread { flow.onNfcTap(device) }
            }
            flow.setNfcAvailable(true)
        } catch (e: NfcNotAvailable) {
            flow.setNfcAvailable(false)
        }
    }

    override fun onPause() {
        yubiKit?.stopNfcDiscovery(this)
        super.onPause()
    }

    override fun onDestroy() {
        yubiKit?.stopUsbDiscovery()
        if (isFinishing || !isChangingConfigurations) PasskeyPromptState.active = false
        super.onDestroy()
    }

    private fun deliver(result: PasskeyResult) {
        if (finished) return
        finished = true
        val data = Intent()
        val ok = when (result) {
            is PasskeyResult.Success -> {
                if (intent.action == ACTION_CREATE) {
                    PendingIntentHandler.setCreateCredentialResponse(data, CreatePublicKeyCredentialResponse(result.responseJson))
                } else {
                    PendingIntentHandler.setGetCredentialResponse(data, GetCredentialResponse(androidx.credentials.PublicKeyCredential(result.responseJson)))
                }
                true
            }
            is PasskeyResult.CreateFailed -> { PendingIntentHandler.setCreateCredentialException(data, result.error); false }
            is PasskeyResult.GetFailed -> { PendingIntentHandler.setGetCredentialException(data, result.error); false }
        }
        setResult(if (ok) Activity.RESULT_OK else Activity.RESULT_CANCELED, data)
        PasskeyPromptState.active = false
        finish()
    }

    companion object {
        const val ACTION_CREATE = "net.skorchin.ykmanager.passkey.CREATE"
        const val ACTION_GET = "net.skorchin.ykmanager.passkey.GET"
        const val ACTION_SELF_TEST = "net.skorchin.ykmanager.passkey.SELF_TEST"
        const val EXTRA_CREDENTIAL_ID = "credential_id"
    }
}

/** Lets the main app stay off the YubiKey while a passkey prompt is using it. */
object PasskeyPromptState {
    @Volatile var active: Boolean = false
}

// ----------------------------------------------------------------------
// UI
// ----------------------------------------------------------------------

@RequiresApi(34)
@Composable
private fun PasskeySheet(flow: PasskeyFlow) {
    val ui by flow.ui.collectAsStateWithLifecycle()
    val pin by flow.pin.collectAsStateWithLifecycle()
    val newPin by flow.newPin.collectAsStateWithLifecycle()
    val newPin2 by flow.newPinRepeat.collectAsStateWithLifecycle()

    BackHandler { flow.cancel() }

    Box(
        Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.45f))
            .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) { /* swallow taps */ },
        contentAlignment = Alignment.BottomCenter,
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth().imePadding(),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            tonalElevation = 6.dp,
        ) {
            Column(
                Modifier
                    .navigationBarsPadding()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 24.dp, vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(Icons.Filled.Key, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(36.dp))
                Text(ui.title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
                if (ui.subtitle.isNotBlank()) {
                    Text(ui.subtitle, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }

                when (ui.phase) {
                    Phase.VERIFYING -> Busy(ui.instruction)
                    Phase.WORKING -> Busy(ui.instruction)
                    Phase.TOUCH -> Prompt(if (ui.touchIsFingerprint) Icons.Filled.Fingerprint else Icons.Filled.TouchApp, ui.instruction)
                    Phase.PICK -> {
                        Text(ui.instruction, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                        ui.accounts.forEachIndexed { i, name ->
                            OutlinedButton(onClick = { flow.pick(i) }, modifier = Modifier.fillMaxWidth()) { Text(name) }
                        }
                    }
                    Phase.READY -> {
                        PinFields(ui, pin, newPin, newPin2, flow)
                        Prompt(if (ui.usbAttached) Icons.Filled.Usb else Icons.Filled.Nfc, ui.instruction)
                    }
                    Phase.FATAL -> Unit
                }

                ui.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center)
                }

                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { flow.cancel() }) { Text(if (ui.phase == Phase.FATAL) "Close" else "Cancel") }
                    if (ui.phase == Phase.READY && (ui.usbAttached || ui.nfcKeyPresent || ui.pinMode != PinMode.NONE)) {
                        Spacer(Modifier.width(8.dp))
                        Button(onClick = { flow.onContinue() }) { Text("Continue") }
                    }
                }
            }
        }
    }
}

@RequiresApi(34)
@Composable
private fun PinFields(ui: PasskeyUi, pin: String, newPin: String, newPin2: String, flow: PasskeyFlow) {
    val pinKeyboard = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done)
    val done = KeyboardActions(onDone = { flow.onContinue() })
    when (ui.pinMode) {
        PinMode.NONE -> return
        PinMode.ENTER -> OutlinedTextField(
            value = pin, onValueChange = { flow.pin.value = it; flow.clearError() },
            label = { Text("FIDO2 PIN") }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(), keyboardOptions = pinKeyboard, keyboardActions = done,
            modifier = Modifier.fillMaxWidth(),
        )
        PinMode.CHANGE, PinMode.SET_NEW -> {
            if (ui.pinMode == PinMode.CHANGE) OutlinedTextField(
                value = pin, onValueChange = { flow.pin.value = it; flow.clearError() },
                label = { Text("Current PIN") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = pinKeyboard.copy(imeAction = ImeAction.Next), modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = newPin, onValueChange = { flow.newPin.value = it; flow.clearError() },
                label = { Text("New PIN (at least ${ui.minPinLength})") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = pinKeyboard.copy(imeAction = ImeAction.Next), modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = newPin2, onValueChange = { flow.newPinRepeat.value = it; flow.clearError() },
                label = { Text("Repeat new PIN") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = pinKeyboard, keyboardActions = done,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
    ui.pinHint?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun Busy(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 8.dp)) {
        CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 3.dp)
        Spacer(Modifier.width(12.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun Prompt(icon: ImageVector, text: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(vertical = 4.dp)) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(44.dp))
        Spacer(Modifier.height(6.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
    }
}
