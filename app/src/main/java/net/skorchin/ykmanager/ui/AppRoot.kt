package net.skorchin.ykmanager.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.PlaylistAddCheck
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Nfc
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material.icons.filled.TouchApp
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.skorchin.ykmanager.yubi.AppViewModel
import net.skorchin.ykmanager.yubi.ExportFile
import net.skorchin.ykmanager.yubi.Link
import net.skorchin.ykmanager.yubi.Screen
import kotlinx.coroutines.launch

fun copyToClipboard(context: Context, label: String, value: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText(label, value))
    Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
}

private fun Screen.icon(): ImageVector = when (this) {
    Screen.HOME -> Icons.Filled.Home
    Screen.ACCOUNTS -> Icons.Filled.Password
    Screen.PASSKEYS -> Icons.Filled.Fingerprint
    Screen.CERTIFICATES -> Icons.Filled.Badge
    Screen.SLOTS -> Icons.Filled.Key
    Screen.OPENPGP -> Icons.Filled.Lock
    Screen.APPLICATIONS -> Icons.Filled.Apps
    Screen.RESET -> Icons.Filled.RestartAlt
    Screen.RECIPES -> Icons.Filled.PlaylistAddCheck
    Screen.FINGERPRINTS -> Icons.Filled.Fingerprint
    Screen.ABOUT -> Icons.Filled.Info
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRoot(vm: AppViewModel) {
    val core = vm.core
    val context = LocalContext.current
    val screen by vm.screen.collectAsStateWithLifecycle()
    val busy by core.busy.collectAsStateWithLifecycle()
    val link by core.link.collectAsStateWithLifecycle()
    val keyInfo by core.keyInfo.collectAsStateWithLifecycle()
    val message by core.message.collectAsStateWithLifecycle()
    val tapPrompt by core.tapPrompt.collectAsStateWithLifecycle()
    val touchPrompt by core.touchPrompt.collectAsStateWithLifecycle()
    val dialog by core.dialog.collectAsStateWithLifecycle()
    val export by core.export.collectAsStateWithLifecycle()

    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var accepted by remember { mutableStateOf(termsAccepted(context)) }

    LaunchedEffect(message) {
        val m = message ?: return@LaunchedEffect
        snackbar.showSnackbar(m.text, withDismissAction = true,
            duration = if (m.isError) SnackbarDuration.Long else SnackbarDuration.Short)
        core.clearMessage()
    }

    // Save exported files (certificates, CSRs) with the system file picker.
    var pendingExport by remember { mutableStateOf<ExportFile?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri ->
        val f = pendingExport
        pendingExport = null
        if (uri != null && f != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { it.write(f.bytes) }
            }.onSuccess { core.toast("Saved ${f.suggestedName}") }
                .onFailure { core.error("Could not save: ${it.message}") }
        }
    }
    LaunchedEffect(export) {
        val f = export ?: return@LaunchedEffect
        core.clearExport()
        pendingExport = f
        saver.launch(f.suggestedName)
    }

    ModalNavigationDrawer(
        drawerState = drawer,
        drawerContent = {
            ModalDrawerSheet {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    Text(
                        "YK Manager",
                        style = MaterialTheme.typography.titleLarge,
                        modifier = Modifier.padding(start = 24.dp, top = 24.dp, bottom = 4.dp),
                    )
                    Text(
                        keyInfo?.let { k -> k.name + (k.version?.let { " · $it" } ?: "") }
                            ?: "No YubiKey connected",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 24.dp, bottom = 12.dp),
                    )
                    HorizontalDivider()
                    Spacer(Modifier.height(8.dp))
                    Screen.values().filter { it.availableFor(keyInfo) }.forEach { s ->
                        if (s == Screen.APPLICATIONS || s == Screen.ABOUT) {
                            HorizontalDivider(Modifier.padding(vertical = 8.dp))
                        }
                        NavigationDrawerItem(
                            label = { Text(s.title) },
                            icon = { Icon(s.icon(), contentDescription = null) },
                            selected = s == screen,
                            onClick = {
                                vm.navigate(s)
                                scope.launch { drawer.close() }
                            },
                            modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
                        )
                    }
                }
            }
        },
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(screen.title) },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawer.open() } }) {
                            Icon(Icons.Filled.Menu, contentDescription = "Menu")
                        }
                    },
                    actions = {
                        when (link) {
                            Link.USB -> Icon(Icons.Filled.Usb, contentDescription = "USB",
                                tint = MaterialTheme.colorScheme.primary)
                            Link.NFC -> Icon(Icons.Filled.Nfc, contentDescription = "NFC",
                                tint = MaterialTheme.colorScheme.primary)
                            Link.NONE -> Unit
                        }
                        IconButton(onClick = { core.refreshNow() }, enabled = !busy) {
                            Icon(Icons.Filled.Refresh, contentDescription = "Refresh")
                        }
                    },
                )
            },
            snackbarHost = { SnackbarHost(snackbar) },
        ) { padding ->
            Box(
                Modifier
                    .padding(padding)
                    .fillMaxSize()
            ) {
                when (screen) {
                    Screen.HOME -> HomeScreen(vm)
                    Screen.ACCOUNTS -> AccountsScreen(vm)
                    Screen.PASSKEYS -> PasskeysScreen(vm)
                    Screen.CERTIFICATES -> CertificatesScreen(vm)
                    Screen.SLOTS -> SlotsScreen(vm)
                    Screen.OPENPGP -> OpenPgpScreen(vm)
                    Screen.APPLICATIONS -> ApplicationsScreen(vm)
                    Screen.RESET -> ResetScreen(vm)
                    Screen.RECIPES -> RecipesScreen(vm)
                    Screen.FINGERPRINTS -> FingerprintsScreen(vm)
                    Screen.ABOUT -> LegalScreen()
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth().align(Alignment.TopCenter))
            }
        }
    }

    if (!accepted) {
        TermsGate(
            onAccepted = { acceptTerms(context); accepted = true },
            onDeclined = { (context as? Activity)?.finish() },
        )
    }

    tapPrompt?.let { what ->
        AlertDialog(
            onDismissRequest = { core.cancelPrompt() },
            icon = { Icon(Icons.Filled.Nfc, contentDescription = null, modifier = Modifier.size(40.dp)) },
            title = { Text(if (what.startsWith("Unplug")) "Re-insert your YubiKey" else "Scan your YubiKey") },
            text = { Text(what) },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { core.cancelPrompt() }) { Text("Cancel") } },
        )
    }

    if (touchPrompt) {
        AlertDialog(
            onDismissRequest = {},
            icon = { Icon(Icons.Filled.TouchApp, contentDescription = null, modifier = Modifier.size(40.dp)) },
            title = { Text("Touch your YubiKey") },
            text = { Text("Touch the gold contact on your YubiKey when it blinks.") },
            confirmButton = {},
        )
    }

    dialog?.let { d ->
        AlertDialog(
            onDismissRequest = { core.clearDialog() },
            title = { Text(d.title) },
            text = {
                SelectionContainer {
                    Text(d.body, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                }
            },
            confirmButton = { TextButton(onClick = { core.clearDialog() }) { Text("Done") } },
            dismissButton = d.copyValue?.let { v ->
                { TextButton(onClick = { copyToClipboard(context, d.title, v) }) { Text("Copy") } }
            },
        )
    }
}

@Composable
fun TransportRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label); Text(value)
    }
}
