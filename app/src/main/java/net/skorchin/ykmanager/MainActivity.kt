package net.skorchin.ykmanager

import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import androidx.core.content.IntentCompat
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import net.skorchin.ykmanager.ui.AppRoot
import net.skorchin.ykmanager.ui.theme.YkManagerTheme
import net.skorchin.ykmanager.yubi.AppViewModel

class MainActivity : ComponentActivity() {

    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        vm.core.startUsbDiscovery()
        setContent {
            YkManagerTheme {
                AppRoot(vm)
            }
        }
        handleNfcIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleNfcIntent(intent)
    }

    /**
     * Fallback for taps the system dispatched as an NDEF/tag intent (the
     * manifest registers the YubiKey's NDEF URL). Normally reader mode
     * delivers taps directly; this catches the cases where Android handed
     * the tag to the system instead, so the user lands in the app with the
     * tap treated like any other scan.
     */
    private fun handleNfcIntent(intent: Intent?) {
        val action = intent?.action ?: return
        if (action != NfcAdapter.ACTION_NDEF_DISCOVERED && action != NfcAdapter.ACTION_TECH_DISCOVERED &&
            action != NfcAdapter.ACTION_TAG_DISCOVERED) return
        val tag = IntentCompat.getParcelableExtra(intent, NfcAdapter.EXTRA_TAG, Tag::class.java) ?: return
        intent.action = null // handle once
        vm.core.onNfcIntentTag(tag)
    }

    override fun onResume() {
        super.onResume()
        vm.core.startNfcDiscovery(this)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // Re-arm reader mode after dialogs, permission prompts or app switches.
        if (hasFocus) vm.core.startNfcDiscovery(this)
    }

    override fun onPause() {
        vm.core.stopNfcDiscovery(this)
        super.onPause()
    }
}
