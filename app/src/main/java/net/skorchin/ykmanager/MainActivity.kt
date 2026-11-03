package net.skorchin.ykmanager

import android.os.Bundle
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
    }

    override fun onResume() {
        super.onResume()
        vm.core.startNfcDiscovery(this)
    }

    override fun onPause() {
        vm.core.stopNfcDiscovery(this)
        super.onPause()
    }
}
