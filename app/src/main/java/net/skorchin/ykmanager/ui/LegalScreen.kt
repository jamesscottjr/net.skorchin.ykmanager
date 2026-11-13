package net.skorchin.ykmanager.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Gavel
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import net.skorchin.ykmanager.BuildConfig
import androidx.core.content.edit
import androidx.core.net.toUri

/** Bump when the Terms change so existing users are asked to accept again. */
const val TERMS_VERSION = 1
private const val PREFS = "legal"
private const val KEY_ACCEPTED = "terms_accepted_version"

fun termsAccepted(context: Context): Boolean =
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(KEY_ACCEPTED, 0) >= TERMS_VERSION

fun acceptTerms(context: Context) {
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit { putInt(KEY_ACCEPTED, TERMS_VERSION) }
}

object LegalText {
    const val EFFECTIVE = "November 1, 2026"

    val warranty = """
        THIS APPLICATION IS PROVIDED "AS IS" AND "AS AVAILABLE", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. THE DEVELOPER DOES NOT WARRANT THAT THE APPLICATION WILL BE ERROR-FREE, UNINTERRUPTED, OR COMPATIBLE WITH ANY PARTICULAR SECURITY KEY, DEVICE, OR FIRMWARE VERSION.

        TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE DEVELOPER SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL OR PUNITIVE DAMAGES, OR FOR ANY LOSS OF DATA, CREDENTIALS, ACCESS TO ACCOUNTS, OR USE OF A SECURITY KEY, ARISING OUT OF OR IN CONNECTION WITH YOUR USE OF THIS APPLICATION, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. THE DEVELOPER'S TOTAL LIABILITY SHALL NOT EXCEED THE AMOUNT YOU PAID FOR THE APPLICATION.
    """.trimIndent()

    val sections: List<Pair<String, String>> = listOf(
        "1. Acceptance" to
            "By installing or using YK Manager (the \"App\") you agree to these Terms of Use. If you do not agree, do not use the App.",

        "2. What the App does" to
            "The App lets you view and change the configuration of compatible hardware security keys over USB or NFC, " +
            "including OTP slots, OATH accounts, PIV certificates, FIDO2 credentials, fingerprints, OpenPGP settings, enabled applications, " +
            "and factory resets. The App runs entirely on your device and communicates only with the connected key.",

        "3. Your responsibility" to
            "Many operations are irreversible. Programming an OTP slot overwrites its previous contents; deleting accounts, " +
            "credentials or certificates cannot be undone; entering a wrong PIN, PUK or management key repeatedly will block it; " +
            "a factory reset permanently erases the affected application. You are solely responsible for understanding each " +
            "action before confirming it, for keeping backups or recovery methods for any account that depends on your key, " +
            "and for keeping your PINs and keys secret. The App is not a substitute for reading your security key's documentation.",

        "4. No warranty and limitation of liability" to warranty,

        "5. Not affiliated with Yubico" to
            "YK Manager is an independent application. It is not developed, endorsed, sponsored or supported by Yubico AB. " +
            "YubiKey and Yubico are registered trademarks of Yubico AB and are used only to describe compatibility. " +
            "For official support of your key, contact its manufacturer.",

        "6. Open source components" to
            "The App includes third-party open source software listed under \"Open source licenses\" below. Those components are " +
            "governed by their own licenses, which are reproduced there and which take precedence for those components.",

        "7. Privacy" to
            "The App does not collect, transmit or store any personal data. The only data kept on your device is a local " +
            "history of the OTP slot configurations you program, which you can clear at any time. See the Privacy Policy on " +
            "the store listing for details.",

        "8. Changes" to
            "These Terms may be updated with a new version of the App. If the Terms change materially you will be asked to " +
            "accept them again before continuing.",

        "9. Governing law" to
            "These Terms are governed by the laws of the State of Arizona, USA, without regard to conflict-of-law rules. " +
            "If any provision is held unenforceable, the remainder stays in effect.",
    )

    data class Notice(val name: String, val copyright: String, val license: String, val url: String)

    val notices = listOf(
        Notice("YubiKit for Android", "Copyright 2019-2024 Yubico AB", "Apache License 2.0",
            "https://github.com/Yubico/yubikit-android"),
        Notice("Bouncy Castle Crypto APIs", "Copyright 2000-2024 The Legion of the Bouncy Castle Inc.",
            "Bouncy Castle License (MIT-style)", "https://www.bouncycastle.org/licence.html"),
        Notice("ZXing Android Embedded", "Copyright 2012-2018 ZXing authors, Journey Mobile",
            "Apache License 2.0", "https://github.com/journeyapps/zxing-android-embedded"),
        Notice("ZXing (Zebra Crossing)", "Copyright 2008 ZXing authors", "Apache License 2.0",
            "https://github.com/zxing/zxing"),
        Notice("AndroidX and Jetpack Compose", "Copyright The Android Open Source Project",
            "Apache License 2.0", "https://developer.android.com/jetpack/androidx"),
        Notice("Kotlin and kotlinx.coroutines", "Copyright 2010-2024 JetBrains s.r.o. and Kotlin Programming Language contributors",
            "Apache License 2.0", "https://github.com/JetBrains/kotlin"),
    )

    val apache2 = """
        Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

            http://www.apache.org/licenses/LICENSE-2.0

        Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
    """.trimIndent()

    val bouncyCastle = """
        Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    """.trimIndent()
}

@Composable
private fun Heading(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(top = 16.dp, bottom = 4.dp))
}

@Composable
private fun Body(text: String) {
    Text(text, style = MaterialTheme.typography.bodyMedium)
}

@Composable
private fun TermsBody() {
    Text("Effective ${LegalText.EFFECTIVE}", style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
    LegalText.sections.forEach { (title, body) ->
        Heading(title)
        Body(body)
    }
}

/** Full "About & legal" screen reachable from the drawer. */
@Composable
fun LegalScreen() {
    val context = LocalContext.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
    ) {
        Text("YK Manager", style = MaterialTheme.typography.headlineSmall)
        Text("Version ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text("An independent manager for hardware security keys. Not affiliated with or endorsed by Yubico AB.",
            style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 8.dp))

        Card(
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("No warranty", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onErrorContainer)
                Text(
                    "This app changes the configuration of your security key. Operations such as programming a slot, " +
                        "deleting credentials or a factory reset are permanent. The app is provided \"as is\" without " +
                        "warranty of any kind; use it at your own risk.",
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(top = 4.dp),
                )
            }
        }

        Spacer(Modifier.height(8.dp))
        Text("Terms of Use", style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(top = 16.dp))
        TermsBody()

        HorizontalDivider(Modifier.padding(vertical = 24.dp))
        Text("Open source licenses", style = MaterialTheme.typography.titleLarge)
        Text("This app is built with the following open source software. We thank their authors.",
            style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp))
        LegalText.notices.forEach { n ->
            Heading(n.name)
            Text(n.copyright, style = MaterialTheme.typography.bodySmall)
            Text(n.license, style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = {
                runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, n.url.toUri())) }
            }) { Text(n.url, style = MaterialTheme.typography.bodySmall) }
        }

        Heading("Apache License, Version 2.0")
        Text(LegalText.apache2, style = MaterialTheme.typography.bodySmall)
        Heading("Bouncy Castle License")
        Text(LegalText.bouncyCastle, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(24.dp))
    }
}

/** First-run gate: must be accepted before the app can be used. */
@Composable
fun TermsGate(onAccepted: () -> Unit, onDeclined: () -> Unit) {
    AlertDialog(
        onDismissRequest = {},
        icon = { Icon(Icons.Filled.Gavel, contentDescription = null) },
        title = { Text("Terms of Use") },
        text = {
            Column(
                Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    "YK Manager changes the configuration of your security key. Some operations are permanent " +
                        "and cannot be undone. The app is provided \"as is\" without warranty of any kind.",
                    style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold,
                )
                Text("Please read and accept the Terms of Use to continue. You can review them later under About & legal.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                HorizontalDivider(Modifier.padding(vertical = 8.dp))
                TermsBody()
            }
        },
        confirmButton = { Button(onClick = onAccepted) { Text("I accept") } },
        dismissButton = { TextButton(onClick = onDeclined) { Text("Decline") } },
    )
}
