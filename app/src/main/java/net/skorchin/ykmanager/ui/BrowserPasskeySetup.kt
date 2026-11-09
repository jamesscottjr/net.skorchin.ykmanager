package net.skorchin.ykmanager.ui

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/**
 * Chrome only hands passkey and password requests to providers like
 * YK Manager when "Autofill using another service" is on. Chrome reports
 * that setting through a content provider; see
 * https://developer.android.com/identity/autofill/autofill-services#enable-autofill-chrome
 */
object BrowserPasskeySetup {

    data class Browser(val packageName: String, val label: String)

    val CHROME_CHANNELS = listOf(
        Browser("com.android.chrome", "Chrome"),
        Browser("com.chrome.beta", "Chrome Beta"),
        Browser("com.chrome.dev", "Chrome Dev"),
        Browser("com.chrome.canary", "Chrome Canary"),
    )

    /** true = uses another service, false = Google built-in, null = unknown (old Chrome or not readable). */
    data class Status(val browser: Browser, val usesAnotherService: Boolean?)

    fun installed(context: Context): List<Browser> = CHROME_CHANNELS.filter {
        runCatching { context.packageManager.getPackageInfo(it.packageName, 0); true }.getOrDefault(false)
    }

    fun status(context: Context): List<Status> = installed(context).map { Status(it, read(context, it.packageName)) }

    private fun read(context: Context, pkg: String): Boolean? = runCatching {
        val uri = Uri.Builder()
            .scheme(ContentResolver.SCHEME_CONTENT)
            .authority("$pkg.AutofillThirdPartyModeContentProvider")
            .path("autofill_third_party_mode")
            .build()
        context.contentResolver.query(uri, arrayOf("autofill_third_party_state"), null, null, null)?.use { c ->
            if (!c.moveToFirst()) return@use null
            val i = c.getColumnIndex("autofill_third_party_state")
            if (i == -1) null else c.getInt(i) != 0
        }
    }.getOrNull()

    /** Opens Chrome's Autofill services settings page. */
    fun openChromeSettings(context: Context, pkg: String): Boolean {
        val intent = Intent(Intent.ACTION_APPLICATION_PREFERENCES)
            .addCategory(Intent.CATEGORY_DEFAULT)
            .addCategory(Intent.CATEGORY_APP_BROWSER)
            .addCategory(Intent.CATEGORY_PREFERENCE)
            .setPackage(pkg)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY) == null) {
            return runCatching {
                context.startActivity(context.packageManager.getLaunchIntentForPackage(pkg)!!.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                false
            }.getOrDefault(false)
        }
        return runCatching { context.startActivity(intent); true }.getOrDefault(false)
    }
}
