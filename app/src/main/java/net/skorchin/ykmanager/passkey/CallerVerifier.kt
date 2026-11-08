package net.skorchin.ykmanager.passkey

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Works out who is asking for a passkey, and on whose behalf.
 *
 * A passkey provider is responsible for the check a browser normally does:
 * a credential for example.com may only be used by example.com.
 *
 * - Browsers (Chrome, Firefox, Edge, Samsung Internet, ...) pass the web
 *   origin. They are trusted to do so only if their package and signing
 *   certificate are on Google's privileged-browser list.
 * - Native apps get the origin "android:apk-key-hash:<cert hash>", and may
 *   only use the site's passkeys if the site lists the app in its Digital
 *   Asset Links file (https://<rpId>/.well-known/assetlinks.json).
 */
object CallerVerifier {

    sealed class Result {
        data class Allowed(
            /** Origin placed into clientDataJSON (web origin or android:apk-key-hash:...). */
            val origin: String,
            /** Domain the RP ID is validated against. */
            val effectiveDomain: String,
            /** Human-readable caller, for example "Chrome" or "com.example.app". */
            val callerLabel: String,
            val isBrowser: Boolean,
        ) : Result()

        data class Rejected(val reason: String) : Result()
    }

    private const val ALLOWLIST_ASSET = "privileged_browsers.json"
    private const val ALLOWLIST_FILE = "privileged_browsers.json"
    private const val ALLOWLIST_URL = "https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json"
    private const val REFRESH_MS = 24L * 60 * 60 * 1000

    private val assetLinkCache = ConcurrentHashMap<String, Pair<Long, Boolean>>()

    @RequiresApi(34)
    suspend fun verify(context: Context, info: CallingAppInfo, rpId: String?): Result = withContext(Dispatchers.IO) {
        val pkg = info.packageName
        val label = appLabel(context, pkg)

        // 1. A browser calling on behalf of a website.
        if (info.isOriginPopulated()) {
            val origin = try {
                info.getOrigin(privilegedAllowlist(context))
            } catch (e: Exception) {
                null
            }
            if (origin.isNullOrBlank()) {
                return@withContext Result.Rejected(
                    "$label passed a website address but is not on the list of browsers trusted to do so. " +
                        "Use Chrome, Firefox, Edge, Brave, Samsung Internet or another major browser."
                )
            }
            val clean = origin.trimEnd('/')
            val host = Uri.parse(clean).host?.lowercase(Locale.ROOT)
                ?: return@withContext Result.Rejected("The browser sent an invalid website address.")
            return@withContext Result.Allowed(clean, host, label, isBrowser = true)
        }

        // 2. A native app. The site must vouch for the app via Digital Asset Links.
        val id = rpId?.lowercase(Locale.ROOT)
            ?: return@withContext Result.Rejected("The app did not say which website the passkey is for.")
        val hashes = certHashes(info)
        if (hashes.isEmpty()) return@withContext Result.Rejected("Could not read the signature of $label.")
        val ok = assetLinksAllow(id, pkg, hashes.map { it.toFingerprint() })
        if (!ok) {
            return@withContext Result.Rejected(
                "$id does not list $label as one of its apps (Digital Asset Links), so its passkeys can't be used here. " +
                    "This check protects you from look-alike apps."
            )
        }
        val origin = "android:apk-key-hash:" +
            Base64.encodeToString(hashes.first(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        Result.Allowed(origin, id, label, isBrowser = false)
    }

    /** Label for the calling app; falls back to the package name. */
    @RequiresApi(34)
    fun appLabel(context: Context, pkg: String): String = runCatching {
        val pm = context.packageManager
        pm.getApplicationLabel(pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))).toString()
    }.getOrNull()?.takeIf { it.isNotBlank() } ?: KNOWN_LABELS[pkg] ?: pkg

    private val KNOWN_LABELS = mapOf(
        "com.android.chrome" to "Chrome",
        "org.mozilla.firefox" to "Firefox",
        "com.microsoft.emmx" to "Edge",
        "com.brave.browser" to "Brave",
        "com.sec.android.app.sbrowser" to "Samsung Internet",
        "com.duckduckgo.mobile.android" to "DuckDuckGo",
        "com.vivaldi.browser" to "Vivaldi",
        "com.opera.browser" to "Opera",
        "app.vanadium.browser" to "Vanadium",
    )

    // ------------------------------------------------------------------
    // Privileged browser list
    // ------------------------------------------------------------------

    /** The newest valid copy of Google's privileged-browser list (downloaded, else bundled). */
    fun privilegedAllowlist(context: Context): String {
        val f = File(context.filesDir, ALLOWLIST_FILE)
        if (f.exists()) runCatching { f.readText().also { validate(it) } }.getOrNull()?.let { return it }
        return context.assets.open(ALLOWLIST_ASSET).bufferedReader().use { it.readText() }
    }

    /** Download a fresh list at most once a day. Failures keep the current copy. */
    fun refreshAllowlistIfStale(context: Context) {
        val f = File(context.filesDir, ALLOWLIST_FILE)
        if (f.exists() && System.currentTimeMillis() - f.lastModified() < REFRESH_MS) return
        runCatching {
            val text = httpGet(ALLOWLIST_URL, 512 * 1024) ?: return
            validate(text)
            val tmp = File(context.filesDir, "$ALLOWLIST_FILE.tmp")
            tmp.writeText(text)
            tmp.renameTo(f)
        }
    }

    private fun validate(json: String) {
        val apps = JSONObject(json).getJSONArray("apps")
        require(apps.length() > 0)
    }

    // ------------------------------------------------------------------
    // Digital Asset Links
    // ------------------------------------------------------------------

    @RequiresApi(34)
    private fun certHashes(info: CallingAppInfo): List<ByteArray> {
        val si = info.signingInfo
        val certs = if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        return certs.orEmpty().map { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()) }
    }

    private fun ByteArray.toFingerprint(): String = joinToString(":") { "%02X".format(it) }

    private fun assetLinksAllow(rpId: String, pkg: String, fingerprints: List<String>): Boolean {
        val key = "$rpId|$pkg|${fingerprints.joinToString()}"
        assetLinkCache[key]?.let { (time, ok) ->
            if (System.currentTimeMillis() - time < 60 * 60 * 1000) return ok
        }
        val ok = runCatching {
            val text = httpGet("https://$rpId/.well-known/assetlinks.json", 256 * 1024) ?: return@runCatching false
            val statements = JSONArray(text)
            (0 until statements.length()).any { i ->
                val s = statements.getJSONObject(i)
                val relations = s.optJSONArray("relation") ?: return@any false
                val rel = (0 until relations.length()).map { relations.getString(it) }
                val relevant = rel.any {
                    it == "delegate_permission/common.get_login_creds" ||
                        it == "delegate_permission/common.handle_all_urls"
                }
                val target = s.optJSONObject("target") ?: return@any false
                if (!relevant || target.optString("namespace") != "android_app") return@any false
                if (target.optString("package_name") != pkg) return@any false
                val fps = target.optJSONArray("sha256_cert_fingerprints") ?: return@any false
                (0 until fps.length()).any { j -> fps.getString(j).uppercase(Locale.ROOT) in fingerprints }
            }
        }.getOrDefault(false)
        assetLinkCache[key] = System.currentTimeMillis() to ok
        return ok
    }

    private fun httpGet(url: String, maxBytes: Int): String? {
        val c = URL(url).openConnection() as HttpURLConnection
        return try {
            c.connectTimeout = 8_000
            c.readTimeout = 8_000
            c.instanceFollowRedirects = false // Asset Links must be served without redirects
            c.setRequestProperty("Accept", "application/json")
            if (c.responseCode != 200) return null
            val bytes = c.inputStream.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8192)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > maxBytes) return null
                }
                out.toByteArray()
            }
            String(bytes, Charsets.UTF_8)
        } finally {
            c.disconnect()
        }
    }
}
