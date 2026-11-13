package net.skorchin.ykmanager.yubi

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Base64
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.yubico.yubikit.oath.Base32
import java.net.URLDecoder
import java.net.URLEncoder
import androidx.core.graphics.scale

/** Decoding QR codes from images and turning their contents into otpauth:// URIs. */
object QrCodes {

    /**
     * Decode a QR code from an image the user picked. Tries several
     * binarizers, an inverted copy and a down-scaled copy, because screenshots
     * and photos of screens are often noisy or very large.
     */
    fun decodeImage(context: Context, uri: Uri): String? {
        val bitmap = loadBitmap(context, uri, 2000) ?: return null
        val attempts = listOfNotNull(bitmap, scaled(bitmap, 1000), scaled(bitmap, 600))
        for (bmp in attempts) {
            val w = bmp.width
            val h = bmp.height
            val pixels = IntArray(w * h)
            bmp.getPixels(pixels, 0, w, 0, 0, w, h)
            val source: LuminanceSource = RGBLuminanceSource(w, h, pixels)
            for (src in listOf(source, source.invert())) {
                for (binarizer in listOf({ HybridBinarizer(src) }, { GlobalHistogramBinarizer(src) })) {
                    val text = runCatching {
                        MultiFormatReader().apply {
                            setHints(mapOf(
                                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                                DecodeHintType.TRY_HARDER to true,
                            ))
                        }.decodeWithState(BinaryBitmap(binarizer())).text
                    }.getOrNull()
                    if (!text.isNullOrBlank()) return text
                }
            }
        }
        return null
    }

    private fun loadBitmap(context: Context, uri: Uri, maxSide: Int): Bitmap? {
        // Pass 1: read only the dimensions (decodeStream returns null by design here).
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        val probe = context.contentResolver.openInputStream(uri)
            ?: throw IllegalArgumentException("The image could not be opened")
        probe.use { BitmapFactory.decodeStream(it, null, bounds) }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) throw IllegalArgumentException("That file is not a readable image")
        // Pass 2: decode, down-sampling very large images.
        var sample = 1
        while (bounds.outWidth / sample > maxSide * 2 || bounds.outHeight / sample > maxSide * 2) sample *= 2
        val opts = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val bmp = context.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) }
            ?: throw IllegalArgumentException("The image could not be decoded")
        return if (bmp.config == Bitmap.Config.ARGB_8888) bmp else bmp.copy(Bitmap.Config.ARGB_8888, false)
    }

    private fun scaled(b: Bitmap, maxSide: Int): Bitmap? {
        val m = maxOf(b.width, b.height)
        if (m <= maxSide) return null
        val f = maxSide.toFloat() / m
        return b.scale((b.width * f).toInt().coerceAtLeast(1), (b.height * f).toInt().coerceAtLeast(1))
    }

    /**
     * Turn QR contents into otpauth:// URIs. Accepts a plain otpauth:// link
     * or a Google Authenticator export (otpauth-migration://offline?data=…),
     * which may contain several accounts.
     */
    fun toOtpAuthUris(text: String): List<String> {
        val t = text.trim()
        return when {
            t.startsWith("otpauth://", ignoreCase = true) -> listOf(t)
            t.startsWith("otpauth-migration://", ignoreCase = true) -> parseMigration(t)
            else -> emptyList()
        }
    }

    // ---- Google Authenticator export (protobuf MigrationPayload) -------------

    private fun parseMigration(uri: String): List<String> {
        val query = uri.substringAfter('?', "")
        val dataParam = query.split('&').firstOrNull { it.startsWith("data=") }?.substringAfter("data=")
            ?: throw IllegalArgumentException("The export link has no data")
        val raw = Base64.decode(URLDecoder.decode(dataParam, "UTF-8"), Base64.DEFAULT)
        val result = mutableListOf<String>()
        val payload = ProtoReader(raw)
        while (payload.hasMore()) {
            val (field, wire) = payload.tag()
            if (field == 1 && wire == 2) result += otpParameters(ProtoReader(payload.bytes()))
            else payload.skip(wire)
        }
        return result
    }

    private fun otpParameters(r: ProtoReader): String {
        var secret = ByteArray(0); var name = ""; var issuer = ""
        var algorithm = 1; var digits = 1; var type = 2; var counter = 0L
        while (r.hasMore()) {
            val (field, wire) = r.tag()
            when (field) {
                1 -> secret = r.bytes()
                2 -> name = String(r.bytes(), Charsets.UTF_8)
                3 -> issuer = String(r.bytes(), Charsets.UTF_8)
                4 -> algorithm = r.varint().toInt()
                5 -> digits = r.varint().toInt()
                6 -> type = r.varint().toInt()
                7 -> counter = r.varint()
                else -> r.skip(wire)
            }
        }
        val typeName = if (type == 1) "hotp" else "totp"
        val algName = when (algorithm) { 2 -> "SHA256"; 3 -> "SHA512"; else -> "SHA1" }
        val digitCount = if (digits == 2) 8 else 6
        val label = (if (issuer.isNotBlank() && !name.startsWith("$issuer:")) "$issuer:" else "") + name
        val enc = { s: String -> URLEncoder.encode(s, "UTF-8").replace("+", "%20") }
        val sb = StringBuilder("otpauth://$typeName/${enc(label)}?secret=${Base32.encode(secret).trimEnd('=')}&algorithm=$algName&digits=$digitCount")
        if (issuer.isNotBlank()) sb.append("&issuer=${enc(issuer)}")
        if (type == 1) sb.append("&counter=$counter") else sb.append("&period=30")
        return sb.toString()
    }

    /** Minimal protobuf wire-format reader. */
    private class ProtoReader(private val buf: ByteArray) {
        private var pos = 0
        fun hasMore() = pos < buf.size
        fun varint(): Long {
            var shift = 0; var result = 0L
            while (true) {
                if (pos >= buf.size) throw IllegalArgumentException("Truncated export data")
                val b = buf[pos++].toInt()
                result = result or ((b and 0x7F).toLong() shl shift)
                if (b and 0x80 == 0) return result
                shift += 7
            }
        }
        fun tag(): Pair<Int, Int> { val v = varint().toInt(); return (v ushr 3) to (v and 7) }
        fun bytes(): ByteArray {
            val len = varint().toInt()
            if (len < 0 || pos + len > buf.size) throw IllegalArgumentException("Truncated export data")
            return buf.copyOfRange(pos, pos + len).also { pos += len }
        }
        fun skip(wire: Int) {
            when (wire) {
                0 -> varint()
                1 -> pos += 8
                2 -> bytes()
                5 -> pos += 4
                else -> throw IllegalArgumentException("Unsupported export data")
            }
        }
    }
}
