package net.skorchin.ykmanager.yubi

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import androidx.core.content.edit

/**
 * Persists OATH access keys ("Remember on this phone"), keyed by the OATH
 * application's device ID. Keys are encrypted with an AES-GCM key that lives
 * in the Android Keystore, so the stored bytes are useless off the device.
 * Nothing here is backed up (allowBackup is false).
 */
class AccessKeyStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("oath_access_keys", Context.MODE_PRIVATE)

    fun get(deviceId: String): ByteArray? {
        val stored = prefs.getString(deviceId, null) ?: return null
        return runCatching {
            val blob = Base64.decode(stored, Base64.NO_WRAP)
            val iv = blob.copyOfRange(0, IV_LEN)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv))
            cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)
        }.getOrElse {
            // Logs the OATH device ID (a public identifier) and the exception, never key material.
            Log.w(TAG, "Dropping unreadable remembered key for $deviceId", it) // nosemgrep: mobsf.mobsfscan.kotlin.android.android_kotlin_logging
            remove(deviceId)
            null
        }
    }

    fun put(deviceId: String, key: ByteArray) {
        runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey())
            val blob = cipher.iv + cipher.doFinal(key)
            prefs.edit { putString(deviceId, Base64.encodeToString(blob, Base64.NO_WRAP)) }
        }.onFailure { Log.w(TAG, "Could not remember the OATH password", it) } // nosemgrep: mobsf.mobsfscan.kotlin.android.android_kotlin_logging
    }

    fun contains(deviceId: String) = prefs.contains(deviceId)

    fun remove(deviceId: String) { prefs.edit { remove(deviceId) } }

    fun clear() { prefs.edit { clear() } }

    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    private companion object {
        const val TAG = "AccessKeyStore"
        const val ALIAS = "ykmanager.oath.accesskeys"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}
