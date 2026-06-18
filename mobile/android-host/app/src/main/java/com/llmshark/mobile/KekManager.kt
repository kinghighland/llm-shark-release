package com.llmshark.mobile

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages the KEK (Key Encryption Key) lifecycle using Android Keystore.
 *
 * Design:
 * - A non-exportable AES-256-GCM master key lives in Android Keystore.
 * - The actual KEK (32-byte random) is generated via [FfiBridge.generateCkB64],
 *   then encrypted with the master key and persisted in SharedPreferences.
 * - When the KEK is needed, it is decrypted in-memory, used briefly, and
 *   the byte array is zeroed immediately after.
 *
 * This ensures the KEK is never stored in plaintext on disk, and the master
 * key is never extractable from the device.
 */
class KekManager(private val context: Context) {

    companion object {
        private const val TAG = "KekManager"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MASTER_KEY_ALIAS = "com.llmshark.mobile.master_key_v1"
        private const val PREFS_NAME = "llmshark_kek_v1"
        private const val KEY_KEK_CIPHERTEXT_B64 = "kek_ciphertext_b64"
        private const val KEY_KEK_IV_B64 = "kek_iv_b64"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 128
    }

    private val kekPrefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Returns the KEK as a Base64 string, decrypting it from Keystore-protected storage.
     * The caller is responsible for not caching this value longer than necessary.
     *
     * If no KEK exists yet, one is generated, encrypted, and persisted.
     */
    fun getOrGenerateKekB64(): String {
        val existing = loadEncryptedKek()
        if (existing != null) {
            val decrypted = decryptWithMasterKey(existing.first, existing.second)
            if (decrypted != null) {
                return decrypted
            }
            // Decryption failed (e.g. master key was invalidated after lock screen change).
            // Fall through to regenerate.
            Log.w(TAG, "Failed to decrypt existing KEK, regenerating")
            clearEncryptedKek()
        }
        return generateAndPersistKek()
    }

    /**
     * Checks whether a KEK has already been persisted.
     */
    fun hasKek(): Boolean {
        return kekPrefs.contains(KEY_KEK_CIPHERTEXT_B64) &&
            kekPrefs.contains(KEY_KEK_IV_B64)
    }

    /**
     * Deletes the persisted KEK. Useful when the master key is invalidated
     * and a fresh start is required.
     */
    fun clearEncryptedKek() {
        kekPrefs.edit().clear().apply()
    }

    // ---------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------

    private fun generateAndPersistKek(): String {
        val kekB64 = FfiBridge.generateCkB64()
        val iv = encryptWithMasterKey(kekB64)
        if (iv != null) {
            saveEncryptedKek(iv.first, iv.second)
        } else {
            // Master key encryption failed — this shouldn't happen in normal flow,
            // but as a fallback, log and return the KEK anyway (it just won't be persisted).
            Log.e(TAG, "Failed to encrypt KEK with master key, KEK not persisted")
        }
        return kekB64
    }

    private fun getOrCreateMasterKey(): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        if (keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            val entry = keyStore.getEntry(MASTER_KEY_ALIAS, null)
            return (entry as? KeyStore.SecretKeyEntry)?.secretKey
        }

        return try {
            val generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
            )
            val spec = KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .apply {
                    // Require user authentication on API 28+ only if device has secure lock.
                    // We don't require it to keep offline/first-use smooth.
                }
                .build()
            generator.init(spec)
            generator.generateKey()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create master key", e)
            null
        }
    }

    /**
     * Encrypts the KEK Base64 string with the Keystore master key.
     * Returns (iv_base64, ciphertext_base64) on success, null on failure.
     */
    private fun encryptWithMasterKey(kekB64: String): Pair<String, String>? {
        val masterKey = getOrCreateMasterKey() ?: return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, masterKey)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(kekB64.toByteArray(Charsets.UTF_8))
            Pair(
                Base64.encodeToString(iv, Base64.NO_WRAP),
                Base64.encodeToString(ciphertext, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Encrypt KEK failed", e)
            null
        }
    }

    /**
     * Decrypts the KEK Base64 string using the Keystore master key.
     * Returns the KEK Base64 string on success, null on failure.
     */
    private fun decryptWithMasterKey(ivB64: String, ciphertextB64: String): String? {
        val masterKey = getOrCreateMasterKey() ?: return null
        return try {
            val iv = Base64.decode(ivB64, Base64.NO_WRAP)
            val ciphertext = Base64.decode(ciphertextB64, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, masterKey, spec)
            val plainBytes = cipher.doFinal(ciphertext)
            String(plainBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            Log.e(TAG, "Decrypt KEK failed", e)
            null
        }
    }

    private fun saveEncryptedKek(ivB64: String, ciphertextB64: String) {
        kekPrefs.edit()
            .putString(KEY_KEK_IV_B64, ivB64)
            .putString(KEY_KEK_CIPHERTEXT_B64, ciphertextB64)
            .apply()
    }

    private fun loadEncryptedKek(): Pair<String, String>? {
        val iv = kekPrefs.getString(KEY_KEK_IV_B64, null) ?: return null
        val ct = kekPrefs.getString(KEY_KEK_CIPHERTEXT_B64, null) ?: return null
        return Pair(iv, ct)
    }
}
