package com.your.package

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import org.json.JSONArray
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
private const val GCM_IV_LENGTH = 12
private const val GCM_TAG_LENGTH = 16

class EncryptedSharedPrefs(
    context: Context, prefsName: String
) : SharedPreferences {
    private val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    private val keyAlias: String = "prefs_master_key_${prefsName.hashCode()}"

    // Cache the key for better performance
    private val secretKey: SecretKey by lazy {
        generateSecretKeyIfNeeded()
        retrieveSecretKey()
    }

    // Generic put method
    private inline fun <reified T> putValue(key: String, value: T) {
        val hashedKey = hashKey(key)
        val bytes = when (T::class) {
            String::class -> (value as String).toByteArray(StandardCharsets.UTF_8)
            Boolean::class -> byteArrayOf(if (value as Boolean) 1 else 0)
            Int::class -> ByteBuffer.allocate(4).putInt(value as Int).array()
            Long::class -> ByteBuffer.allocate(8).putLong(value as Long).array()
            Float::class -> ByteBuffer.allocate(4).putFloat(value as Float).array()
            Set::class -> {
                val jsonArray = JSONArray()
                @Suppress("UNCHECKED_CAST")
                (value as Set<String>).forEach { jsonArray.put(it) }
                jsonArray.toString().toByteArray(StandardCharsets.UTF_8)
            }

            else -> throw IllegalArgumentException("Unsupported type: ${T::class}")
        }
        val encrypted = encrypt(bytes)
        prefs.edit { putString(hashedKey, encrypted) }
    }

    // Generic get method
    private inline fun <reified T> getValue(key: String, defaultValue: T): T {
        val hashedKey = hashKey(key)
        val encrypted = prefs.getString(hashedKey, null) ?: return defaultValue

        return try {
            val decrypted = decrypt(encrypted)
            when (T::class) {
                String::class -> {
                    String(decrypted, StandardCharsets.UTF_8) as T
                }

                Boolean::class -> {
                    (decrypted.isNotEmpty() && decrypted[0] == 1.toByte()) as T
                }

                Int::class -> {
                    if (decrypted.size >= 4) {
                        ByteBuffer.wrap(decrypted).int as T
                    } else defaultValue
                }

                Long::class -> {
                    if (decrypted.size >= 8) {
                        ByteBuffer.wrap(decrypted).long as T
                    } else defaultValue
                }

                Float::class -> {
                    if (decrypted.size >= 4) {
                        ByteBuffer.wrap(decrypted).float as T
                    } else defaultValue
                }

                else -> defaultValue
            }
        } catch (e: Exception) {
            defaultValue
        }
    }

    // SharedPreferences interface implementation
    override fun getAll(): Map<String, *> {
        // Note: We can't reverse-hash the keys, so we return empty map
        // This is a limitation of the encrypted approach
        return emptyMap<String, Any?>()
    }

    override fun getString(key: String, defValue: String?): String? {
        val hashedKey = hashKey(key)
        val encrypted = prefs.getString(hashedKey, null) ?: return defValue

        return try {
            val decrypted = decrypt(encrypted)
            String(decrypted, StandardCharsets.UTF_8)
        } catch (e: Exception) {
            defValue
        }
    }

    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? {
        val hashedKey = hashKey(key)
        val encrypted = prefs.getString(hashedKey, null) ?: return defValues

        return try {
            val decrypted = decrypt(encrypted)
            val jsonString = String(decrypted, StandardCharsets.UTF_8)
            val jsonArray = JSONArray(jsonString)
            val set = mutableSetOf<String>()
            for (i in 0 until jsonArray.length()) {
                set.add(jsonArray.getString(i))
            }
            set
        } catch (e: Exception) {
            defValues
        }
    }

    override fun getInt(key: String, defValue: Int): Int = getValue(key, defValue)

    override fun getLong(key: String, defValue: Long): Long = getValue(key, defValue)

    override fun getFloat(key: String, defValue: Float): Float = getValue(key, defValue)

    override fun getBoolean(key: String, defValue: Boolean): Boolean = getValue(key, defValue)

    override fun contains(key: String): Boolean {
        val hashedKey = hashKey(key)
        return prefs.contains(hashedKey)
    }

    override fun edit(): SharedPreferences.Editor {
        return EncryptedEditor()
    }

    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
        // Note: Change listeners receives the hashed key, not the original key
        prefs.registerOnSharedPreferenceChangeListener(listener)
    }

    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }

    // Inner Editor class that implements SharedPreferences.Editor
    private inner class EncryptedEditor : SharedPreferences.Editor {
        private val lock = ReentrantLock()
        private val executor = Executors.newSingleThreadExecutor()
        private val pendingOperations = mutableListOf<() -> Unit>()
        private var shouldClear = false

        override fun putString(key: String, value: String?): SharedPreferences.Editor {
            if (value != null) {
                addPendingOperation { putValue(key, value) }
            } else {
                addPendingOperation { remove(key) }
            }
            return this
        }

        override fun putStringSet(
            key: String, values: MutableSet<String>?
        ): SharedPreferences.Editor {
            if (values != null) {
                addPendingOperation { putValue(key, values) }
            } else {
                addPendingOperation { remove(key) }
            }
            return this
        }

        override fun putInt(key: String, value: Int): SharedPreferences.Editor {
            addPendingOperation { putValue(key, value) }
            return this
        }

        override fun putLong(key: String, value: Long): SharedPreferences.Editor {
            addPendingOperation { putValue(key, value) }
            return this
        }

        override fun putFloat(key: String, value: Float): SharedPreferences.Editor {
            addPendingOperation { putValue(key, value) }
            return this
        }

        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor {
            addPendingOperation { putValue(key, value) }
            return this
        }

        override fun remove(key: String): SharedPreferences.Editor {
            addPendingOperation {
                val hashedKey = hashKey(key)
                prefs.edit { remove(hashedKey) }
            }
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            shouldClear = true
            pendingOperations.clear()
            return this
        }

        override fun commit(): Boolean {
            return try {
                applyOperations()
                true
            } catch (e: Exception) {
                false
            }
        }

        override fun apply() {
            // Asynchronous operation - runs in background
            executor.execute {
                try {
                    applyOperations()
                } catch (e: Exception) {
                    // Apply doesn't return success/failure, just handle silently
                    // In production, you might want to somehow log this error
                }
            }
        }

        private fun addPendingOperation(operation: () -> Unit) {
            lock.lock()
            try {
                pendingOperations.add(operation)
            } finally {
                lock.unlock()
            }
        }

        private fun applyOperations() {
            lock.lock()
            try {
                if (shouldClear) {
                    prefs.edit { clear() }
                }
                pendingOperations.forEach { it.invoke() }
                pendingOperations.clear()
            } finally {
                lock.unlock()
            }
        }
    }

    // ---------------- Internal crypto methods ----------------

    private fun generateSecretKeyIfNeeded() {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(keyAlias)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEYSTORE_PROVIDER
            )
            val spec = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false) // Explicit for clarity
                .build()
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }
    }

    private fun retrieveSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return (keyStore.getEntry(keyAlias, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun hashKey(key: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(key.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(hashBytes, Base64.NO_WRAP)
    }

    private fun encrypt(plainBytes: ByteArray): String {
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plainBytes)

        // Combine IV + ciphertext for storage
        val combined = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(ciphertext, 0, combined, iv.size, ciphertext.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decrypt(encryptedData: String): ByteArray {
        val combined = Base64.decode(encryptedData, Base64.NO_WRAP)

        // Extract IV and ciphertext
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv) // 128-bit auth tag
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(ciphertext)
    }
}
