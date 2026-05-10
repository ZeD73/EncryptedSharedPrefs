package com.your.package

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
private const val GCM_IV_LENGTH = 12
private const val GCM_TAG_LENGTH = 16

fun interface SecretKeyProvider {
    fun getOrCreateKey(alias: String): SecretKey
}

class AndroidKeyStoreSecretKeyProvider : SecretKeyProvider {
    override fun getOrCreateKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        if (!keyStore.containsAlias(alias)) {
            val keyGenerator =
                KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    KEYSTORE_PROVIDER,
                )

            val spec =
                KeyGenParameterSpec
                    .Builder(
                        alias,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                    ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false)
                    .build()

            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }

        return (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
    }
}

class EncryptedSharedPrefs(
    context: Context,
    prefsName: String,
    private val secretKeyProvider: SecretKeyProvider = AndroidKeyStoreSecretKeyProvider(),
) : SharedPreferences {
    private val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    private val keyAlias: String = "prefs_master_key_${prefsName.hashCode()}"

    // Cache the key for better performance
    private val secretKey: SecretKey by lazy {
        secretKeyProvider.getOrCreateKey(keyAlias)
    }

    private inline fun <reified T> getValue(
        key: String,
        defaultValue: T,
    ): T {
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
                    } else {
                        defaultValue
                    }
                }

                Long::class -> {
                    if (decrypted.size >= 8) {
                        ByteBuffer.wrap(decrypted).long as T
                    } else {
                        defaultValue
                    }
                }

                Float::class -> {
                    if (decrypted.size >= 4) {
                        ByteBuffer.wrap(decrypted).float as T
                    } else {
                        defaultValue
                    }
                }

                else -> {
                    defaultValue
                }
            }
        } catch (_: Exception) {
            defaultValue
        }
    }

    override fun getAll(): Map<String, *> = emptyMap<String, Any?>()

    override fun getString(
        key: String,
        defValue: String?,
    ): String? {
        val hashedKey = hashKey(key)
        val encrypted = prefs.getString(hashedKey, null) ?: return defValue

        return try {
            val decrypted = decrypt(encrypted)
            String(decrypted, StandardCharsets.UTF_8)
        } catch (_: Exception) {
            defValue
        }
    }

    override fun getStringSet(
        key: String,
        defValues: MutableSet<String>?,
    ): MutableSet<String>? {
        val hashedKey = hashKey(key)
        val encrypted = prefs.getString(hashedKey, null) ?: return defValues

        return try {
            val decrypted = decrypt(encrypted)
            val jsonArray = JSONArray(String(decrypted, StandardCharsets.UTF_8))
            val set = mutableSetOf<String>()

            for (i in 0 until jsonArray.length()) {
                set.add(jsonArray.getString(i))
            }

            set
        } catch (_: Exception) {
            defValues
        }
    }

    override fun getInt(
        key: String,
        defValue: Int,
    ): Int = getValue(key, defValue)

    override fun getLong(
        key: String,
        defValue: Long,
    ): Long = getValue(key, defValue)

    override fun getFloat(
        key: String,
        defValue: Float,
    ): Float = getValue(key, defValue)

    override fun getBoolean(
        key: String,
        defValue: Boolean,
    ): Boolean = getValue(key, defValue)

    override fun contains(key: String): Boolean = prefs.contains(hashKey(key))

    override fun edit(): SharedPreferences.Editor = EncryptedEditor()

    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
        // Note: Change listeners receives the hashed key, not the original key
        prefs.registerOnSharedPreferenceChangeListener(listener)
    }

    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }

    private inner class EncryptedEditor : SharedPreferences.Editor {
        private val editor: SharedPreferences.Editor = prefs.edit()

        override fun putString(
            key: String,
            value: String?,
        ): SharedPreferences.Editor {
            val hashedKey = hashKey(key)

            if (value == null) {
                editor.remove(hashedKey)
            } else {
                val encrypted = encrypt(value.toByteArray(StandardCharsets.UTF_8))
                editor.putString(hashedKey, encrypted)
            }

            return this
        }

        override fun putStringSet(
            key: String,
            values: MutableSet<String>?,
        ): SharedPreferences.Editor {
            val hashedKey = hashKey(key)

            if (values == null) {
                editor.remove(hashedKey)
            } else {
                val jsonArray = JSONArray()
                values.forEach { jsonArray.put(it) }

                val encrypted =
                    encrypt(
                        jsonArray.toString().toByteArray(StandardCharsets.UTF_8),
                    )

                editor.putString(hashedKey, encrypted)
            }

            return this
        }

        override fun putInt(
            key: String,
            value: Int,
        ): SharedPreferences.Editor {
            val encrypted = encrypt(ByteBuffer.allocate(4).putInt(value).array())
            editor.putString(hashKey(key), encrypted)
            return this
        }

        override fun putLong(
            key: String,
            value: Long,
        ): SharedPreferences.Editor {
            val encrypted = encrypt(ByteBuffer.allocate(8).putLong(value).array())
            editor.putString(hashKey(key), encrypted)
            return this
        }

        override fun putFloat(
            key: String,
            value: Float,
        ): SharedPreferences.Editor {
            val encrypted = encrypt(ByteBuffer.allocate(4).putFloat(value).array())
            editor.putString(hashKey(key), encrypted)
            return this
        }

        override fun putBoolean(
            key: String,
            value: Boolean,
        ): SharedPreferences.Editor {
            val encrypted = encrypt(byteArrayOf(if (value) 1 else 0))
            editor.putString(hashKey(key), encrypted)
            return this
        }

        override fun remove(key: String): SharedPreferences.Editor {
            editor.remove(hashKey(key))
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            editor.clear()
            return this
        }

        override fun commit(): Boolean = editor.commit()

        override fun apply() {
            editor.apply()
        }
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

        require(combined.size > GCM_IV_LENGTH) {
            "Invalid encrypted data"
        }

        // Extract IV and ciphertext
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv) // 128-bit auth tag
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(ciphertext)
    }
}
