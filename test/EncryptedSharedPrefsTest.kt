package com.your.package

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

@RunWith(RobolectricTestRunner::class)
class EncryptedSharedPrefsTest {
    private lateinit var context: Context
    private lateinit var prefs: EncryptedSharedPrefs
    private lateinit var keyProvider: InMemorySecretKeyProvider

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keyProvider = InMemorySecretKeyProvider()

        context
            .getSharedPreferences("test_prefs", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()

        prefs =
            EncryptedSharedPrefs(
                context = context,
                prefsName = "test_prefs",
                secretKeyProvider = keyProvider,
            )
    }

    @Test
    fun `putString and getString returns stored value`() {
        prefs
            .edit()
            .putString("name", "Alice")
            .commit()

        assertEquals("Alice", prefs.getString("name", null))
    }

    @Test
    fun `putString null removes value`() {
        prefs
            .edit()
            .putString("token", "abc")
            .commit()

        prefs
            .edit()
            .putString("token", null)
            .commit()

        assertNull(prefs.getString("token", null))
        assertFalse(prefs.contains("token"))
    }

    @Test
    fun `putStringSet and getStringSet returns stored set`() {
        val values = mutableSetOf("a", "b", "c")

        prefs
            .edit()
            .putStringSet("letters", values)
            .commit()

        assertEquals(values, prefs.getStringSet("letters", null))
    }

    @Test
    fun `putStringSet null removes value`() {
        prefs
            .edit()
            .putStringSet("letters", mutableSetOf("a", "b"))
            .commit()

        prefs
            .edit()
            .putStringSet("letters", null)
            .commit()

        assertNull(prefs.getStringSet("letters", null))
        assertFalse(prefs.contains("letters"))
    }

    @Test
    fun `putInt and getInt returns stored value`() {
        prefs
            .edit()
            .putInt("age", 42)
            .commit()

        assertEquals(42, prefs.getInt("age", 0))
    }

    @Test
    fun `putLong and getLong returns stored value`() {
        prefs
            .edit()
            .putLong("timestamp", 123456789L)
            .commit()

        assertEquals(123456789L, prefs.getLong("timestamp", 0L))
    }

    @Test
    fun `putFloat and getFloat returns stored value`() {
        prefs
            .edit()
            .putFloat("ratio", 3.14f)
            .commit()

        assertEquals(3.14f, prefs.getFloat("ratio", 0f), 0.0001f)
    }

    @Test
    fun `putBoolean and getBoolean returns stored value`() {
        prefs
            .edit()
            .putBoolean("enabled", true)
            .commit()

        assertTrue(prefs.getBoolean("enabled", false))
    }

    @Test
    fun `missing values return defaults`() {
        assertEquals("default", prefs.getString("missing_string", "default"))
        assertEquals(7, prefs.getInt("missing_int", 7))
        assertEquals(9L, prefs.getLong("missing_long", 9L))
        assertEquals(1.5f, prefs.getFloat("missing_float", 1.5f), 0.0001f)
        assertTrue(prefs.getBoolean("missing_boolean", true))
        assertEquals(
            mutableSetOf("default"),
            prefs.getStringSet("missing_set", mutableSetOf("default")),
        )
    }

    @Test
    fun `contains returns true for stored key`() {
        prefs
            .edit()
            .putString("token", "abc")
            .commit()

        assertTrue(prefs.contains("token"))
    }

    @Test
    fun `remove deletes stored key`() {
        prefs
            .edit()
            .putString("token", "abc")
            .commit()

        prefs
            .edit()
            .remove("token")
            .commit()

        assertFalse(prefs.contains("token"))
        assertNull(prefs.getString("token", null))
    }

    @Test
    fun `clear removes all stored values`() {
        prefs
            .edit()
            .putString("name", "Alice")
            .putInt("age", 42)
            .putBoolean("enabled", true)
            .commit()

        prefs
            .edit()
            .clear()
            .commit()

        assertFalse(prefs.contains("name"))
        assertFalse(prefs.contains("age"))
        assertFalse(prefs.contains("enabled"))

        assertNull(prefs.getString("name", null))
        assertEquals(0, prefs.getInt("age", 0))
        assertFalse(prefs.getBoolean("enabled", false))
    }

    @Test
    fun `clear followed by put keeps new value only`() {
        prefs
            .edit()
            .putString("old_key", "old")
            .putInt("old_number", 100)
            .commit()

        prefs
            .edit()
            .clear()
            .putString("new_key", "new")
            .commit()

        assertFalse(prefs.contains("old_key"))
        assertFalse(prefs.contains("old_number"))

        assertTrue(prefs.contains("new_key"))
        assertEquals("new", prefs.getString("new_key", null))
    }

    @Test
    fun `put before clear survives because clear is applied first`() {
        prefs
            .edit()
            .putString("old_key", "old")
            .commit()

        prefs
            .edit()
            .putString("temporary_key", "temporary")
            .clear()
            .commit()

        assertFalse(prefs.contains("old_key"))
        assertTrue(prefs.contains("temporary_key"))
        assertEquals("temporary", prefs.getString("temporary_key", null))
    }

    @Test
    fun `clear followed by remove does not crash`() {
        prefs
            .edit()
            .putString("key", "value")
            .commit()

        val result =
            prefs
                .edit()
                .clear()
                .remove("key")
                .commit()

        assertTrue(result)
        assertFalse(prefs.contains("key"))
    }

    @Test
    fun `stored raw SharedPreferences value is encrypted and key is hashed`() {
        prefs
            .edit()
            .putString("secret", "plain_text")
            .commit()

        val rawPrefs = context.getSharedPreferences("test_prefs", Context.MODE_PRIVATE)

        assertFalse(rawPrefs.contains("secret"))

        val rawValues = rawPrefs.all
        assertEquals(1, rawValues.size)

        val storedValue = rawValues.values.first() as String

        assertFalse(storedValue.contains("plain_text"))
    }

    @Test
    fun `same key provider can decrypt across prefs instances`() {
        prefs
            .edit()
            .putString("token", "abc")
            .commit()

        val secondInstance =
            EncryptedSharedPrefs(
                context = context,
                prefsName = "test_prefs",
                secretKeyProvider = keyProvider,
            )

        assertEquals("abc", secondInstance.getString("token", null))
    }

    @Test
    fun `different key provider cannot decrypt existing value and returns default`() {
        prefs
            .edit()
            .putString("token", "abc")
            .commit()

        val secondInstance =
            EncryptedSharedPrefs(
                context = context,
                prefsName = "test_prefs",
                secretKeyProvider = InMemorySecretKeyProvider(),
            )

        assertEquals("default", secondInstance.getString("token", "default"))
    }

    @Test
    fun `getAll returns empty map`() {
        prefs
            .edit()
            .putString("name", "Alice")
            .commit()

        assertTrue(prefs.all.isEmpty())
    }

    class InMemorySecretKeyProvider : SecretKeyProvider {
        private val keys = mutableMapOf<String, SecretKey>()

        override fun getOrCreateKey(alias: String): SecretKey =
            keys.getOrPut(alias) {
                val keyGenerator = KeyGenerator.getInstance("AES")
                keyGenerator.init(256)
                keyGenerator.generateKey()
            }
    }
}
