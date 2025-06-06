# EncryptedSharedPrefs

A modern Kotlin-based secure alternative to the deprecated `EncryptedSharedPreferences` on Android. This utility class ensures that sensitive app data is encrypted even when stored locally, mitigating risks posed by rooted devices and potential data extraction attacks.

---

## Why Use EncryptedSharedPrefs?

While modern Android versions implement strong sandboxing and user-level isolation mechanisms, **they are not foolproof**. In cases where a device is:

- **Rooted** (privileged access),
- **Userdata partition physically compromised**,
- **Affected by vendor-specific daemons**,

An attacker may extract unprotected app data. Default `SharedPreferences` stores data in plain-text format within the app's sandbox, making it vulnerable in such scenarios.

`EncryptedSharedPrefs` offers an extra layer of defense by encrypting sensitive fields individually using secure and modern cryptographic techniques.

---

## Should I Use This Implementation Over Other Available?

✅ Yes — if:

- You need a small, lightweight utility class configured to cover 80% of real-world use cases.
- You want secure encryption under the hood without worrying about manual setup.
- You prefer minimal dependencies and easy integration.
- You are comfortable adjusting it slightly if you have custom needs (e.g., adding key invalidation handling, changing cipher configs).

❌ No — if:

- You are looking for a full-featured library with a broad set of APIs.
- You need to choose between multiple encryption providers, cipher modes, or want fine-grained configuration (e.g., biometric binding, remote key management).
- You expect extensive features like migration utilities, backward compatibility layers, or audit-ready key management.

In this implementation, we intentionally sacrificed the ```getAll()``` method and chose SHA-256 hashing for key names instead of encrypting them.

This decision was made because:

- Hashing is significantly faster than encryption, reducing overhead during read/write operations.
- Encrypted keys would require a cipher initialization and encryption per access, which can be a performance bottleneck, especially on older or mid-range devices.
- Hashing ensures key obfuscation to prevent metadata leakage while providing better performance for most use cases.

As a result:
- ```getAll()``` returns an empty map (original keys can't be reconstructed).
- Read and write performance is optimized for frequent access patterns.

This trade-off is suitable for apps that require strong security but prioritize speed in preference storage operations.

---

## Tips for Usage

### Provide as a Singleton via Dependency Injection
⚠️ **Important**:

Avoid creating new instances of EncryptedSharedPrefs in short-lived components (like Fragments, ViewModels).
Each instance creation accesses the Android Keystore and loads (or creates) cryptographic keys.
This is a relatively expensive operation and can lead to unnecessary performance overhead if done frequently.

For best practices, it is recommended to expose a **single instance** of `EncryptedSharedPrefs` through a dependency injection framework like **Hilt** or **Dagger**.

Example using **Hilt**:

```kotlin
private const val PREFS_NAME = "SecurePrefs"

@Module
@InstallIn(SingletonComponent::class)
object SecurePrefsModule {

    @Provides
    @Singleton
    fun provideEncryptedSharedPreferences(
        @ApplicationContext context: Context
    ): EncryptedSharedPrefs {
        return EncryptedSharedPrefs(context, PREFS_NAME)
    }
}
```

---

## Features

- **Secure Encryption**: Utilizes **AES-256 GCM** for encryption with keys securely stored in **Android Keystore**.
- **Hashing of Keys**: All keys are SHA-256 hashed before storage to prevent metadata leakage.
- **Kotlin-first Implementation**: Fully written in Kotlin, leveraging:
  - **Inline Functions** with `reified` type parameters to avoid boilerplate and ensure type safety without casting.
- **Thread-Safe Asynchronous Operations**: apply() using a background executor to avoid blocking the main thread.
- **Mitigation of Deprecated API**: Provides a self-contained secure alternative now that `EncryptedSharedPreferences` is deprecated.

---

## How It Works

### Encryption Algorithm

- **Cipher**: AES (Advanced Encryption Standard)
- **Mode**: GCM (Galois/Counter Mode) — provides both confidentiality and integrity.
- **Padding**: NoPadding.
- **Key Size**: 256-bit AES key.
- **IV Size**: 12 bytes (96 bits) random per encryption.
- **Authentication Tag**: 16 bytes (128 bits).

### Key Management

Keys are generated and stored securely using the Android Keystore system:

```kotlin
KeyGenParameterSpec.Builder(
    keyAlias,
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
.setKeySize(256)
.setUserAuthenticationRequired(false)
.build()
```

The secret key never leaves the secure hardware (when available) and is used for all encryption and decryption operations.

## Kotlin Language Features

Inline Functions with reified Types

The getValue and putValue functions leverages reified type parameters, allowing a single generic method for all types:
```kotlin
private inline fun <reified T> getValue(key: String, defaultValue: T): T
private inline fun <reified T> putValue(key: String, value: T)
```
This design minimizes code duplication and maximizes type safety without resorting to unsafe casts or reflection.

## Limitations
- Key Hashing: Key names are hashed with SHA-256, making getAll() return an empty map because the original keys cannot be reconstructed.
- Preference Change Listeners: Not fully supported, as listeners would receive encrypted key names instead of the original keys.
- No Automatic Migration: Existing unencrypted SharedPreferences must be migrated manually.


## Architecture Overview

| Component    | Description |
| -------- | ------- |
| AES-256   | GCM	Symmetric encryption with integrity check   |
| Android  | Keystore	Secure hardware-backed key storage    |
| SHA-256	    | Key hashing to prevent key metadata leakage    |
| Inline + reified | Compile-time type inference, no need for unsafe casting |

## Security Considerations

- Always validate the root integrity using tools like SafetyNet Attestation.
- Encrypt only truly sensitive data to maintain performance.
- Consider setting setUserAuthenticationRequired(true) for keys if you require biometrics or device credentials for decryption.

## Contributing

Contributions are welcome! Please open an issue first to discuss what you would like to change.
 
