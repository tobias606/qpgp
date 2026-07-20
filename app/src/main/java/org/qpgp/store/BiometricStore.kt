package org.qpgp.store

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.qpgp.protocol.Wire
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * OPT-IN biometric unlock.
 *
 * HONEST DESIGN NOTE: a fingerprint cannot derive a key. The only sound
 * construction is to seal the passphrase under a hardware Keystore AES key
 * that (a) is non-exportable, (b) REQUIRES biometric authentication for
 * every single use (setUserAuthenticationRequired + BIOMETRIC_STRONG), and
 * (c) is INVALIDATED the moment any new fingerprint is enrolled
 * (setInvalidatedByBiometricEnrollment). The BiometricPrompt authenticates
 * the decryption Cipher itself (CryptoObject), so the OS refuses the crypto
 * operation without a fresh successful biometric — the prompt cannot be
 * bypassed by UI tampering.
 *
 * TRADEOFF (shown to the user before enabling): anyone with the unlocked-
 * enrollment set (your finger, or a coerced finger) plus the device opens
 * the vault. The passphrase path always remains available.
 */
class BiometricStore(private val ctx: Context) {

    private val file: File get() = File(ctx.filesDir, "bio.qpgp")

    fun isEnabled(): Boolean = file.exists()

    /** Cipher to hand to BiometricPrompt for ENABLING (encrypt direction). */
    fun encryptCipher(): Cipher {
        val ks = KeyStore.getInstance(ANDROID_KS).apply { load(null) }
        ks.deleteEntry(KEY_ALIAS)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (android.os.Build.VERSION.SDK_INT >= 30)
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KS)
        gen.init(spec)
        val key = gen.generateKey()
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    /** After BiometricPrompt success (enable flow): seal passphrase with the authenticated cipher. */
    fun finishEnable(passphrase: CharArray, authedCipher: Cipher) {
        val pw = String(passphrase).toByteArray(Charsets.UTF_8)
        val sealed = authedCipher.doFinal(pw)
        pw.fill(0)
        val out = Wire.Writer().byte(1).raw(authedCipher.iv).bytes(sealed)
        file.writeBytes(out.done())
    }

    /** Cipher to hand to BiometricPrompt for UNLOCKING (decrypt direction). */
    fun decryptCipher(): Cipher {
        val r = Wire.Reader(file.readBytes())
        if (r.byte() != 1) throw Wire.MalformedException("bio format")
        val iv = r.raw(12)
        val ks = KeyStore.getInstance(ANDROID_KS).apply { load(null) }
        val key = ks.getKey(KEY_ALIAS, null) as SecretKey
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        }
    }

    /** After BiometricPrompt success (unlock flow): recover the passphrase. */
    fun finishUnlock(authedCipher: Cipher): CharArray {
        val r = Wire.Reader(file.readBytes())
        r.byte(); r.raw(12)
        val sealed = r.bytes(4096)
        val pw = authedCipher.doFinal(sealed)
        val chars = String(pw, Charsets.UTF_8).toCharArray()
        pw.fill(0)
        return chars
    }

    /** Disable: remove sealed blob + destroy the Keystore key. */
    fun disable() {
        runCatching { if (file.exists()) { file.writeBytes(ByteArray(file.length().toInt())); file.delete() } }
        runCatching {
            KeyStore.getInstance(ANDROID_KS).apply { load(null) }.deleteEntry(KEY_ALIAS)
        }
    }

    companion object {
        private const val ANDROID_KS = "AndroidKeyStore"
        private const val KEY_ALIAS = "qpgp.bio.v1"
    }
}
