package org.kelopatra.store

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.kelopatra.crypto.Hybrid
import org.kelopatra.protocol.Wire
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Layered vault-at-rest encryption.
 *
 *   layer 1 (inner): ChaCha20-Poly1305 under key derived by Argon2id(passphrase)
 *   layer 2 (outer): AES-256-GCM under a NON-EXPORTABLE Android Keystore key
 *                    (StrongBox when the device has it)
 *
 * An attacker needs BOTH the hardware-bound key (i.e. this physical, un-reset
 * device) AND the passphrase. Cloud/adb backups are useless (Keystore key
 * never leaves the device; manifest also sets allowBackup=false).
 *
 * File format: ver(1) | argonSalt(16) | iv(12) | gcmCiphertext(inner sealed)
 */
class Vault(private val ctx: Context) {

    private val file: File get() = File(ctx.filesDir, "vault.klp")

    fun exists(): Boolean = file.exists()

    fun save(data: VaultData, passphrase: CharArray) {
        val salt = ByteArray(16).also { Hybrid.rng.nextBytes(it) }
        val innerKey = Hybrid.argon2id(passphrase, salt)
        val plain = VaultCodec.encode(data)
        val innerSealed = Hybrid.aeadSeal(innerKey, AD, plain)
        plain.fill(0); innerKey.fill(0)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        val outer = cipher.doFinal(innerSealed)
        val iv = cipher.iv

        val out = Wire.Writer().byte(1).raw(salt).raw(iv)
            .bytes(outer.also { require(it.size < 32 * 1024 * 1024) })
        val tmp = File(ctx.filesDir, "vault.klp.tmp")
        tmp.writeBytes(out.done())
        if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) } // atomic-ish swap
    }

    fun load(passphrase: CharArray): VaultData {
        val r = Wire.Reader(file.readBytes())
        if (r.byte() != 1) throw Wire.MalformedException("vault format")
        val salt = r.raw(16)
        val iv = r.raw(12)
        val outer = r.bytes(32 * 1024 * 1024)
        r.requireEnd()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keystoreKey(), GCMParameterSpec(128, iv))
        val innerSealed = cipher.doFinal(outer)

        val innerKey = Hybrid.argon2id(passphrase, salt)
        val plain = try {
            Hybrid.aeadOpen(innerKey, AD, innerSealed)
        } finally {
            innerKey.fill(0)
        }
        val v = VaultCodec.decode(plain)
        plain.fill(0)
        return v
    }

    /** Crypto-shred: overwrite (best effort on flash) then delete + drop keystore key. */
    fun destroy() {
        if (file.exists()) {
            runCatching { file.writeBytes(ByteArray(file.length().toInt())) }
            file.delete()
        }
        runCatching {
            val ks = KeyStore.getInstance(ANDROID_KS).apply { load(null) }
            ks.deleteEntry(KEY_ALIAS)
        }
    }

    private fun keystoreKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KS).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        // Prefer StrongBox (dedicated secure element) when present.
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KS)
        return try {
            spec.setIsStrongBoxBacked(true)
            gen.init(spec.build()); gen.generateKey()
        } catch (e: Exception) {
            spec.setIsStrongBoxBacked(false)
            gen.init(spec.build()); gen.generateKey()
        }
    }

    companion object {
        private const val ANDROID_KS = "AndroidKeyStore"
        private const val KEY_ALIAS = "kelopatra.vault.v1"
        private val AD = "KELOPATRA-v1/vault".toByteArray()
    }
}
