package org.qpgp.store

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.qpgp.crypto.Hybrid
import org.qpgp.protocol.Wire
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

    private val file: File get() = File(ctx.filesDir, "vault.qpgp")

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
        val tmp = File(ctx.filesDir, "vault.qpgp.tmp")
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

    /**
     * Vault destruction — forensic honesty:
     *
     * The PRIMARY erasure mechanism is CRYPTO-SHREDDING: destroying the
     * non-exportable Keystore key (held in TEE/StrongBox, never on flash)
     * makes every vault byte on disk permanently undecryptable, even if a
     * forensic lab images the raw flash and recovers old copies — those
     * copies are AES-GCM ciphertext whose key no longer exists anywhere.
     * Layer 2 (Argon2id passphrase) additionally protects any recovered
     * ciphertext even in the hypothetical case of a keystore compromise.
     *
     * We ALSO do best-effort multi-pass overwrite + delete of every app
     * file, but on flash (FTL wear-leveling) overwrite-in-place is not
     * guaranteed to hit the same physical cells — which is exactly why
     * crypto-shredding, not overwriting, carries the guarantee here.
     * This construction (key destruction in hardware) is the strongest
     * erasure primitive available on any phone.
     */
    fun destroy() {
        // 1. crypto-shred: kill BOTH keystore keys first (vault + biometric)
        runCatching {
            val ks = KeyStore.getInstance(ANDROID_KS).apply { load(null) }
            ks.deleteEntry(KEY_ALIAS)
            ks.deleteEntry("qpgp.bio.v1")
        }
        // 2. best-effort physical overwrite (3 passes: random, ones, zeros)
        //    of every file in our sandbox, then delete
        val rng = java.security.SecureRandom()
        fun shredFile(f: File) {
            runCatching {
                val len = f.length().toInt()
                if (len > 0) {
                    val buf = ByteArray(len)
                    rng.nextBytes(buf); f.writeBytes(buf)
                    java.util.Arrays.fill(buf, 0xFF.toByte()); f.writeBytes(buf)
                    java.util.Arrays.fill(buf, 0x00.toByte()); f.writeBytes(buf)
                }
            }
            runCatching { f.delete() }
        }
        fun shredDir(dir: File) {
            dir.listFiles()?.forEach { if (it.isDirectory) shredDir(it) else shredFile(it) }
            runCatching { dir.delete() }
        }
        // filesDir, cache, and any shared_prefs/databases siblings
        shredDir(ctx.filesDir)
        shredDir(ctx.cacheDir)
        ctx.filesDir.parentFile?.listFiles()?.forEach { sub ->
            if (sub.name in setOf("shared_prefs", "databases", "app_textures", "code_cache"))
                shredDir(sub)
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
        private const val KEY_ALIAS = "qpgp.vault.v1"
        private val AD = "QPGP-v1/vault".toByteArray()
    }
}
