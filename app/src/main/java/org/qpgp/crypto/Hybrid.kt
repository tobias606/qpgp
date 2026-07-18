package org.qpgp.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * qPGP hybrid cryptography core.
 *
 * PRINCIPLES
 *  - Hybrid everything: breaking the composite requires breaking BOTH the
 *    post-quantum primitive AND the classical primitive.
 *      KEM       : ML-KEM-1024 (FIPS 203) + X25519  -> HKDF-SHA-512 combiner
 *      Signature : ML-DSA-87  (FIPS 204) + Ed25519  -> both must verify
 *      AEAD      : ChaCha20-Poly1305, one fresh key per message
 *      PBKDF     : Argon2id
 *  - No custom primitives. Only composition of audited BouncyCastle code.
 *  - Every derived secret is domain-separated with an explicit info string.
 */
object Hybrid {

    val rng = SecureRandom()

    const val PROTO = "QPGP-v1"

    // ---------- containers ----------

    class KemPublic(val mlkem: ByteArray, val x25519: ByteArray)
    class KemKeyPair(val pub: KemPublic, val mlkemSecret: ByteArray, val x25519Secret: ByteArray)
    class SigPublic(val mldsa: ByteArray, val ed25519: ByteArray)
    class SigKeyPair(val pub: SigPublic, val mldsaSecret: ByteArray, val ed25519Secret: ByteArray)
    class Encapsulation(val mlkemCiphertext: ByteArray, val ephemeralX25519Pub: ByteArray, val sharedSecret: ByteArray)

    // ---------- key generation ----------

    fun generateKem(): KemKeyPair {
        val g = MLKEMKeyPairGenerator()
        g.init(MLKEMKeyGenerationParameters(rng, MLKEMParameters.ml_kem_1024))
        val kp = g.generateKeyPair()
        val pk = kp.public as MLKEMPublicKeyParameters
        val sk = kp.private as MLKEMPrivateKeyParameters

        val xSk = X25519PrivateKeyParameters(rng)
        val xPk = xSk.generatePublicKey()
        return KemKeyPair(KemPublic(pk.encoded, xPk.encoded), sk.encoded, xSk.encoded)
    }

    fun generateSig(): SigKeyPair {
        val g = MLDSAKeyPairGenerator()
        g.init(MLDSAKeyGenerationParameters(rng, MLDSAParameters.ml_dsa_87))
        val kp = g.generateKeyPair()
        val pk = kp.public as MLDSAPublicKeyParameters
        val sk = kp.private as MLDSAPrivateKeyParameters

        val eSk = Ed25519PrivateKeyParameters(rng)
        val ePk = eSk.generatePublicKey()
        return SigKeyPair(SigPublic(pk.encoded, ePk.encoded), sk.encoded, eSk.encoded)
    }

    // ---------- hybrid KEM ----------

    /** Encapsulate to a recipient's hybrid public key. Fresh shared secret per call. */
    fun encapsulate(to: KemPublic): Encapsulation {
        // ML-KEM leg
        val kemPub = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, to.mlkem)
        val enc = MLKEMGenerator(rng).generateEncapsulated(kemPub)
        val ssKem = enc.secret

        // X25519 leg (fresh ephemeral key per message)
        val ephSk = X25519PrivateKeyParameters(rng)
        val agree = X25519Agreement()
        agree.init(ephSk)
        val ssX = ByteArray(agree.agreementSize)
        agree.calculateAgreement(X25519PublicKeyParameters(to.x25519), ssX, 0)

        val ss = combine(ssKem, ssX, to)
        ssKem.fill(0); ssX.fill(0)
        return Encapsulation(enc.encapsulation, ephSk.generatePublicKey().encoded, ss)
    }

    /** Decapsulate with our hybrid secret key. */
    fun decapsulate(mine: KemKeyPair, mlkemCiphertext: ByteArray, ephemeralX25519Pub: ByteArray): ByteArray {
        val ssKem = MLKEMExtractor(
            MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, mine.mlkemSecret)
        ).extractSecret(mlkemCiphertext)

        val agree = X25519Agreement()
        agree.init(X25519PrivateKeyParameters(mine.x25519Secret))
        val ssX = ByteArray(agree.agreementSize)
        agree.calculateAgreement(X25519PublicKeyParameters(ephemeralX25519Pub), ssX, 0)

        val ss = combine(ssKem, ssX, mine.pub)
        ssKem.fill(0); ssX.fill(0)
        return ss
    }

    /** KEM combiner: HKDF-SHA-512 over both shared secrets, bound to the recipient key. */
    private fun combine(ssKem: ByteArray, ssX: ByteArray, recipient: KemPublic): ByteArray {
        val ikm = ssKem + ssX
        val salt = sha512(recipient.mlkem + recipient.x25519) // binds ss to recipient key
        val out = hkdf(ikm, salt, "$PROTO/hybrid-kem".toByteArray(), 32)
        ikm.fill(0)
        return out
    }

    // ---------- dual signature ----------

    /** Sign with BOTH ML-DSA-87 and Ed25519. Returns (mldsaSig, ed25519Sig). */
    fun sign(kp: SigKeyPair, data: ByteArray): Pair<ByteArray, ByteArray> {
        val m = MLDSASigner()
        m.init(true, MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, kp.mldsaSecret))
        m.update(data, 0, data.size)
        val mldsaSig = m.generateSignature()

        val e = Ed25519Signer()
        e.init(true, Ed25519PrivateKeyParameters(kp.ed25519Secret))
        e.update(data, 0, data.size)
        val edSig = e.generateSignature()
        return Pair(mldsaSig, edSig)
    }

    /** Verify BOTH signatures. A single failure rejects the message. */
    fun verify(pub: SigPublic, data: ByteArray, mldsaSig: ByteArray, edSig: ByteArray): Boolean {
        return try {
            val m = MLDSASigner()
            m.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, pub.mldsa))
            m.update(data, 0, data.size)
            if (!m.verifySignature(mldsaSig)) return false

            val e = Ed25519Signer()
            e.init(false, Ed25519PublicKeyParameters(pub.ed25519))
            e.update(data, 0, data.size)
            e.verifySignature(edSig)
        } catch (t: Throwable) {
            false
        }
    }

    // ---------- AEAD ----------

    /** ChaCha20-Poly1305 seal. Key MUST be fresh/unique per call (we derive one per message). */
    fun aeadSeal(key32: ByteArray, ad: ByteArray, plaintext: ByteArray): ByteArray {
        require(key32.size == 32)
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val c = ChaCha20Poly1305()
        c.init(true, ParametersWithIV(KeyParameter(key32), nonce))
        c.processAADBytes(ad, 0, ad.size)
        val out = ByteArray(c.getOutputSize(plaintext.size))
        val n = c.processBytes(plaintext, 0, plaintext.size, out, 0)
        c.doFinal(out, n)
        return nonce + out
    }

    /** Open. Throws on any tamper. */
    fun aeadOpen(key32: ByteArray, ad: ByteArray, sealed: ByteArray): ByteArray {
        require(key32.size == 32)
        require(sealed.size > 12 + 16) { "ciphertext too short" }
        val nonce = sealed.copyOfRange(0, 12)
        val ct = sealed.copyOfRange(12, sealed.size)
        val c = ChaCha20Poly1305()
        c.init(false, ParametersWithIV(KeyParameter(key32), nonce))
        c.processAADBytes(ad, 0, ad.size)
        val out = ByteArray(c.getOutputSize(ct.size))
        val n = c.processBytes(ct, 0, ct.size, out, 0)
        val fin = c.doFinal(out, n)
        return out.copyOf(n + fin)
    }

    // ---------- KDFs & hashing ----------

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, len: Int): ByteArray {
        val g = HKDFBytesGenerator(SHA512Digest())
        g.init(HKDFParameters(ikm, salt, info))
        val out = ByteArray(len)
        g.generateBytes(out, 0, len)
        return out
    }

    /**
     * Argon2id for the vault passphrase. 64 MiB / 3 iterations / 2 lanes:
     * deliberately heavy for offline brute force, tolerable on a phone.
     */
    fun argon2id(passphrase: CharArray, salt: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(64 * 1024)
            .withIterations(3)
            .withParallelism(2)
            .build()
        val g = Argon2BytesGenerator()
        g.init(params)
        val out = ByteArray(32)
        g.generateBytes(passphrase, out, 0, out.size)
        return out
    }

    fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)

    /** 32-byte identity fingerprint over both signature public keys. */
    fun fingerprint(pub: SigPublic): ByteArray =
        hkdf(pub.mldsa + pub.ed25519, ByteArray(0), "$PROTO/fingerprint".toByteArray(), 32)

    /** 8-byte identifier of a hybrid KEM public key (used in message headers). */
    fun keyId(pub: KemPublic): ByteArray =
        hkdf(pub.mlkem + pub.x25519, ByteArray(0), "$PROTO/key-id".toByteArray(), 8)

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var r = 0
        for (i in a.indices) r = r or (a[i].toInt() xor b[i].toInt())
        return r == 0
    }
}
