package org.kelopatra.protocol

import org.kelopatra.crypto.Hybrid

/**
 * Kelopatra message protocol v1 — offline pairwise messaging with
 * continuous KEM key rotation ("ratchet by correspondence").
 *
 * ROTATION DESIGN (hardened version of the user's scheme):
 *   - Each party advertises a hybrid KEM public key. Every message a sender
 *     writes carries a FRESH next KEM public key for replies, placed INSIDE
 *     the AEAD ciphertext and covered by the dual signature. An attacker who
 *     cannot break the current message cannot inject a rogue rotation key.
 *   - The receiver updates the contact's current key but RETAINS previous
 *     keys (window of KEY_WINDOW) so messages encrypted to an older key still
 *     decrypt — exactly the "keep the old one just in case" requirement.
 *   - The sender likewise retains its last KEY_WINDOW private keys, because
 *     the peer may not have received the newest advertisement yet.
 *   - Effect: every exchanged message heals the session (post-compromise
 *     security); compromise of one message key does not expose others
 *     (forward secrecy at rotation granularity).
 *
 * ENVELOPE (outer, visible to anyone holding the ciphertext):
 *   ver(1) | recipientKeyId(8) | mlkemCt | ephX25519Pub | aeadSealed
 *   -> reveals nothing but an 8-byte pseudonymous key id.
 *
 * INNER (inside AEAD, after decryption):
 *   senderFingerprint(32) | counter(8) | nextKemPub(mlkem,x25519) |
 *   message | mldsaSig | edSig
 *   Signature covers: PROTO || ver || recipientKeyId || senderFp || counter ||
 *                     nextKemPub || message   (identity binding, no misbinding)
 */
object Protocol {

    const val VERSION = 1
    const val KEY_WINDOW = 3          // previous keys kept per direction
    const val REPLAY_WINDOW = 64      // seen-counter memory per contact

    class Outgoing(val wire: ByteArray, val newOwnKeyPair: Hybrid.KemKeyPair, val counter: Long)

    class Incoming(
        val message: ByteArray,
        val senderFingerprint: ByteArray,
        val counter: Long,
        val theirNextKey: Hybrid.KemPublic,
        /** true if this message was encrypted to one of our OLDER keys */
        val usedOldKey: Boolean
    )

    /**
     * Encrypt [message] to [theirCurrentKem], signing with [ourSig].
     * Generates and embeds a fresh own KEM keypair for the peer's next reply.
     */
    fun seal(
        ourSig: Hybrid.SigKeyPair,
        theirCurrentKem: Hybrid.KemPublic,
        counter: Long,
        message: ByteArray
    ): Outgoing {
        require(message.size <= Wire.MAX_MESSAGE) { "message too large" }
        val nextOwn = Hybrid.generateKem()
        val recipientKeyId = Hybrid.keyId(theirCurrentKem)
        val senderFp = Hybrid.fingerprint(ourSig.pub)

        val signedBody = signedData(recipientKeyId, senderFp, counter, nextOwn.pub, message)
        val (mldsaSig, edSig) = Hybrid.sign(ourSig, signedBody)

        val inner = Wire.Writer()
            .raw(senderFp)
            .raw(longBytes(counter))
            .bytes(nextOwn.pub.mlkem)
            .bytes(nextOwn.pub.x25519)
            .bytes(message)
            .bytes(mldsaSig)
            .bytes(edSig)
            .done()

        val enc = Hybrid.encapsulate(theirCurrentKem)
        val msgKey = Hybrid.hkdf(enc.sharedSecret, recipientKeyId, "${Hybrid.PROTO}/msg-key".toByteArray(), 32)
        enc.sharedSecret.fill(0)
        val ad = adBytes(recipientKeyId)
        val sealed = Hybrid.aeadSeal(msgKey, ad, inner)
        msgKey.fill(0)

        val wire = Wire.Writer()
            .byte(VERSION)
            .raw(recipientKeyId)
            .bytes(enc.mlkemCiphertext)
            .bytes(enc.ephemeralX25519Pub)
            .bytes(sealed)
            .done()

        return Outgoing(wire, nextOwn, counter)
    }

    /** Peek the recipient key id so the caller can select the right private key. */
    fun peekRecipientKeyId(wire: ByteArray): ByteArray {
        val r = Wire.Reader(wire)
        val ver = r.byte()
        if (ver != VERSION) throw Wire.MalformedException("unsupported version $ver")
        return r.raw(8)
    }

    /**
     * Decrypt and authenticate. [ourKemForThatId] must be the keypair whose
     * keyId matches the header. [expectedSender] pins the contact identity:
     * a valid signature from anyone else is REJECTED (prevents cross-contact
     * substitution).
     */
    fun open(
        wire: ByteArray,
        ourKemForThatId: Hybrid.KemKeyPair,
        expectedSender: Hybrid.SigPublic,
        usedOldKey: Boolean
    ): Incoming {
        val r = Wire.Reader(wire)
        val ver = r.byte()
        if (ver != VERSION) throw Wire.MalformedException("unsupported version $ver")
        val recipientKeyId = r.raw(8)
        val mlkemCt = r.bytes()
        val ephX = r.bytes()
        val sealed = r.bytes(Wire.MAX_FIELD + Wire.MAX_MESSAGE)
        r.requireEnd()

        val ss = Hybrid.decapsulate(ourKemForThatId, mlkemCt, ephX)
        val msgKey = Hybrid.hkdf(ss, recipientKeyId, "${Hybrid.PROTO}/msg-key".toByteArray(), 32)
        ss.fill(0)
        val inner = Hybrid.aeadOpen(msgKey, adBytes(recipientKeyId), sealed)
        msgKey.fill(0)

        val ir = Wire.Reader(inner)
        val senderFp = ir.raw(32)
        val counter = bytesLong(ir.raw(8))
        val nextMlkem = ir.bytes()
        val nextX = ir.bytes()
        val message = ir.bytes(Wire.MAX_MESSAGE)
        val mldsaSig = ir.bytes()
        val edSig = ir.bytes()
        ir.requireEnd()

        // Identity pinning: sender fingerprint must match the expected contact.
        val expectedFp = Hybrid.fingerprint(expectedSender)
        if (!Hybrid.constantTimeEquals(senderFp, expectedFp))
            throw SecurityException("Sender identity mismatch — possible impersonation or wrong contact selected")

        val nextKey = Hybrid.KemPublic(nextMlkem, nextX)
        val signedBody = signedData(recipientKeyId, senderFp, counter, nextKey, message)
        if (!Hybrid.verify(expectedSender, signedBody, mldsaSig, edSig))
            throw SecurityException("Signature verification FAILED — message forged or corrupted")

        return Incoming(message, senderFp, counter, nextKey, usedOldKey)
    }

    private fun signedData(
        recipientKeyId: ByteArray, senderFp: ByteArray, counter: Long,
        nextKey: Hybrid.KemPublic, message: ByteArray
    ): ByteArray = Wire.Writer()
        .raw("${Hybrid.PROTO}/sig".toByteArray())
        .byte(VERSION)
        .raw(recipientKeyId)
        .raw(senderFp)
        .raw(longBytes(counter))
        .bytes(nextKey.mlkem)
        .bytes(nextKey.x25519)
        .bytes(message)
        .done()

    private fun adBytes(recipientKeyId: ByteArray): ByteArray =
        "${Hybrid.PROTO}/ad".toByteArray() + byteArrayOf(VERSION.toByte()) + recipientKeyId

    fun longBytes(v: Long): ByteArray {
        val b = ByteArray(8)
        for (i in 0..7) b[i] = (v ushr (56 - 8 * i)).toByte()
        return b
    }

    fun bytesLong(b: ByteArray): Long {
        var v = 0L
        for (i in 0..7) v = (v shl 8) or (b[i].toLong() and 0xff)
        return v
    }
}
