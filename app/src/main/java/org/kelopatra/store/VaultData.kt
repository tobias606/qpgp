package org.kelopatra.store

import org.kelopatra.crypto.Hybrid
import org.kelopatra.protocol.Protocol
import org.kelopatra.protocol.Wire

/**
 * In-memory model of everything the vault holds. Serialized with the same
 * rigid Wire format and sealed under the vault key by [Vault].
 *
 * Contact key state implements the rotation window:
 *   theirKeys[0]  = their newest advertised KEM key (encrypt to this)
 *   theirKeys[1..] = older keys kept for reference
 *   ourKeys[0]    = our newest KEM keypair (advertised in our last message)
 *   ourKeys[1..]  = older keypairs kept so late messages still decrypt
 */
class Contact(
    var name: String,
    val sigPub: Hybrid.SigPublic,
    val theirKeys: ArrayDeque<Hybrid.KemPublic> = ArrayDeque(),
    val ourKeys: ArrayDeque<Hybrid.KemKeyPair> = ArrayDeque(),
    var sendCounter: Long = 0,
    val seenCounters: ArrayDeque<Long> = ArrayDeque(),
    var verified: Boolean = false
) {
    fun fingerprint(): ByteArray = Hybrid.fingerprint(sigPub)

    fun pushTheirKey(k: Hybrid.KemPublic) {
        // Ignore exact duplicates (peer resent same rotation key)
        if (theirKeys.isNotEmpty() && Hybrid.constantTimeEquals(Hybrid.keyId(theirKeys.first()), Hybrid.keyId(k))) return
        theirKeys.addFirst(k)
        while (theirKeys.size > Protocol.KEY_WINDOW) theirKeys.removeLast()
    }

    fun pushOurKey(k: Hybrid.KemKeyPair) {
        ourKeys.addFirst(k)
        while (ourKeys.size > Protocol.KEY_WINDOW) {
            val dead = ourKeys.removeLast()
            // forward secrecy: destroy expired private keys
            dead.mlkemSecret.fill(0)
            dead.x25519Secret.fill(0)
        }
    }

    fun findOurKeyById(keyId: ByteArray): Pair<Hybrid.KemKeyPair, Boolean>? {
        ourKeys.forEachIndexed { idx, kp ->
            if (Hybrid.constantTimeEquals(Hybrid.keyId(kp.pub), keyId)) return Pair(kp, idx > 0)
        }
        return null
    }

    /** Replay protection: reject counters we've already accepted. */
    fun checkAndRecordCounter(c: Long): Boolean {
        if (seenCounters.contains(c)) return false
        seenCounters.addFirst(c)
        while (seenCounters.size > Protocol.REPLAY_WINDOW) seenCounters.removeLast()
        return true
    }
}

class Identity(
    val sig: Hybrid.SigKeyPair,
    /** Our long-term "introduction" KEM keypair, shared when adding contacts. */
    val introKem: Hybrid.KemKeyPair
)

class VaultData(
    var identity: Identity? = null,
    val contacts: MutableList<Contact> = mutableListOf()
)

/** Serialization of VaultData <-> bytes (rigid Wire format, versioned). */
object VaultCodec {
    private const val VAULT_VERSION = 1
    private const val SK_CAP = 8 * 1024

    fun encode(v: VaultData): ByteArray {
        val w = Wire.Writer().byte(VAULT_VERSION)
        val id = v.identity
        w.byte(if (id != null) 1 else 0)
        if (id != null) {
            w.bytes(id.sig.pub.mldsa).bytes(id.sig.pub.ed25519)
            w.bytes(id.sig.mldsaSecret).bytes(id.sig.ed25519Secret)
            writeKemPair(w, id.introKem)
        }
        w.byte(v.contacts.size.coerceAtMost(255))
        for (c in v.contacts) {
            w.bytes(c.name.toByteArray(Charsets.UTF_8))
            w.bytes(c.sigPub.mldsa).bytes(c.sigPub.ed25519)
            w.byte(c.theirKeys.size)
            for (k in c.theirKeys) { w.bytes(k.mlkem); w.bytes(k.x25519) }
            w.byte(c.ourKeys.size)
            for (k in c.ourKeys) writeKemPair(w, k)
            w.raw(Protocol.longBytes(c.sendCounter))
            w.byte(c.seenCounters.size)
            for (s in c.seenCounters) w.raw(Protocol.longBytes(s))
            w.byte(if (c.verified) 1 else 0)
        }
        return w.done()
    }

    fun decode(data: ByteArray): VaultData {
        val r = Wire.Reader(data)
        val ver = r.byte()
        if (ver != VAULT_VERSION) throw Wire.MalformedException("vault version $ver unsupported")
        val v = VaultData()
        if (r.byte() == 1) {
            val sigPub = Hybrid.SigPublic(r.bytes(), r.bytes())
            val sig = Hybrid.SigKeyPair(sigPub, r.bytes(SK_CAP), r.bytes(SK_CAP))
            v.identity = Identity(sig, readKemPair(r))
        }
        val n = r.byte()
        repeat(n) {
            val name = String(r.bytes(), Charsets.UTF_8)
            val sigPub = Hybrid.SigPublic(r.bytes(), r.bytes())
            val c = Contact(name, sigPub)
            repeat(r.byte()) { c.theirKeys.addLast(Hybrid.KemPublic(r.bytes(), r.bytes())) }
            repeat(r.byte()) { c.ourKeys.addLast(readKemPair(r)) }
            c.sendCounter = Protocol.bytesLong(r.raw(8))
            repeat(r.byte()) { c.seenCounters.addLast(Protocol.bytesLong(r.raw(8))) }
            c.verified = r.byte() == 1
            v.contacts.add(c)
        }
        r.requireEnd()
        return v
    }

    private fun writeKemPair(w: Wire.Writer, k: Hybrid.KemKeyPair) {
        w.bytes(k.pub.mlkem); w.bytes(k.pub.x25519); w.bytes(k.mlkemSecret); w.bytes(k.x25519Secret)
    }
    private fun readKemPair(r: Wire.Reader): Hybrid.KemKeyPair {
        val pub = Hybrid.KemPublic(r.bytes(), r.bytes())
        return Hybrid.KemKeyPair(pub, r.bytes(SK_CAP), r.bytes(SK_CAP))
    }
}
