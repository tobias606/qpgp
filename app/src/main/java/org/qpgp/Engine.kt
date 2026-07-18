package org.qpgp

import org.qpgp.crypto.Hybrid
import org.qpgp.protocol.Armor
import org.qpgp.protocol.Protocol
import org.qpgp.protocol.Wire
import org.qpgp.store.Contact
import org.qpgp.store.Identity
import org.qpgp.store.VaultData

/**
 * Session engine: pure logic tying identity, contacts and the protocol
 * together. No Android dependencies — fully unit-testable on the JVM.
 */
object Engine {

    // ---------- identity bundle (what you share when someone adds you) ----------
    // ver(1) | mldsaPub | ed25519Pub | introMlkemPub | introX25519Pub | name

    fun exportIdentity(v: VaultData, name: String): String {
        val id = v.identity ?: error("no identity")
        val w = Wire.Writer().byte(1)
            .bytes(id.sig.pub.mldsa).bytes(id.sig.pub.ed25519)
            .bytes(id.introKem.pub.mlkem).bytes(id.introKem.pub.x25519)
            .bytes(name.toByteArray(Charsets.UTF_8))
        return Armor.encode(Armor.TYPE_IDENTITY, w.done())
    }

    /** Parse a peer's identity bundle into a new (UNVERIFIED) contact. */
    fun importContact(text: String): Contact {
        val r = Wire.Reader(Armor.decode(Armor.TYPE_IDENTITY, text))
        if (r.byte() != 1) throw Wire.MalformedException("identity version")
        val sigPub = Hybrid.SigPublic(r.bytes(), r.bytes())
        val introKem = Hybrid.KemPublic(r.bytes(), r.bytes())
        val nameRaw = String(r.bytes(1024), Charsets.UTF_8)
        r.requireEnd()
        // sanitize the display name — it is attacker-supplied data
        val name = nameRaw.filter { !it.isISOControl() }.take(48).ifBlank { "unnamed" }
        val c = Contact(name, sigPub)
        c.pushTheirKey(introKem)
        return c
    }

    fun createIdentity(): Identity = Identity(Hybrid.generateSig(), Hybrid.generateKem())

    // ---------- verification words ----------

    /**
     * Human-comparable fingerprint: 6 words from a fixed 256-word list,
     * derived from BOTH parties' identity fingerprints, order-independent.
     * Compare in person / over a trusted voice channel.
     */
    fun verificationWords(mine: Hybrid.SigPublic, theirs: Hybrid.SigPublic): String {
        val a = Hybrid.fingerprint(mine)
        val b = Hybrid.fingerprint(theirs)
        val combined = if (compareBytes(a, b) <= 0) a + b else b + a
        val h = Hybrid.hkdf(combined, ByteArray(0), "QPGP-v1/sas".toByteArray(), 6)
        return h.joinToString(" ") { WORDS[it.toInt() and 0xff] }
    }

    /** Short local fingerprint of one identity (for the identity screen). */
    fun shortFingerprint(pub: Hybrid.SigPublic): String =
        Hybrid.fingerprint(pub).copyOf(8).joinToString(":") { "%02X".format(it) }

    // ---------- send / receive with rotation ----------

    fun encryptTo(v: VaultData, c: Contact, message: String): String {
        val id = v.identity ?: error("no identity")
        val theirKey = c.theirKeys.firstOrNull() ?: error("contact has no key")
        c.sendCounter += 1
        val out = Protocol.seal(id.sig, theirKey, c.sendCounter, message.toByteArray(Charsets.UTF_8))
        // rotate our own receiving key: the peer will encrypt replies to out.newOwnKeyPair
        c.pushOurKey(out.newOwnKeyPair)
        return Armor.encode(Armor.TYPE_MESSAGE, out.wire)
    }

    class Decrypted(val text: String, val contact: Contact, val usedOldKey: Boolean, val replayed: Boolean)

    /**
     * Decrypt an armored message. Tries every contact's key window; the
     * header key-id makes this an O(contacts × window) exact lookup, not trial
     * decryption.
     */
    fun decryptFrom(v: VaultData, text: String): Decrypted {
        val wire = Armor.decode(Armor.TYPE_MESSAGE, text)
        val keyId = Protocol.peekRecipientKeyId(wire)

        // Also consider the intro KEM key (first-contact messages).
        val id = v.identity ?: error("no identity")

        for (c in v.contacts) {
            val hit = c.findOurKeyById(keyId)
                ?: if (Hybrid.constantTimeEquals(Hybrid.keyId(id.introKem.pub), keyId))
                    Pair(id.introKem, false) else null
            if (hit != null) {
                val (kp, old) = hit
                val inc = try {
                    Protocol.open(wire, kp, c.sigPub, old)
                } catch (se: SecurityException) {
                    // key-id matched but signature pinned to another contact — keep trying
                    continue
                }
                val replayed = !c.checkAndRecordCounter(inc.counter)
                if (!replayed) {
                    // rotation: adopt their newly advertised key for our next send
                    c.pushTheirKey(inc.theirNextKey)
                }
                return Decrypted(String(inc.message, Charsets.UTF_8), c, inc.usedOldKey, replayed)
            }
        }
        throw SecurityException(
            "No key found for this message. Either it isn't addressed to you, " +
            "it targets a rotated-out key (>${Protocol.KEY_WINDOW} messages old), or the sender is unknown."
        )
    }

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    /** 256 distinct, phonetically-separated words for verification. */
    val WORDS: Array<String> = arrayOf(
        "acid","actor","adobe","aegis","agile","alarm","album","alien","alpha","amber","angle","anvil","apple","arrow","atlas","audio",
        "axiom","bacon","badge","bagel","baker","bamboo","banjo","barn","basil","beacon","beaver","bell","bench","bison","blade","blaze",
        "bloom","bolt","bonus","book","boots","brass","brave","bread","brick","bridge","brook","brush","budget","bugle","bunker","butter",
        "cabin","cable","cactus","camel","candle","canoe","canyon","cargo","carbon","castle","cedar","cello","chalk","chess","chief","chrome",
        "cider","cigar","circus","citrus","civic","clock","cloud","clover","cobalt","cocoa","coffee","comet","coral","cotton","cougar","cradle",
        "crane","crater","crayon","cream","crown","crystal","cube","cyclone","daisy","dance","delta","denim","depot","desert","diesel","dime",
        "dingo","dolphin","domino","donor","dragon","drum","dune","eagle","early","earth","easel","echo","eclipse","edge","elbow","elder",
        "ember","emerald","empire","engine","envoy","epoch","erode","essay","ethic","evoke","exact","exile","fable","falcon","fancy","fauna",
        "feast","fedora","fence","ferry","fiber","fiddle","field","finch","fjord","flame","flint","flora","flute","forge","fossil","fresco",
        "frost","fudge","fungus","gadget","galaxy","garden","gecko","genie","ginger","glacier","globe","gloss","goggle","gopher","gorge","granite",
        "grape","gravel","griffin","grove","guitar","gumbo","hazel","heron","hippo","holly","honey","horizon","hotel","husky","icicle","igloo",
        "indigo","ingot","iris","ivory","jackal","jade","jaguar","jasmine","jelly","jigsaw","jockey","jungle","juniper","kayak","kettle","kiosk",
        "kiwi","koala","lagoon","lantern","lapel","lava","legend","lemon","lever","lilac","lime","lion","lizard","llama","lobster","locket",
        "lotus","lunar","macaw","magma","magnet","mango","maple","marble","meadow","melon","mesa","meteor","mint","mirror","mocha","mosaic",
        "motel","mural","musket","narwhal","nectar","nickel","ninja","noble","nomad","north","nougat","novel","nugget","oasis","ocean","olive",
        "onion","opera","orbit","orchid","otter","owl","oxygen","oyster","panda","panther","papaya","parade","pastel","peach","pecan","pelican"
    )
}
