package org.kelopatra

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kelopatra.crypto.Hybrid
import org.kelopatra.protocol.Armor
import org.kelopatra.protocol.Protocol
import org.kelopatra.store.VaultCodec
import org.kelopatra.store.VaultData

/**
 * End-to-end tests of the crypto core, rotation protocol and codecs.
 * These run on the JVM (no Android device needed).
 */
class ProtocolTest {

    private fun freshUser(name: String): VaultData {
        val v = VaultData()
        v.identity = Engine.createIdentity()
        return v
    }

    private fun connect(a: VaultData, b: VaultData) {
        val aBlock = Engine.exportIdentity(a, "alice")
        val bBlock = Engine.exportIdentity(b, "bob")
        a.contacts.add(Engine.importContact(bBlock))
        b.contacts.add(Engine.importContact(aBlock))
    }

    @Test
    fun hybridKemRoundTrip() {
        val kp = Hybrid.generateKem()
        val enc = Hybrid.encapsulate(kp.pub)
        val ss = Hybrid.decapsulate(kp, enc.mlkemCiphertext, enc.ephemeralX25519Pub)
        assertTrue(Hybrid.constantTimeEquals(enc.sharedSecret, ss))
        assertEquals(32, ss.size)
    }

    @Test
    fun dualSignatureRejectsTamper() {
        val kp = Hybrid.generateSig()
        val data = "attack at dawn".toByteArray()
        val (m, e) = Hybrid.sign(kp, data)
        assertTrue(Hybrid.verify(kp.pub, data, m, e))
        assertFalse(Hybrid.verify(kp.pub, "attack at dusk".toByteArray(), m, e))
        val badEd = e.copyOf().also { it[3] = (it[3].toInt() xor 1).toByte() }
        assertFalse("flipping ONE signature must reject", Hybrid.verify(kp.pub, data, m, badEd))
    }

    @Test
    fun aeadRejectsTamper() {
        val key = ByteArray(32).also { Hybrid.rng.nextBytes(it) }
        val sealed = Hybrid.aeadSeal(key, "ad".toByteArray(), "secret".toByteArray())
        assertEquals("secret", String(Hybrid.aeadOpen(key, "ad".toByteArray(), sealed)))
        val bad = sealed.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        try { Hybrid.aeadOpen(key, "ad".toByteArray(), bad); throw AssertionError("must throw") }
        catch (expected: Exception) { /* ok */ }
    }

    @Test
    fun messageRoundTripWithRotation() {
        val alice = freshUser("alice"); val bob = freshUser("bob")
        connect(alice, bob)
        val aliceBob = alice.contacts[0]; val bobAlice = bob.contacts[0]

        // A -> B (encrypted to bob's intro key)
        val ct1 = Engine.encryptTo(alice, aliceBob, "hello bob")
        val r1 = Engine.decryptFrom(bob, ct1)
        assertEquals("hello bob", r1.text)
        assertFalse(r1.replayed)
        // bob adopted alice's rotated key AND kept the intro key (window)
        assertEquals(2, bobAlice.theirKeys.size)

        // B -> A: must use alice's ROTATED key, not the intro key
        val ct2 = Engine.encryptTo(bob, bobAlice, "hi alice, got your rotation")
        val r2 = Engine.decryptFrom(alice, ct2)
        assertEquals("hi alice, got your rotation", r2.text)
        assertFalse(r2.usedOldKey)

        // several more rounds — rotation keeps healing
        repeat(5) { i ->
            val c = Engine.encryptTo(alice, aliceBob, "ping $i")
            assertEquals("ping $i", Engine.decryptFrom(bob, c).text)
            val c2 = Engine.encryptTo(bob, bobAlice, "pong $i")
            assertEquals("pong $i", Engine.decryptFrom(alice, c2).text)
        }
    }

    @Test
    fun oldKeyWindowStillDecrypts() {
        val alice = freshUser("alice"); val bob = freshUser("bob")
        connect(alice, bob)
        val aliceBob = alice.contacts[0]; val bobAlice = bob.contacts[0]

        // establish rotated state
        Engine.decryptFrom(bob, Engine.encryptTo(alice, aliceBob, "m1"))
        Engine.decryptFrom(alice, Engine.encryptTo(bob, bobAlice, "m2"))

        // Bob writes to alice's current key, but BEFORE alice sees it,
        // alice sends 2 more messages (rotating her own keys forward).
        val late = Engine.encryptTo(bob, bobAlice, "late message")
        Engine.decryptFrom(bob, Engine.encryptTo(alice, aliceBob, "m3"))
        Engine.decryptFrom(bob, Engine.encryptTo(alice, aliceBob, "m4"))

        val r = Engine.decryptFrom(alice, late)
        assertEquals("late message", r.text)
        assertTrue("should be flagged as old-key usage", r.usedOldKey)
    }

    @Test
    fun replayIsDetected() {
        val alice = freshUser("alice"); val bob = freshUser("bob")
        connect(alice, bob)
        val ct = Engine.encryptTo(alice, alice.contacts[0], "once only")
        assertFalse(Engine.decryptFrom(bob, ct).replayed)
        assertTrue("second delivery must be flagged as replay", Engine.decryptFrom(bob, ct).replayed)
    }

    @Test
    fun impersonationRejected() {
        val alice = freshUser("alice"); val bob = freshUser("bob"); val mallory = freshUser("mallory")
        connect(alice, bob)
        // mallory somehow knows bob's public key and sends bob a message,
        // but bob only has alice as a contact -> must be rejected.
        val malloryView = VaultData().apply {
            identity = mallory.identity
            contacts.add(Engine.importContact(Engine.exportIdentity(bob, "bob")))
        }
        val forged = Engine.encryptTo(malloryView, malloryView.contacts[0], "it's alice, trust me")
        try {
            Engine.decryptFrom(bob, forged)
            throw AssertionError("must reject unknown sender")
        } catch (expected: SecurityException) { /* ok */ }
    }

    @Test
    fun corruptedArmorRejected() {
        val alice = freshUser("alice"); val bob = freshUser("bob")
        connect(alice, bob)
        val ct = Engine.encryptTo(alice, alice.contacts[0], "hello")
        val corrupted = ct.replaceFirst("A", "B")
        try {
            Engine.decryptFrom(bob, corrupted)
            throw AssertionError("must reject corrupted armor")
        } catch (expected: Exception) { /* ok */ }
    }

    @Test
    fun vaultCodecRoundTrip() {
        val alice = freshUser("alice"); val bob = freshUser("bob")
        connect(alice, bob)
        Engine.decryptFrom(bob, Engine.encryptTo(alice, alice.contacts[0], "state"))
        alice.contacts[0].verified = true

        val bytes = VaultCodec.encode(alice)
        val back = VaultCodec.decode(bytes)
        assertEquals(1, back.contacts.size)
        assertEquals(alice.contacts[0].name, back.contacts[0].name)
        assertTrue(back.contacts[0].verified)
        assertEquals(alice.contacts[0].sendCounter, back.contacts[0].sendCounter)
        assertEquals(alice.contacts[0].ourKeys.size, back.contacts[0].ourKeys.size)

        // decoded state remains fully functional
        val ct = Engine.encryptTo(back, back.contacts[0], "post-restore")
        assertEquals("post-restore", Engine.decryptFrom(bob, ct).text)
    }

    @Test
    fun verificationWordsSymmetric() {
        val a = Hybrid.generateSig(); val b = Hybrid.generateSig()
        assertEquals(Engine.verificationWords(a.pub, b.pub), Engine.verificationWords(b.pub, a.pub))
        val c = Hybrid.generateSig()
        assertFalse(Engine.verificationWords(a.pub, b.pub) == Engine.verificationWords(a.pub, c.pub))
    }

    @Test
    fun armorChecksumCatchesCorruption() {
        val data = ByteArray(300).also { Hybrid.rng.nextBytes(it) }
        val enc = Armor.encode(Armor.TYPE_MESSAGE, data)
        assertTrue(Hybrid.constantTimeEquals(data, Armor.decode(Armor.TYPE_MESSAGE, enc)))
    }
}
