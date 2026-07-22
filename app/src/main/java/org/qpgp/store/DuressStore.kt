package org.qpgp.store

import android.content.Context
import org.qpgp.crypto.Hybrid
import org.qpgp.protocol.Wire
import java.io.File

/**
 * DURESS PIN — coercion protection.
 *
 * THREAT: the user is physically forced to open the app. Entering the duress
 * PIN must (a) irreversibly destroy the real vault (identity, contacts, all
 * private keys) via the same crypto-shred as "Destroy vault", and (b) open a
 * plausible, fully-functional DUMMY vault so the coercer sees a working app
 * with nothing incriminating — never a hint that a real vault existed.
 *
 * INDISTINGUISHABILITY (the whole point):
 *  - The duress PIN is checked at unlock BEFORE the real passphrase, using an
 *    Argon2id verifier stored here. A match triggers the duress path.
 *  - The duress path lands on the exact same Contacts screen as a normal
 *    unlock — same timing surface (destroy runs, but the user is mid-"unlock"
 *    so a short delay is expected either way), no toast, no visual tell.
 *  - The dummy vault is a genuine Vault instance under a SEPARATE hardware
 *    keystore key (qpgp.dummy.v1), so destroying the real key leaves it intact.
 *  - Setup requires the real passphrase, and the duress PIN must differ from it.
 *
 * FILE (duress.qpgp): ver(1) | argonSalt(16) | verifier(32)
 *   verifier = Argon2id(pin, salt). We store only the verifier, never the PIN.
 *
 * RESIDUAL RISKS (documented, not hidden):
 *  - A coercer who watches the user set BOTH pins, or who has forensic access
 *    to a flash image taken BEFORE the duress trip, can still recover the real
 *    vault ciphertext (but not its key, which lived only in the TEE). Duress
 *    protects against on-the-spot coercion, not prior full-image capture.
 *  - Presence of the duress.qpgp file itself is a (small) tell that the
 *    feature MIGHT be configured. It is not a tell of what any PIN does.
 */
class DuressStore(private val ctx: Context) {

    private val file: File get() = File(ctx.filesDir, "duress.qpgp")

    fun isConfigured(): Boolean = file.exists()

    /** Enable/replace the duress PIN. Caller must have verified the real passphrase. */
    fun set(pin: CharArray) {
        val salt = ByteArray(16).also { Hybrid.rng.nextBytes(it) }
        val verifier = Hybrid.argon2id(pin, salt)
        val out = Wire.Writer().byte(1).raw(salt).raw(verifier)
        file.writeBytes(out.done())
        verifier.fill(0)
    }

    fun disable() {
        runCatching {
            if (file.exists()) { file.writeBytes(ByteArray(file.length().toInt())); file.delete() }
        }
    }

    /**
     * Constant-time check whether [candidate] is the duress PIN.
     * Returns false (never throws) if not configured or on any error.
     */
    fun matches(candidate: CharArray): Boolean {
        if (!file.exists()) return false
        return try {
            val r = Wire.Reader(file.readBytes())
            if (r.byte() != 1) return false
            val salt = r.raw(16)
            val stored = r.raw(32)
            val got = Hybrid.argon2id(candidate, salt)
            val ok = Hybrid.constantTimeEquals(got, stored)
            got.fill(0)
            ok
        } catch (t: Throwable) {
            false
        }
    }
}
