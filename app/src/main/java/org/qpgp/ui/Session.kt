package org.qpgp.ui

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import org.qpgp.Engine
import org.qpgp.store.DuressStore
import org.qpgp.store.Vault
import org.qpgp.store.VaultData

/**
 * In-memory session. The decrypted vault lives ONLY here, only while unlocked.
 * Auto-locks after IDLE_MS of inactivity or when the app leaves the foreground.
 */
object Session {
    private const val IDLE_MS = 3 * 60 * 1000L

    var data: VaultData? = null
        private set
    /** Which on-disk vault the current session is bound to (REAL or DUMMY). */
    private var slot: Vault.Slot = Vault.Slot.REAL
    private var passphrase: CharArray? = null
    private val handler = Handler(Looper.getMainLooper())
    private val lockRunnable = Runnable { lock() }

    /**
     * Unlock entry point. Handles the DURESS path transparently.
     *
     * Order (indistinguishability):
     *   1. If the entered secret matches the duress verifier → DURESS TRIP:
     *      irreversibly crypto-shred the real vault, then open/create a dummy
     *      vault keyed by this same secret, and return true — landing on the
     *      exact same Contacts screen as a normal unlock, no tell.
     *   2. Otherwise try the real vault normally.
     *
     * Note: the duress check runs an Argon2id, and the real-vault load also
     * runs an Argon2id, so the timing surface of "typed the duress pin" vs
     * "typed the real passphrase" is comparable.
     */
    fun unlock(ctx: Context, pass: CharArray): Boolean {
        val app = ctx.applicationContext

        // 1. duress?
        if (DuressStore(app).matches(pass)) {
            return duressTrip(app, pass)
        }

        // 2. normal real-vault unlock
        val vault = Vault(app, Vault.Slot.REAL)
        return try {
            data = if (vault.exists()) vault.load(pass) else VaultData()
            slot = Vault.Slot.REAL
            passphrase = pass.copyOf()
            touch()
            true
        } catch (t: Throwable) {
            // 2b. if the real vault is gone (post-duress) but a dummy exists,
            //     a wrong real passphrase just fails like any wrong passphrase.
            false
        }
    }

    /**
     * DURESS TRIP — destroy the real vault beyond recovery, then hand the
     * coercer a working dummy vault. Best-effort: even if dummy creation has
     * a hiccup, the real vault is ALREADY shredded before we return.
     */
    private fun duressTrip(app: Context, pin: CharArray): Boolean {
        // (a) irreversibly destroy the real vault + biometric, keep dummy slot
        runCatching { Vault(app, Vault.Slot.REAL).destroySlotForDuress() }
        // remove the duress config itself so re-entry just opens the dummy as
        // a normal passphrase, and there's no lingering "duress configured" tell
        runCatching { DuressStore(app).disable() }

        // (b) open or create the dummy vault, keyed by the duress pin
        val dummy = Vault(app, Vault.Slot.DUMMY)
        return try {
            data = if (dummy.exists()) dummy.load(pin) else {
                val fresh = VaultData().apply { identity = Engine.createIdentity() }
                dummy.save(fresh, pin)
                fresh
            }
            slot = Vault.Slot.DUMMY
            passphrase = pin.copyOf()
            touch()
            true
        } catch (t: Throwable) {
            // If an old dummy file exists but the pin changed, rebuild it fresh.
            val fresh = VaultData().apply { identity = Engine.createIdentity() }
            runCatching { dummy.save(fresh, pin) }
            data = fresh
            slot = Vault.Slot.DUMMY
            passphrase = pin.copyOf()
            touch()
            true
        }
    }

    /** Persist current state to whichever slot is active (real or dummy). */
    fun persist(ctx: Context) {
        val d = data ?: return
        val p = passphrase ?: return
        Vault(ctx.applicationContext, slot).save(d, p)
        touch()
    }

    /** True when the current session is the dummy (duress) vault. Internal use only. */
    val isDummy: Boolean get() = slot == Vault.Slot.DUMMY

    fun touch() {
        handler.removeCallbacks(lockRunnable)
        handler.postDelayed(lockRunnable, IDLE_MS)
    }

    fun lock() {
        // best-effort scrub of secret material before dropping references
        data?.identity?.let {
            it.sig.mldsaSecret.fill(0); it.sig.ed25519Secret.fill(0)
            it.introKem.mlkemSecret.fill(0); it.introKem.x25519Secret.fill(0)
        }
        data?.contacts?.forEach { c ->
            c.ourKeys.forEach { k -> k.mlkemSecret.fill(0); k.x25519Secret.fill(0) }
        }
        passphrase?.fill('\u0000')
        passphrase = null
        data = null
        slot = Vault.Slot.REAL
        handler.removeCallbacks(lockRunnable)
        onLocked?.invoke()
    }

    val unlocked: Boolean get() = data != null
    var onLocked: (() -> Unit)? = null
}

/** Apply to every activity: no screenshots, no recents thumbnail, no casting. */
fun Activity.secureWindow() {
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
}
