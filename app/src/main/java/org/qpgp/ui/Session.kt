package org.qpgp.ui

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
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
    private var passphrase: CharArray? = null
    private val handler = Handler(Looper.getMainLooper())
    private val lockRunnable = Runnable { lock() }

    fun unlock(ctx: Context, pass: CharArray): Boolean {
        val vault = Vault(ctx.applicationContext)
        return try {
            data = if (vault.exists()) vault.load(pass) else VaultData()
            passphrase = pass.copyOf()
            touch()
            true
        } catch (t: Throwable) {
            false
        }
    }

    /** Persist current state (re-sealed under both layers). */
    fun persist(ctx: Context) {
        val d = data ?: return
        val p = passphrase ?: return
        Vault(ctx.applicationContext).save(d, p)
        touch()
    }

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
