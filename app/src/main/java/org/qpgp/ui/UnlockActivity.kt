package org.qpgp.ui

import android.content.Intent
import android.os.Bundle
import android.widget.ScrollView
import android.widget.Toast
import org.qpgp.Engine
import org.qpgp.store.Vault

class UnlockActivity : SecureActivity() {
    override fun needsUnlock() = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val vault = Vault(this)
        val fresh = !vault.exists()

        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ qPGP"))
        col.addView(Ui.subtitle(this, "offline · zero permissions · post-quantum"))

        if (fresh) {
            col.addView(Ui.label(this,
                "No vault on this device yet.\nChoose a strong passphrase — it cannot be recovered, there is no reset."))
            val p1 = Ui.password(this, "passphrase")
            val p2 = Ui.password(this, "repeat passphrase")
            col.addView(p1); col.addView(Ui.spacer(this, 20)); col.addView(p2)
            col.addView(Ui.spacer(this, 36))
            col.addView(Ui.button(this, "Create vault") {
                val a = p1.text.toString(); val b = p2.text.toString()
                when {
                    a != b -> toast("Passphrases differ")
                    a.length < 10 -> toast("Minimum 10 characters. Longer is better.")
                    else -> {
                        val pass = a.toCharArray()
                        if (Session.unlock(this, pass)) {
                            Session.data!!.identity = Engine.createIdentity()
                            Session.persist(this)
                            pass.fill('\u0000')
                            go()
                        } else toast("Vault creation failed")
                    }
                }
            })
        } else {
            col.addView(Ui.label(this, "Vault is locked."))
            val p = Ui.password(this, "passphrase")
            col.addView(p)
            col.addView(Ui.spacer(this, 36))
            col.addView(Ui.button(this, "Unlock") {
                val pass = p.text.toString().toCharArray()
                p.text.clear()
                if (Session.unlock(this, pass)) { pass.fill('\u0000'); go() }
                else toast("Wrong passphrase (or vault bound to a different device state)")
            })

            // biometric unlock, if the user opted in via Settings
            val bio = org.qpgp.store.BiometricStore(this)
            val canBio = androidx.biometric.BiometricManager.from(this)
                .canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
            if (bio.isEnabled() && canBio) {
                col.addView(Ui.spacer(this, 16))
                col.addView(Ui.buttonAlt(this, "☝  Unlock with biometrics", Ui.ACCENT) {
                    val cipher = try { bio.decryptCipher() } catch (t: Throwable) {
                        // key invalidated (new fingerprint enrolled) or blob corrupt
                        bio.disable()
                        toast("Biometric key invalidated — use passphrase and re-enable in Settings")
                        return@buttonAlt
                    }
                    val prompt = androidx.biometric.BiometricPrompt(this,
                        androidx.core.content.ContextCompat.getMainExecutor(this),
                        object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(
                                r: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                                val pass = try { bio.finishUnlock(r.cryptoObject!!.cipher!!) }
                                catch (t: Throwable) {
                                    bio.disable()
                                    toast("Unseal failed — use passphrase and re-enable in Settings")
                                    return
                                }
                                if (Session.unlock(this@UnlockActivity, pass)) { pass.fill('\u0000'); go() }
                                else { pass.fill('\u0000'); toast("Vault unlock failed") }
                            }
                        })
                    prompt.authenticate(
                        androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                            .setTitle("Unlock qPGP")
                            .setNegativeButtonText("Use passphrase")
                            .setAllowedAuthenticators(
                                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                            .build(),
                        androidx.biometric.BiometricPrompt.CryptoObject(cipher))
                })
            }
        }

        Session.onLocked = { }
        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }

    private fun go() {
        startActivity(Intent(this, ContactsActivity::class.java))
        finish()
    }
    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
