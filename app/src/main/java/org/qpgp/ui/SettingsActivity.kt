package org.qpgp.ui

import android.os.Bundle
import android.widget.ScrollView
import android.widget.Toast
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import org.qpgp.store.BiometricStore
import org.qpgp.store.Vault

/**
 * Settings: biometric unlock (opt-in) and vault destruction.
 */
class SettingsActivity : SecureActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        render()
    }

    private fun render() {
        val bio = BiometricStore(this)
        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ Settings"))
        col.addView(Ui.subtitle(this, "vault security"))

        // ---- biometric unlock ----
        col.addView(Ui.label(this, "Biometric unlock", Ui.ACCENT))
        val canBio = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

        when {
            !canBio -> col.addView(Ui.label(this,
                "No strong biometrics available on this device (no sensor, or none enrolled)."))
            bio.isEnabled() -> {
                col.addView(Ui.label(this, "Enabled. The vault can be opened with fingerprint/face."))
                col.addView(Ui.spacer(this, 12))
                col.addView(Ui.buttonAlt(this, "Disable biometric unlock", Ui.WARN) {
                    bio.disable()
                    Toast.makeText(this, "Biometric unlock disabled, key destroyed", Toast.LENGTH_SHORT).show()
                    recreate()
                })
            }
            else -> {
                col.addView(Ui.label(this,
                    "Tradeoff, stated plainly: your passphrase gets sealed under a " +
                    "hardware key that opens with any enrolled fingerprint/face. " +
                    "Anyone who has this device AND your biometric (including a " +
                    "coerced one — courts can compel a finger more easily than a " +
                    "passphrase) can open the vault. Enrolling a NEW fingerprint " +
                    "automatically invalidates it. Passphrase always keeps working."))
                col.addView(Ui.spacer(this, 16))
                val pass = Ui.password(this, "confirm passphrase to enable")
                col.addView(pass)
                col.addView(Ui.spacer(this, 16))
                col.addView(Ui.button(this, "Enable biometric unlock") {
                    val p = pass.text.toString().toCharArray()
                    pass.text.clear()
                    // verify the passphrase is actually correct before sealing it
                    if (!verifyPassphrase(p)) {
                        Toast.makeText(this, "Wrong passphrase", Toast.LENGTH_SHORT).show()
                        p.fill('\u0000'); return@button
                    }
                    val cipher = bio.encryptCipher()
                    val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                        object : BiometricPrompt.AuthenticationCallback() {
                            override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                                bio.finishEnable(p, r.cryptoObject!!.cipher!!)
                                p.fill('\u0000')
                                Toast.makeText(this@SettingsActivity, "Biometric unlock enabled", Toast.LENGTH_SHORT).show()
                                recreate()
                            }
                            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                                p.fill('\u0000')
                                Toast.makeText(this@SettingsActivity, "Cancelled: $msg", Toast.LENGTH_SHORT).show()
                            }
                        })
                    prompt.authenticate(
                        BiometricPrompt.PromptInfo.Builder()
                            .setTitle("Enable biometric unlock")
                            .setSubtitle("Seals your passphrase under a biometric-gated hardware key")
                            .setNegativeButtonText("Cancel")
                            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                            .build(),
                        BiometricPrompt.CryptoObject(cipher))
                })
            }
        }

        col.addView(Ui.spacer(this, 40))
        col.addView(Ui.divider(this))

        // ---- duress PIN ----
        col.addView(Ui.label(this, "Duress PIN", Ui.DANGER))
        val duress = org.qpgp.store.DuressStore(this)
        col.addView(Ui.label(this,
            "For coercion. If you are FORCED to open the app, enter the duress " +
            "PIN at the unlock screen instead of your passphrase. The real vault " +
            "(identity, contacts, all keys) is instantly and irreversibly " +
            "destroyed — same crypto-shred as Destroy vault — and a harmless " +
            "empty vault opens in its place, looking like a normal fresh app. " +
            "There is NO way to tell the difference, and NO recovery. Use a PIN " +
            "you can recall under stress but that isn't your passphrase."))
        if (duress.isConfigured()) {
            col.addView(Ui.spacer(this, 12))
            col.addView(Ui.mono(this, "status: configured", Ui.WARN))
            col.addView(Ui.spacer(this, 12))
            col.addView(Ui.buttonAlt(this, "Remove duress PIN", Ui.WARN) {
                duress.disable()
                Toast.makeText(this, "Duress PIN removed", Toast.LENGTH_SHORT).show()
                recreate()
            })
        }
        col.addView(Ui.spacer(this, 16))
        val dPin = Ui.password(this, if (duress.isConfigured()) "new duress PIN" else "duress PIN (min 4)")
        val dPin2 = Ui.password(this, "repeat duress PIN")
        val dPass = Ui.password(this, "confirm your REAL passphrase")
        col.addView(dPin); col.addView(Ui.spacer(this, 12))
        col.addView(dPin2); col.addView(Ui.spacer(this, 12))
        col.addView(dPass)
        col.addView(Ui.spacer(this, 16))
        col.addView(Ui.button(this, if (duress.isConfigured()) "Update duress PIN" else "Set duress PIN", Ui.DANGER) {
            val a = dPin.text.toString(); val b = dPin2.text.toString()
            val realP = dPass.text.toString().toCharArray()
            when {
                a.length < 4 -> Toast.makeText(this, "Duress PIN too short (min 4)", Toast.LENGTH_SHORT).show()
                a != b -> Toast.makeText(this, "Duress PINs differ", Toast.LENGTH_SHORT).show()
                !verifyPassphrase(realP) -> Toast.makeText(this, "Wrong real passphrase", Toast.LENGTH_SHORT).show()
                a == String(realP) -> Toast.makeText(this, "Duress PIN must differ from your passphrase", Toast.LENGTH_LONG).show()
                else -> {
                    val pin = a.toCharArray()
                    duress.set(pin)
                    pin.fill('\u0000')
                    dPin.text.clear(); dPin2.text.clear(); dPass.text.clear()
                    Toast.makeText(this, "Duress PIN set", Toast.LENGTH_SHORT).show()
                    recreate()
                }
            }
            realP.fill('\u0000')
        })

        col.addView(Ui.spacer(this, 40))
        col.addView(Ui.divider(this))

        // ---- destroy vault ----
        col.addView(Ui.label(this, "Destroy vault", Ui.DANGER))
        col.addView(Ui.label(this,
            "Irreversibly destroys everything: your identity, all contacts, all " +
            "session keys. Primary mechanism is crypto-shredding — the hardware " +
            "keystore keys are destroyed first, making every byte this app ever " +
            "wrote to flash permanently undecryptable even for a forensic lab " +
            "imaging the raw storage. Files are additionally overwritten (3 " +
            "passes) and deleted. There is NO recovery. Anyone you talk to must " +
            "re-add you from scratch."))
        val confirm = Ui.field(this, "type DESTROY to confirm")
        col.addView(confirm)
        col.addView(Ui.spacer(this, 16))
        col.addView(Ui.button(this, "🗑  DESTROY VAULT — no recovery", Ui.DANGER) {
            if (confirm.text.toString().trim() != "DESTROY") {
                Toast.makeText(this, "Type DESTROY (all caps) to confirm", Toast.LENGTH_SHORT).show()
                return@button
            }
            Session.lock()
            BiometricStore(this).disable()
            Vault(this).destroy()
            Toast.makeText(this, "Vault destroyed.", Toast.LENGTH_LONG).show()
            finishAffinity()   // exit the app entirely
        })

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }

    /** Check a passphrase by attempting a real vault load. */
    private fun verifyPassphrase(p: CharArray): Boolean =
        runCatching { Vault(this).load(p) }.isSuccess
}
