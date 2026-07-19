package org.qpgp.ui

import android.os.Bundle
import android.widget.ScrollView
import android.widget.Toast
import org.qpgp.Engine

/**
 * Contact management: alias, verification status, fingerprint, deletion.
 * Deletion is deliberately slow (typed confirmation) and destroys the
 * session key material held for this contact (crypto-shred of the pairing).
 */
class EditContactActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val d = Session.data ?: return
        val idx = intent.getIntExtra("idx", -1)
        val c = d.contacts.getOrNull(idx) ?: run { finish(); return }

        val col = Ui.column(this)
        col.addView(Ui.title(this, "✎ ${c.name}"))
        col.addView(Ui.subtitle(this, "edit contact"))

        // ---- alias ----
        col.addView(Ui.label(this, "Alias — local display name, never shared:"))
        val alias = Ui.field(this, "alias").apply { setText(c.name) }
        col.addView(alias)
        col.addView(Ui.spacer(this, 18))
        col.addView(Ui.button(this, "Save alias") {
            val n = alias.text.toString().filter { !it.isISOControl() }.trim().take(48)
            if (n.isEmpty()) { Toast.makeText(this, "Alias can't be empty", Toast.LENGTH_SHORT).show(); return@button }
            c.name = n
            Session.persist(this)
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            finish()
        })

        col.addView(Ui.spacer(this, 36))
        col.addView(Ui.divider(this))

        // ---- verification ----
        col.addView(Ui.label(this, "Verification", Ui.ACCENT))
        val words = Engine.verificationWords(d.identity!!.sig.pub, c.sigPub)
        col.addView(Ui.monoCard(this, "status: ${if (c.verified) "✔ verified" else "⚠ unverified"}\n\n$words",
            if (c.verified) Ui.ACCENT else Ui.WARN))
        col.addView(Ui.spacer(this, 16))
        if (c.verified) {
            col.addView(Ui.buttonAlt(this, "Mark UNVERIFIED (re-check needed)", Ui.WARN) {
                c.verified = false; Session.persist(this); recreate()
            })
        } else {
            col.addView(Ui.button(this, "Words match — mark verified", Ui.ACCENT_DIM) {
                c.verified = true; Session.persist(this); recreate()
            })
        }

        col.addView(Ui.spacer(this, 24))
        col.addView(Ui.label(this, "Their fingerprint:"))
        col.addView(Ui.monoCard(this, Engine.shortFingerprint(c.sigPub), Ui.MUTED))

        col.addView(Ui.spacer(this, 36))
        col.addView(Ui.divider(this))

        // ---- danger zone ----
        col.addView(Ui.label(this, "Danger zone", Ui.DANGER))
        col.addView(Ui.label(this,
            "Deleting destroys the keys shared with this contact. Old ciphertexts " +
            "exchanged with them become permanently undecryptable. To talk again, " +
            "you must re-exchange identities from scratch."))
        val confirm = Ui.field(this, "type DELETE to confirm")
        col.addView(confirm)
        col.addView(Ui.spacer(this, 18))
        col.addView(Ui.button(this, "🗑  Delete contact", Ui.DANGER) {
            if (confirm.text.toString().trim() != "DELETE") {
                Toast.makeText(this, "Type DELETE (all caps) to confirm", Toast.LENGTH_SHORT).show()
                return@button
            }
            // crypto-shred: zero every private key held for this pairing
            c.ourKeys.forEach { it.mlkemSecret.fill(0); it.x25519Secret.fill(0) }
            c.ourKeys.clear(); c.theirKeys.clear(); c.seenCounters.clear()
            d.contacts.remove(c)
            Session.persist(this)
            Toast.makeText(this, "Contact deleted, keys destroyed", Toast.LENGTH_SHORT).show()
            setResult(RESULT_DELETED)
            finish()
        })

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }

    companion object { const val RESULT_DELETED = 7 }
}
