package org.qpgp.ui

import android.os.Bundle
import android.widget.ScrollView
import android.widget.Toast
import org.qpgp.Engine

class AddContactActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val d = Session.data ?: return

        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ Add contact"))
        col.addView(Ui.label(this, "Paste the QPGP IDENTITY block you received:"))
        val input = Ui.field(this, "-----BEGIN QPGP IDENTITY----- …", multi = true)
        col.addView(input)
        col.addView(Ui.spacer(this, 24))
        col.addView(Ui.button(this, "Import") {
            try {
                val c = Engine.importContact(input.text.toString())
                val mine = d.identity!!.sig.pub
                val dup = d.contacts.any {
                    org.qpgp.crypto.Hybrid.constantTimeEquals(it.fingerprint(), c.fingerprint())
                }
                if (dup) { Toast.makeText(this, "Contact already exists", Toast.LENGTH_SHORT).show(); return@button }
                if (org.qpgp.crypto.Hybrid.constantTimeEquals(
                        org.qpgp.crypto.Hybrid.fingerprint(mine), c.fingerprint())) {
                    Toast.makeText(this, "That is your own identity", Toast.LENGTH_SHORT).show(); return@button
                }
                d.contacts.add(c)
                Session.persist(this)

                // Show verification ceremony immediately.
                val words = Engine.verificationWords(mine, c.sigPub)
                col.removeAllViews()
                col.addView(Ui.title(this, "⚠ Verify ${c.name}"))
                col.addView(Ui.label(this,
                    "Both of you must see the SAME six words. Compare in person or " +
                    "over a call where you recognize the voice. If they differ, someone " +
                    "is intercepting — delete this contact."))
                col.addView(Ui.spacer(this, 16))
                col.addView(Ui.mono(this, words, Ui.WARN).apply { textSize = 18f })
                col.addView(Ui.spacer(this, 32))
                col.addView(Ui.button(this, "Words MATCH — mark verified", Ui.ACCENT) {
                    c.verified = true
                    Session.persist(this)
                    finish()
                })
                col.addView(Ui.spacer(this, 12))
                col.addView(Ui.button(this, "Can't verify yet (stays UNVERIFIED)", Ui.FIELD_BG) { finish() })
                col.addView(Ui.spacer(this, 12))
                col.addView(Ui.button(this, "Words DIFFER — delete contact", Ui.DANGER) {
                    d.contacts.remove(c)
                    Session.persist(this)
                    finish()
                })
            } catch (t: Throwable) {
                Toast.makeText(this, "Rejected: ${t.message}", Toast.LENGTH_LONG).show()
            }
        })
        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
