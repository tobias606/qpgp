package org.qpgp.ui

import android.content.Intent
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import org.qpgp.Engine
import org.qpgp.store.Contact

class AddContactActivity : SecureActivity() {
    private lateinit var col: LinearLayout

    private val scanLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
            val block = res.data?.getStringExtra(QrScanActivity.EXTRA_BLOCK)
            if (res.resultCode == RESULT_OK && block != null) importBlock(block)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ Add contact"))
        col.addView(Ui.subtitle(this, "scan their QR or paste their identity block"))

        col.addView(Ui.button(this, "▦  Scan identity QR") {
            scanLauncher.launch(Intent(this, QrScanActivity::class.java))
        })
        col.addView(Ui.spacer(this, 28))
        col.addView(Ui.divider(this))
        col.addView(Ui.label(this, "…or paste the block manually:"))

        val input = Ui.field(this, "-----BEGIN QPGP IDENTITY----- …", multi = true)
        col.addView(input)
        col.addView(Ui.spacer(this, 20))
        col.addView(Ui.buttonAlt(this, "Import pasted block") { importBlock(input.text.toString()) })

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }

    private fun importBlock(text: String) {
        val d = Session.data ?: return
        try {
            val c = Engine.importContact(text)
            val mine = d.identity!!.sig.pub
            if (d.contacts.any { org.qpgp.crypto.Hybrid.constantTimeEquals(it.fingerprint(), c.fingerprint()) }) {
                Toast.makeText(this, "Contact already exists", Toast.LENGTH_SHORT).show(); return
            }
            if (org.qpgp.crypto.Hybrid.constantTimeEquals(
                    org.qpgp.crypto.Hybrid.fingerprint(mine), c.fingerprint())) {
                Toast.makeText(this, "That is your own identity", Toast.LENGTH_SHORT).show(); return
            }
            d.contacts.add(c)
            Session.persist(this)
            showVerification(c)
        } catch (t: Throwable) {
            Toast.makeText(this, "Rejected: ${t.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun showVerification(c: Contact) {
        val d = Session.data ?: return
        val words = Engine.verificationWords(d.identity!!.sig.pub, c.sigPub)
        col.removeAllViews()
        col.addView(Ui.title(this, "⚠ Verify ${c.name}"))
        col.addView(Ui.subtitle(this, "man-in-the-middle check"))
        col.addView(Ui.label(this,
            "Both of you must see the SAME six words. Compare in person or " +
            "over a call where you recognize the voice. If they differ, someone " +
            "is intercepting — delete this contact."))
        col.addView(Ui.spacer(this, 20))
        col.addView(Ui.monoCard(this, words, Ui.WARN).apply { textSize = 17f })
        col.addView(Ui.spacer(this, 40))
        col.addView(Ui.button(this, "Words MATCH — mark verified", Ui.ACCENT_DIM) {
            c.verified = true
            Session.persist(this)
            finish()
        })
        col.addView(Ui.spacer(this, 16))
        col.addView(Ui.buttonAlt(this, "Can't verify yet (stays unverified)") { finish() })
        col.addView(Ui.spacer(this, 16))
        col.addView(Ui.button(this, "Words DIFFER — delete contact", Ui.DANGER) {
            Session.data?.contacts?.remove(c)
            Session.persist(this)
            finish()
        })
    }
}
