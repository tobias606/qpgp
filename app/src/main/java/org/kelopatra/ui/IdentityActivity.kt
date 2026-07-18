package org.kelopatra.ui

import android.os.Bundle
import android.widget.ScrollView
import android.widget.Toast
import org.kelopatra.Engine

class IdentityActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val d = Session.data ?: return
        val id = d.identity ?: return

        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ My identity"))
        col.addView(Ui.label(this, "Fingerprint (verify with your contact in person):"))
        col.addView(Ui.mono(this, Engine.shortFingerprint(id.sig.pub), Ui.ACCENT))
        col.addView(Ui.spacer(this, 24))
        col.addView(Ui.label(this,
            "Share the block below with a contact so they can add you. " +
            "It contains ONLY public keys. Kelopatra never uses the clipboard — " +
            "the block is shown via the system share sheet, choose your channel deliberately."))

        val name = Ui.field(this, "display name to embed (optional)")
        col.addView(name)
        col.addView(Ui.spacer(this, 16))

        val out = Ui.mono(this, "", Ui.FG)
        col.addView(Ui.button(this, "Generate identity block") {
            val block = Engine.exportIdentity(d, name.text.toString().take(48))
            out.text = block
            out.setTextIsSelectable(true)
            Toast.makeText(this, "Long-press to select & share. Public keys only.", Toast.LENGTH_LONG).show()
        })
        col.addView(Ui.spacer(this, 16))
        col.addView(out)

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
