package org.qpgp.ui

import android.os.Bundle
import android.widget.ScrollView
import android.widget.Toast
import org.qpgp.Engine

class IdentityActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val d = Session.data ?: return
        val id = d.identity ?: return

        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ My identity"))
        col.addView(Ui.subtitle(this, "public keys only — safe to share"))

        col.addView(Ui.label(this, "Fingerprint — verify with your contact in person:"))
        col.addView(Ui.monoCard(this, Engine.shortFingerprint(id.sig.pub), Ui.ACCENT))
        col.addView(Ui.spacer(this, 28))

        col.addView(Ui.label(this,
            "Share the block below so a contact can add you. It contains only " +
            "public keys. qPGP never touches the clipboard itself — long-press " +
            "the block to select and copy it deliberately."))

        val name = Ui.field(this, "display name to embed (optional)")
        col.addView(name)
        col.addView(Ui.spacer(this, 24))

        val out = Ui.monoCard(this)
        col.addView(Ui.button(this, "Generate identity block") {
            val block = Engine.exportIdentity(d, name.text.toString().take(48))
            out.text = block
            out.setTextIsSelectable(true)
            Toast.makeText(this, "Long-press the block to select & copy.", Toast.LENGTH_LONG).show()
        })
        col.addView(Ui.spacer(this, 24))
        col.addView(out)

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
