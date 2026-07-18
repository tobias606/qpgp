package org.qpgp.ui

import android.content.Intent
import android.os.Bundle
import android.widget.ScrollView
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

        val name = Ui.field(this, "display name to embed (optional)")
        col.addView(name)
        col.addView(Ui.spacer(this, 24))

        col.addView(Ui.button(this, "▦  Show as QR (in person)") {
            startActivity(Intent(this, QrShowActivity::class.java)
                .putExtra("name", name.text.toString().take(48)))
        })
        col.addView(Ui.spacer(this, 16))

        val out = Ui.monoCard(this)
        val copy = Ui.copyButton(this, "identity block") { out.text.toString() }
        copy.visibility = android.view.View.GONE

        col.addView(Ui.buttonAlt(this, "⌨  Show as text block") {
            out.text = Engine.exportIdentity(d, name.text.toString().take(48))
            out.setTextIsSelectable(true)
            copy.visibility = android.view.View.VISIBLE
        })
        col.addView(Ui.spacer(this, 24))
        col.addView(copy)
        col.addView(Ui.spacer(this, 12))
        col.addView(out)

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
