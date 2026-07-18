package org.qpgp.ui

import android.content.Intent
import android.os.Bundle
import android.widget.ScrollView
import org.qpgp.Engine

class ContactsActivity : SecureActivity() {
    override fun onResume() {
        super.onResume()
        if (Session.unlocked) render()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Session.unlocked) render()
    }

    private fun render() {
        val d = Session.data ?: return
        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ qPGP"))
        col.addView(Ui.subtitle(this, "contacts"))

        col.addView(Ui.buttonAlt(this, "⚿  My identity — share key") {
            startActivity(Intent(this, IdentityActivity::class.java))
        })
        col.addView(Ui.spacer(this, 16))
        col.addView(Ui.button(this, "＋  Add contact") {
            startActivity(Intent(this, AddContactActivity::class.java))
        })
        col.addView(Ui.spacer(this, 16))
        col.addView(Ui.buttonAlt(this, "🔒  Lock now", Ui.DANGER) { Session.lock(); recreate() })

        col.addView(Ui.spacer(this, 40))
        col.addView(Ui.divider(this))
        col.addView(Ui.spacer(this, 16))

        if (d.contacts.isEmpty()) {
            col.addView(Ui.label(this,
                "No contacts yet.\nExchange identity blocks in person for real security."))
        }
        d.contacts.forEachIndexed { i, c ->
            val badge = if (c.verified) "✔ verified" else "⚠ unverified — compare words"
            val color = if (c.verified) Ui.ACCENT else Ui.WARN
            col.addView(Ui.spacer(this, 14))
            col.addView(Ui.buttonAlt(this, "${c.name}\n$badge", color) {
                startActivity(Intent(this, ChatActivity::class.java).putExtra("idx", i))
            })
        }
        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
