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
        col.addView(Ui.title(this, "⬢ Contacts"))

        col.addView(Ui.button(this, "My identity / share key", Ui.FIELD_BG) {
            startActivity(Intent(this, IdentityActivity::class.java))
        })
        col.addView(Ui.spacer(this, 12))
        col.addView(Ui.button(this, "+ Add contact (paste their identity)", Ui.ACCENT) {
            startActivity(Intent(this, AddContactActivity::class.java))
        })
        col.addView(Ui.spacer(this, 12))
        col.addView(Ui.button(this, "🔒 Lock now", Ui.DANGER) { Session.lock(); recreate() })
        col.addView(Ui.spacer(this, 32))

        if (d.contacts.isEmpty()) {
            col.addView(Ui.label(this, "No contacts yet. Exchange identity blocks in person for real security."))
        }
        d.contacts.forEachIndexed { i, c ->
            val badge = if (c.verified) "✔ verified" else "⚠ UNVERIFIED — compare words in person"
            val color = if (c.verified) Ui.ACCENT else Ui.WARN
            col.addView(Ui.spacer(this, 8))
            col.addView(Ui.button(this, "${c.name}\n$badge", Ui.FIELD_BG) {
                startActivity(Intent(this, ChatActivity::class.java).putExtra("idx", i))
            }.apply { setTextColor(color) })
        }
        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
