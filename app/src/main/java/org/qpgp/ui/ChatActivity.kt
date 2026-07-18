package org.qpgp.ui

import android.os.Bundle
import android.widget.ScrollView
import android.widget.Toast
import org.qpgp.Engine

class ChatActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val d = Session.data ?: return
        val idx = intent.getIntExtra("idx", -1)
        val c = d.contacts.getOrNull(idx) ?: run { finish(); return }

        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ ${c.name}"))
        col.addView(Ui.subtitle(this, if (c.verified) "✔ verified contact" else "⚠ unverified contact"))

        if (!c.verified) {
            col.addView(Ui.monoCard(this,
                "⚠ UNVERIFIED — messages may be readable by an interceptor.\n\n" +
                "verification words:\n${Engine.verificationWords(d.identity!!.sig.pub, c.sigPub)}",
                Ui.WARN))
            col.addView(Ui.spacer(this, 24))
        }

        // ---- ENCRYPT ----
        col.addView(Ui.label(this, "ENCRYPT · write a message for ${c.name}", Ui.ACCENT))
        val plain = Ui.field(this, "plaintext…", multi = true)
        col.addView(plain)
        col.addView(Ui.spacer(this, 18))
        val cipherOut = Ui.monoCard(this)
        col.addView(Ui.button(this, "Encrypt  ➜  ciphertext") {
            try {
                val msg = plain.text.toString()
                if (msg.isEmpty()) return@button
                val armored = Engine.encryptTo(d, c, msg)
                Session.persist(this)                 // rotation state saved atomically
                plain.text.clear()                    // plaintext leaves the screen
                cipherOut.text = armored
                cipherOut.setTextIsSelectable(true)
                Toast.makeText(this,
                    "Encrypted — key rotated (msg #${c.sendCounter}). Long-press to select & send.",
                    Toast.LENGTH_LONG).show()
            } catch (t: Throwable) {
                Toast.makeText(this, "Failed: ${t.message}", Toast.LENGTH_LONG).show()
            }
        })
        col.addView(Ui.spacer(this, 14))
        col.addView(cipherOut)

        col.addView(Ui.spacer(this, 40))
        col.addView(Ui.divider(this))
        col.addView(Ui.spacer(this, 8))

        // ---- DECRYPT ----
        col.addView(Ui.label(this, "DECRYPT · paste a QPGP MESSAGE block", Ui.ACCENT))
        val cipherIn = Ui.field(this, "-----BEGIN QPGP MESSAGE----- …", multi = true)
        col.addView(cipherIn)
        col.addView(Ui.spacer(this, 18))
        val plainOut = Ui.monoCard(this)
        col.addView(Ui.button(this, "Decrypt & verify") {
            try {
                val res = Engine.decryptFrom(d, cipherIn.text.toString())
                Session.persist(this)                 // adopt their rotated key
                cipherIn.text.clear()
                val notes = buildString {
                    if (res.replayed) append("\n\n⚠ REPLAY: this exact message was already received before. Treat with suspicion.")
                    if (res.usedOldKey) append("\n\nℹ encrypted to an older key of yours (sender hasn't seen your latest yet) — still authentic.")
                    if (res.contact !== c) append("\n\nℹ note: message is from '${res.contact.name}', not this contact.")
                    if (!res.contact.verified) append("\n\n⚠ sender is UNVERIFIED.")
                }
                plainOut.text = "── from ${res.contact.name} ──\n\n${res.text}$notes"
                plainOut.setTextColor(if (res.replayed) Ui.WARN else Ui.FG)
            } catch (t: Throwable) {
                plainOut.text = "✖ REJECTED\n\n${t.message}"
                plainOut.setTextColor(Ui.DANGER)
            }
        })
        col.addView(Ui.spacer(this, 14))
        col.addView(plainOut)

        col.addView(Ui.spacer(this, 32))
        col.addView(Ui.mono(this,
            "keys kept · theirs ${c.theirKeys.size} · ours ${c.ourKeys.size} · window ${org.qpgp.protocol.Protocol.KEY_WINDOW}",
            Ui.MUTED))

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
