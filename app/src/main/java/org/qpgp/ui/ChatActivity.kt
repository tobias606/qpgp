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
        if (!c.verified) {
            col.addView(Ui.mono(this,
                "⚠ UNVERIFIED CONTACT — messages may be readable by an interceptor.\n" +
                "Verification words: ${Engine.verificationWords(d.identity!!.sig.pub, c.sigPub)}",
                Ui.WARN))
            col.addView(Ui.spacer(this, 16))
        }

        // ---- ENCRYPT ----
        col.addView(Ui.label(this, "ENCRYPT — write a message for ${c.name}:", Ui.ACCENT))
        val plain = Ui.field(this, "plaintext…", multi = true)
        col.addView(plain)
        col.addView(Ui.spacer(this, 12))
        val cipherOut = Ui.mono(this, "")
        col.addView(Ui.button(this, "Encrypt ➜ ciphertext") {
            try {
                val msg = plain.text.toString()
                if (msg.isEmpty()) return@button
                val armored = Engine.encryptTo(d, c, msg)
                Session.persist(this)                 // rotation state saved atomically
                plain.text.clear()                    // plaintext leaves the screen
                cipherOut.text = armored
                cipherOut.setTextIsSelectable(true)
                Toast.makeText(this,
                    "Encrypted. Key rotated (msg #${c.sendCounter}). Long-press to select & send.",
                    Toast.LENGTH_LONG).show()
            } catch (t: Throwable) {
                Toast.makeText(this, "Failed: ${t.message}", Toast.LENGTH_LONG).show()
            }
        })
        col.addView(Ui.spacer(this, 8))
        col.addView(cipherOut)
        col.addView(Ui.spacer(this, 40))

        // ---- DECRYPT ----
        col.addView(Ui.label(this, "DECRYPT — paste a QPGP MESSAGE block:", Ui.ACCENT))
        val cipherIn = Ui.field(this, "-----BEGIN QPGP MESSAGE----- …", multi = true)
        col.addView(cipherIn)
        col.addView(Ui.spacer(this, 12))
        val plainOut = Ui.mono(this, "")
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
                plainOut.text = "── from ${res.contact.name} ──\n${res.text}$notes"
                plainOut.setTextColor(if (res.replayed) Ui.WARN else Ui.FG)
            } catch (t: Throwable) {
                plainOut.text = "✖ REJECTED: ${t.message}"
                plainOut.setTextColor(Ui.DANGER)
            }
        })
        col.addView(Ui.spacer(this, 8))
        col.addView(plainOut)
        col.addView(Ui.spacer(this, 24))
        col.addView(Ui.mono(this,
            "keys: theirs=${c.theirKeys.size} kept · ours=${c.ourKeys.size} kept · window=${org.qpgp.protocol.Protocol.KEY_WINDOW}",
            Ui.MUTED))

        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }
}
