package org.qpgp.ui

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/** Shared dark, minimal styling helpers — terminal black & green, but tidy. */
object Ui {
    const val BG = 0xFF0A0E12.toInt()          // near-black
    const val CARD = 0xFF11161D.toInt()        // card surface
    const val FIELD_BG = 0xFF161D26.toInt()    // input surface
    const val BORDER = 0xFF223041.toInt()      // subtle outline
    const val FG = 0xFFE6EDF3.toInt()
    const val ACCENT = 0xFF3FB950.toInt()      // green
    const val ACCENT_DIM = 0xFF238636.toInt()  // button green
    const val WARN = 0xFFD29922.toInt()
    const val DANGER = 0xFFDA3633.toInt()
    const val MUTED = 0xFF7D8590.toInt()

    private fun rounded(fill: Int, stroke: Int = 0, radius: Float = 24f) = GradientDrawable().apply {
        cornerRadius = radius
        setColor(fill)
        if (stroke != 0) setStroke(2, stroke)
    }

    fun title(a: AppCompatActivity, s: String) = TextView(a).apply {
        text = s; textSize = 24f; setTextColor(FG); typeface = Typeface.MONOSPACE
        setPadding(4, 8, 4, 6)
        letterSpacing = 0.02f
    }
    fun subtitle(a: AppCompatActivity, s: String) = TextView(a).apply {
        text = s; textSize = 12f; setTextColor(ACCENT); typeface = Typeface.MONOSPACE
        setPadding(4, 0, 4, 28)
        letterSpacing = 0.06f
    }
    fun label(a: AppCompatActivity, s: String, color: Int = MUTED) = TextView(a).apply {
        text = s; textSize = 13f; setTextColor(color)
        setPadding(4, 20, 4, 10)
        setLineSpacing(6f, 1f)
    }
    fun mono(a: AppCompatActivity, s: String, color: Int = FG) = TextView(a).apply {
        text = s; textSize = 13f; setTextColor(color); typeface = Typeface.MONOSPACE
        setLineSpacing(4f, 1f)
        setTextIsSelectable(false)
    }
    /** Monospace text inside a rounded card — for armored blocks & fingerprints. */
    fun monoCard(a: AppCompatActivity, s: String = "", color: Int = FG) = TextView(a).apply {
        text = s; textSize = 12f; setTextColor(color); typeface = Typeface.MONOSPACE
        background = rounded(CARD, BORDER)
        setPadding(32, 28, 32, 28)
        setLineSpacing(4f, 1f)
        setTextIsSelectable(false)
    }
    fun field(a: AppCompatActivity, hintText: String, multi: Boolean = false) = EditText(a).apply {
        hint = hintText; setHintTextColor(MUTED); setTextColor(FG)
        background = rounded(FIELD_BG, BORDER)
        setPadding(32, 30, 32, 30)
        textSize = 14f; typeface = Typeface.MONOSPACE
        if (multi) {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            minLines = 4; maxLines = 10; gravity = Gravity.TOP
        } else {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
    }
    fun password(a: AppCompatActivity, hintText: String) = field(a, hintText).apply {
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }
    fun button(a: AppCompatActivity, s: String, color: Int = ACCENT_DIM, onClick: () -> Unit) = Button(a).apply {
        text = s
        setTextColor(if (color == CARD || color == FIELD_BG) FG else Color.WHITE)
        background = rounded(color, if (color == CARD || color == FIELD_BG) BORDER else 0)
        isAllCaps = false; textSize = 15f
        stateListAnimator = null; elevation = 0f
        setPadding(36, 34, 36, 34)
        setOnClickListener { onClick() }
    }
    /** Secondary (outlined) button. */
    fun buttonAlt(a: AppCompatActivity, s: String, textColor: Int = FG, onClick: () -> Unit) =
        button(a, s, CARD, onClick).apply { setTextColor(textColor) }

    fun column(a: AppCompatActivity) = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(BG)
        setPadding(52, 56, 52, 72)
    }
    fun spacer(a: AppCompatActivity, h: Int) = TextView(a).apply { height = h }

    /** Thin horizontal divider. */
    fun divider(a: AppCompatActivity) = TextView(a).apply {
        height = 2; setBackgroundColor(BORDER)
    }
}

/** Base for all screens: secure window + auto-lock enforcement. */
abstract class SecureActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow()
    }
    override fun onResume() {
        super.onResume()
        if (needsUnlock() && !Session.unlocked) {
            startActivity(Intent(this, UnlockActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK))
            finish()
            return
        }
        Session.touch()
    }
    override fun onUserInteraction() {
        super.onUserInteraction()
        Session.touch()
    }
    open fun needsUnlock(): Boolean = true
}
