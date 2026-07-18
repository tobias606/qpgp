package org.kelopatra.ui

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/** Shared dark, minimal styling helpers. */
object Ui {
    const val BG = 0xFF0D1117.toInt()
    const val FG = 0xFFE6EDF3.toInt()
    const val ACCENT = 0xFF2EA043.toInt()
    const val WARN = 0xFFD29922.toInt()
    const val DANGER = 0xFFF85149.toInt()
    const val MUTED = 0xFF8B949E.toInt()
    const val FIELD_BG = 0xFF161B22.toInt()

    fun pad(v: Int) = (v * 3)

    fun title(a: AppCompatActivity, s: String) = TextView(a).apply {
        text = s; textSize = 22f; setTextColor(FG); typeface = Typeface.MONOSPACE
        setPadding(0, 24, 0, 24)
    }
    fun label(a: AppCompatActivity, s: String, color: Int = MUTED) = TextView(a).apply {
        text = s; textSize = 13f; setTextColor(color); setPadding(0, 16, 0, 4)
    }
    fun mono(a: AppCompatActivity, s: String, color: Int = FG) = TextView(a).apply {
        text = s; textSize = 13f; setTextColor(color); typeface = Typeface.MONOSPACE
        setTextIsSelectable(false)
    }
    fun field(a: AppCompatActivity, hintText: String, multi: Boolean = false) = EditText(a).apply {
        hint = hintText; setHintTextColor(MUTED); setTextColor(FG)
        setBackgroundColor(FIELD_BG); setPadding(28, 24, 28, 24)
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
    fun button(a: AppCompatActivity, s: String, color: Int = ACCENT, onClick: () -> Unit) = Button(a).apply {
        text = s; setTextColor(Color.WHITE); setBackgroundColor(color)
        isAllCaps = false; textSize = 15f
        setPadding(32, 28, 32, 28)
        setOnClickListener { onClick() }
    }
    fun column(a: AppCompatActivity) = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(BG)
        setPadding(48, 48, 48, 48)
    }
    fun spacer(a: AppCompatActivity, h: Int) = TextView(a).apply { height = h }
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
    override fun onPause() {
        super.onPause()
        // leaving foreground = lock soon; conservative: rely on idle timer,
        // but scrub clipboard-free guarantee is inherent (we never write clipboard)
    }
    open fun needsUnlock(): Boolean = true
}
