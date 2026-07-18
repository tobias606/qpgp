package org.qpgp.ui

import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.ImageView
import android.widget.LinearLayout
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.qpgp.Engine
import org.qpgp.protocol.Qr

/**
 * Shows the identity block as an animated multi-frame QR sequence.
 * The peer scans with "Scan identity QR" and collects frames in any order.
 */
class QrShowActivity : SecureActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private var frames: List<Bitmap> = emptyList()
    private var i = 0
    private lateinit var img: ImageView
    private lateinit var counter: android.widget.TextView

    private val tick = object : Runnable {
        override fun run() {
            if (frames.isEmpty()) return
            img.setImageBitmap(frames[i])
            counter.text = "frame ${i + 1} / ${frames.size} — cycling automatically"
            i = (i + 1) % frames.size
            handler.postDelayed(this, FRAME_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val d = Session.data ?: return
        val name = intent.getStringExtra("name") ?: ""
        val block = Engine.exportIdentity(d, name)
        val parts = Qr.split(Qr.TYPE_IDENTITY, block)
        frames = parts.map { encodeQr(it) }

        val col = Ui.column(this)
        col.gravity = Gravity.CENTER_HORIZONTAL
        col.addView(Ui.title(this, "⬢ Identity QR"))
        col.addView(Ui.subtitle(this, "let your contact scan until complete"))

        img = ImageView(this).apply {
            adjustViewBounds = true
            scaleType = ImageView.ScaleType.FIT_CENTER
            setBackgroundColor(Color.WHITE)
            val pad = 24; setPadding(pad, pad, pad, pad)
        }
        col.addView(img, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT))
        col.addView(Ui.spacer(this, 20))
        counter = Ui.mono(this, "", Ui.ACCENT)
        col.addView(counter)
        col.addView(Ui.spacer(this, 16))
        col.addView(Ui.label(this,
            "Contains only PUBLIC keys — safe to show. Frames repeat in a loop; " +
            "the scanner collects them in any order. Afterwards, compare the six " +
            "verification words together."))

        setContentView(android.widget.ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(col) })
    }

    override fun onResume() { super.onResume(); handler.post(tick) }
    override fun onPause() { super.onPause(); handler.removeCallbacks(tick) }

    private fun encodeQr(text: String): Bitmap {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.CHARACTER_SET to "UTF-8",
            EncodeHintType.MARGIN to 1
        )
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, SIZE, SIZE, hints)
        val bmp = Bitmap.createBitmap(SIZE, SIZE, Bitmap.Config.RGB_565)
        for (y in 0 until SIZE) for (x in 0 until SIZE)
            bmp.setPixel(x, y, if (m.get(x, y)) Color.BLACK else Color.WHITE)
        return bmp
    }

    companion object {
        private const val SIZE = 900
        private const val FRAME_MS = 350L
    }
}
