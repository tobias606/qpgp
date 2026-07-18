package org.qpgp.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import org.qpgp.protocol.Qr

/**
 * Scans an animated identity-QR sequence. Camera permission is requested
 * here and used only while this screen is open. The assembled text is
 * returned to AddContactActivity, which runs it through the SAME strict
 * import parser as a manual paste — a malicious QR can do nothing a
 * malicious paste couldn't.
 */
class QrScanActivity : SecureActivity() {
    private lateinit var barcodeView: DecoratedBarcodeView
    private lateinit var progress: TextView
    private val assembler = Qr.Assembler(Qr.TYPE_IDENTITY)

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) barcodeView.resume() else finish()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val col = Ui.column(this)
        col.addView(Ui.title(this, "⬢ Scan identity"))
        col.addView(Ui.subtitle(this, "point at your contact's QR loop"))

        barcodeView = DecoratedBarcodeView(this).apply {
            statusView.text = ""
            viewFinder.setLaserVisibility(false)
        }
        col.addView(barcodeView, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        col.addView(Ui.spacer(this, 20))
        progress = Ui.mono(this, "waiting for first frame…", Ui.ACCENT)
        col.addView(progress)
        col.addView(Ui.spacer(this, 12))
        col.addView(Ui.label(this,
            "Frames are collected in any order — keep the camera on the loop " +
            "until all are captured."))

        setContentView(col)

        barcodeView.decodeContinuous(object : BarcodeCallback {
            override fun barcodeResult(result: BarcodeResult) {
                val text = result.text ?: return
                val complete = assembler.collect(text)
                progress.text =
                    if (assembler.expected > 0) "frames: ${assembler.received} / ${assembler.expected}"
                    else "waiting for first frame…"
                if (complete != null) {
                    barcodeView.pause()
                    setResult(RESULT_OK, intent.putExtra(EXTRA_BLOCK, complete))
                    finish()
                }
            }
        })
    }

    override fun onResume() {
        super.onResume()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            == PackageManager.PERMISSION_GRANTED) barcodeView.resume()
        else permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    override fun onPause() {
        super.onPause()
        barcodeView.pause()
    }

    companion object { const val EXTRA_BLOCK = "block" }
}
