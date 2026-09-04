package com.example.ctapwallet.cable

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.TextView
import androidx.annotation.OptIn
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import co.nstant.`in`.cbor.CborDecoder
import com.example.ctapwallet.R
import zxingcpp.BarcodeReader
import java.util.concurrent.Executors

/**
 * Scans the desktop client's caBLE `FIDO:/…` QR, then runs the CTAP hybrid
 * authenticator flow (with the client-authentication countermeasure) through
 * [CableTunnel].
 */
class QrScanActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "QrScanActivity"
        const val EXTRA_REQUIRE_CLIENT_AUTH = "require_client_auth"
    }

    private lateinit var previewView: PreviewView
    private lateinit var statusView: TextView
    private val analysisExecutor = Executors.newSingleThreadExecutor()
    private val barcodeReader = BarcodeReader()
    private var handled = false
    private var tunnel: CableTunnel? = null

    private val permissions = arrayOf(
        Manifest.permission.CAMERA,
        Manifest.permission.BLUETOOTH_ADVERTISE,
        Manifest.permission.BLUETOOTH_CONNECT,
    )

    private val requestPerms =
        registerForActivityResult(
            androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions()
        ) { grants ->
            if (grants.values.all { it }) startCamera()
            else setStatus("Camera and Bluetooth permissions are required.")
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = FrameLayout(this)
        previewView = PreviewView(this).apply {
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
            )
        }
        statusView = TextView(this).apply {
            setBackgroundColor(0xAA000000.toInt())
            setTextColor(0xFFFFFFFF.toInt())
            textSize = 16f
            setPadding(32, 32, 32, 32)
            text = "Point the camera at the sign-in QR code."
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM
            )
        }
        root.addView(previewView)
        root.addView(statusView)
        setContentView(root)

        if (permissions.all {
                ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
            }) {
            startCamera()
        } else {
            requestPerms.launch(permissions)
        }
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(analysisExecutor, ::analyze)
            provider.unbindAll()
            provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, ContextCompat.getMainExecutor(this))
    }

    @OptIn(ExperimentalGetImage::class)
    private fun analyze(image: ImageProxy) {
        try {
            if (handled) return
            val bitmap = image.toBitmap()
            val results = barcodeReader.read(bitmap)
            val text = results.firstOrNull()?.text
            if (text != null && text.startsWith("FIDO:/")) {
                handled = true
                onQr(text)
            }
        } catch (e: Exception) {
            Log.e(TAG, "analyze error", e)
        } finally {
            image.close()
        }
    }

    private fun onQr(fidoUri: String) {
        val cbor = DigitCoder.digitDecode(fidoUri.drop(6))
        if (cbor == null) {
            setStatus("Unreadable QR payload.")
            handled = false
            return
        }
        val data = (CborDecoder.decode(cbor)[0] as co.nstant.`in`.cbor.model.Map).values.toTypedArray()
        val compressedPublicKey = (data[0] as co.nstant.`in`.cbor.model.ByteString).bytes
        val qrSecret = (data[1] as co.nstant.`in`.cbor.model.ByteString).bytes

        val requireClientAuth = intent.getBooleanExtra(EXTRA_REQUIRE_CLIENT_AUTH, true)
        setStatus("QR scanned. Connecting to the tunnel…")

        val t = CableTunnel(applicationContext, requireClientAuth) { s -> setStatus(s) }
        t.qrSecret = qrSecret
        t.compressedPublicKey = compressedPublicKey
        tunnel = t
        analysisExecutor.execute {
            try {
                t.connect()
            } catch (e: Exception) {
                Log.e(TAG, "connect failed", e)
                setStatus("Connection failed: ${e.message}")
            }
        }
    }

    private fun setStatus(text: String) = runOnUiThread { statusView.text = text }

    override fun onDestroy() {
        super.onDestroy()
        analysisExecutor.shutdown()
    }
}
