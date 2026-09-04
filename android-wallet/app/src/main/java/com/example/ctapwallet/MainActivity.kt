package com.example.ctapwallet

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.content.Intent
import android.util.Base64
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.ctapwallet.cable.QrScanActivity

/**
 * Authenticator side of the client-enrollment countermeasure (direct BLE
 * connection + numeric comparison).
 *
 *  1. The user starts enrolling a new client here. The authenticator advertises
 *     its presence and hosts a GATT enrollment service.
 *  2. The user opens chrome://ctap-enrollment in their browser's address bar;
 *     that client connects directly over BLE and writes its public key.
 *  3. Both devices show a verification code derived from that key; the user
 *     confirms here only if the codes match, and the key is stored.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var enrollButton: Button
    private lateinit var scanButton: Button
    private lateinit var requireClientAuth: CheckBox
    private lateinit var statusView: TextView
    private lateinit var doneButton: Button
    private lateinit var codeInput: android.widget.EditText
    private lateinit var codeLabel: TextView
    private lateinit var confirmButton: Button
    private lateinit var enrolledList: LinearLayout
    private lateinit var trustStore: ClientTrustStore

    private var gattServer: EnrollmentGattServer? = null
    private var pendingKey: ByteArray? = null
    private var pendingName: String = ""
    private var expectedCode: String? = null

    private val requestPerms =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
            if (grants.values.all { it }) {
                startEnrollment()
            } else {
                statusView.text = "Bluetooth permissions denied"
                enrollButton.visibility = View.VISIBLE
                doneButton.visibility = View.GONE
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        enrollButton = findViewById(R.id.enroll)
        scanButton = findViewById(R.id.scanQr)
        requireClientAuth = findViewById(R.id.requireClientAuth)
        statusView = findViewById(R.id.status)
        doneButton = findViewById(R.id.done)
        codeInput = findViewById(R.id.codeInput)
        codeLabel = findViewById(R.id.codeLabel)
        confirmButton = findViewById(R.id.confirm)
        enrolledList = findViewById(R.id.enrolledList)
        trustStore = ClientTrustStore(this)
        doneButton.visibility = View.GONE
        confirmButton.visibility = View.GONE
        enrollButton.setOnClickListener { showInstruction() }
        scanButton.setOnClickListener {
            val intent = Intent(this, QrScanActivity::class.java)
            intent.putExtra(QrScanActivity.EXTRA_REQUIRE_CLIENT_AUTH, requireClientAuth.isChecked)
            startActivity(intent)
        }
        doneButton.setOnClickListener { ensurePermissionsAndStart() }
        confirmButton.setOnClickListener { onConfirm() }
        refreshEnrolledList()
    }

    private fun refreshEnrolledList() {
        enrolledList.removeAllViews()
        val clients = trustStore.enrolled().toList()
        if (clients.isEmpty()) {
            val tv = TextView(this)
            tv.text = "(none)"
            enrolledList.addView(tv)
            return
        }
        for (entry in clients) {
            val row = LinearLayout(this)
            row.orientation = LinearLayout.HORIZONTAL

            val label = TextView(this)
            val days = entry.daysLeft()
            label.text = if (entry.isExpired()) "${entry.name} (expired)"
                else "${entry.name} (expires in $days d)"
            label.layoutParams = LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)

            val remove = Button(this)
            remove.text = "Remove"
            remove.setOnClickListener {
                trustStore.removeClient(entry.publicKeyB64)
                refreshEnrolledList()
            }

            row.addView(label)
            row.addView(remove)
            enrolledList.addView(row)
        }
    }

    private fun showInstruction() {
        statusView.text = "Open chrome://ctap-enrollment in your browser's " +
            "address bar, then tap Done."
        enrollButton.visibility = View.GONE
        doneButton.visibility = View.VISIBLE
        codeInput.setText(""); codeInput.visibility = View.GONE; codeLabel.visibility = View.GONE
        confirmButton.visibility = View.GONE
    }

    private fun ensurePermissionsAndStart() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val needed = arrayOf(
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_CONNECT,
            )
            val allGranted = needed.all {
                ContextCompat.checkSelfPermission(this, it) ==
                    PackageManager.PERMISSION_GRANTED
            }
            if (allGranted) {
                startEnrollment()
            } else {
                requestPerms.launch(needed)
            }
        } else {
            startEnrollment()
        }
    }

    @SuppressLint("MissingPermission")
    private fun startEnrollment() {
        pendingKey = null
        codeInput.setText(""); codeInput.visibility = View.GONE; codeLabel.visibility = View.GONE
        doneButton.visibility = View.GONE
        confirmButton.visibility = View.GONE

        gattServer?.stop()
        val server = EnrollmentGattServer(this) { code, name, key ->
            runOnUiThread { onCodeReady(code, name, key) }
        }
        server.start()
        gattServer = server

        BleEnrollmentAdvertiser.start { ok ->
            runOnUiThread {
                statusView.text = if (ok) {
                    "Advertising. Open chrome://ctap-enrollment on your client."
                } else {
                    "Advertising failed (adapter off or role unsupported)."
                }
            }
        }
    }

    /**
     * Both nonces are in, so the code is fixed. Neither side could steer it:
     * we committed to ours before the client sent its own.
     */
    private fun onCodeReady(code: String, name: String, key: ByteArray) {
        pendingKey = key
        pendingName = name
        expectedCode = code
        codeInput.setText("")
        codeInput.visibility = View.VISIBLE
        codeLabel.visibility = View.VISIBLE
        statusView.text = "\"$name\" connected. Type the 6-digit code shown by " +
            "that client, then validate."
        confirmButton.visibility = View.VISIBLE
    }

    @SuppressLint("MissingPermission")
    private fun onConfirm() {
        val key = pendingKey ?: return
        val expected = expectedCode ?: return
        // The comparison is done here, not by the user: a wrong entry ends the
        // enrollment. Fresh nonces on the next attempt keep the guessing bound
        // at one 10^-6 trial per run.
        if (codeInput.text.toString().trim() != expected) {
            gattServer?.stop()
            gattServer = null
            BleEnrollmentAdvertiser.stop()
            pendingKey = null
            expectedCode = null
            codeInput.setText(""); codeInput.visibility = View.GONE; codeLabel.visibility = View.GONE
            confirmButton.visibility = View.GONE
            enrollButton.visibility = View.VISIBLE
            statusView.text = "Wrong code — enrollment aborted. Start again from \"Enroll a new client\"."
            return
        }
        trustStore.addClient(Base64.encodeToString(key, Base64.NO_WRAP), pendingName)
        refreshEnrolledList()
        // Notify the client that enrollment was confirmed, before tearing down.
        gattServer?.notifyEnrolled()
        statusView.text = "Enrolled (${trustStore.count()} client(s))."
        codeInput.setText(""); codeInput.visibility = View.GONE; codeLabel.visibility = View.GONE
        confirmButton.visibility = View.GONE
        enrollButton.visibility = View.VISIBLE
        pendingKey = null
        BleEnrollmentAdvertiser.stop()
        // Keep the GATT server open so the notification is delivered; it is
        // closed on the next enrollment or in onDestroy.
    }

    @SuppressLint("MissingPermission")
    override fun onDestroy() {
        super.onDestroy()
        BleEnrollmentAdvertiser.stop()
        gattServer?.stop()
        gattServer = null
    }
}
