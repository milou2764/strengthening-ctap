package com.example.ctapwallet

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresPermission
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

/**
 * Hosts the GATT enrollment service and runs the numeric-comparison exchange.
 *
 * The verification code must be a value no participant can bias: a code derived
 * from the client's key alone -- or from the key and a nonce the authenticator
 * picks -- can be steered by an adversary that is the authenticator of another
 * pairing, which lets it show the user two codes that agree across two
 * different pairings. We therefore use the Bluetooth Secure Simple Pairing
 * construction: both sides contribute a nonce, this side commits to its nonce
 * before the client reveals its own, and the code covers both nonces together
 * with the authenticator identifier and the client's public key.
 *
 * The exchange, with the client as GATT central:
 *
 *   1. client reads  AID          (AID)
 *   2. client writes {name, key}  (KEY)   -- we then draw Na and commit
 *   3. client reads  C            (COMMIT)   -- C = H(COMMIT | AID | PKc | Na)
 *   4. client writes Nc           (CLIENT-NONCE)
 *   5. client reads  Na           (AUTH-NONCE)   -- refused before Nc arrives
 *   6. both compute  code = H(CODE | AID | PKc | Na | Nc) mod 10^6
 *   7. user confirms; we store PKc and notify (RESULT)
 *
 * Step 3 before step 4 fixes our contribution before we learn the client's;
 * step 4 before step 5 fixes the client's before it learns ours. Neither side,
 * and no adversary running two pairings, can bias the result.
 */
class EnrollmentGattServer(
    private val context: Context,
    /** Invoked with (code, clientName, clientPublicKey) once both nonces are in. */
    private val onCodeReady: (String, String, ByteArray) -> Unit,
) {
    companion object {
        private const val LOG_TAG = "CtapWallet"

        val SERVICE_UUID: UUID =
            UUID.fromString("0e310001-70b7-400b-86ba-3d68865ce5cd")
        val KEY_CHAR_UUID: UUID =
            UUID.fromString("0e310002-70b7-400b-86ba-3d68865ce5cd")
        val RESULT_CHAR_UUID: UUID =
            UUID.fromString("0e310003-70b7-400b-86ba-3d68865ce5cd")
        val AID_CHAR_UUID: UUID =
            UUID.fromString("0e310004-70b7-400b-86ba-3d68865ce5cd")
        val COMMIT_CHAR_UUID: UUID =
            UUID.fromString("0e310005-70b7-400b-86ba-3d68865ce5cd")
        val CLIENT_NONCE_CHAR_UUID: UUID =
            UUID.fromString("0e310006-70b7-400b-86ba-3d68865ce5cd")
        val AUTH_NONCE_CHAR_UUID: UUID =
            UUID.fromString("0e310007-70b7-400b-86ba-3d68865ce5cd")
        private val CCCD_UUID: UUID =
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        private val COMMIT_LABEL = "CTAP-enroll-commit".toByteArray()
        private val CODE_LABEL = "CTAP-enroll-code".toByteArray()

        /** C = SHA-256(COMMIT | AID | PKc | Na). */
        fun commitment(aid: ByteArray, publicKey: ByteArray, na: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").run {
                update(COMMIT_LABEL); update(aid); update(publicKey); update(na)
                digest()
            }

        /**
         * The six-digit code both sides display, over everything the pairing
         * fixed: the authenticator identifier, the client's public key, and the
         * two nonces.
         */
        fun verificationCode(
            aid: ByteArray,
            publicKey: ByteArray,
            na: ByteArray,
            nc: ByteArray,
        ): String {
            val h = MessageDigest.getInstance("SHA-256").run {
                update(CODE_LABEL); update(aid); update(publicKey)
                update(na); update(nc)
                digest()
            }
            val v = ((h[0].toLong() and 0xff) shl 24) or
                ((h[1].toLong() and 0xff) shl 16) or
                ((h[2].toLong() and 0xff) shl 8) or
                (h[3].toLong() and 0xff)
            return "%06d".format(v % 1_000_000L)
        }
    }

    private var gattServer: BluetoothGattServer? = null
    private var resultChar: BluetoothGattCharacteristic? = null
    private var connectedDevice: BluetoothDevice? = null

    private val aid: ByteArray = AuthenticatorIdentity.get(context)
    private var authNonce: ByteArray? = null      // Na, drawn when the key arrives
    private var clientNonce: ByteArray? = null    // Nc, written by the client
    private var clientKey: ByteArray? = null      // PKc (SubjectPublicKeyInfo)
    private var clientName: String = "(unknown)"
    private var commitment: ByteArray? = null
    private var keyReceivedNs = 0L   // measurement

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun start() {
        val manager =
            context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val server = manager.openGattServer(context, callback)
        val service =
            BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        fun readable(uuid: UUID) = BluetoothGattCharacteristic(
            uuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        fun writable(uuid: UUID) = BluetoothGattCharacteristic(
            uuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )

        val rChar = BluetoothGattCharacteristic(
            RESULT_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        rChar.addDescriptor(
            BluetoothGattDescriptor(
                CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or
                    BluetoothGattDescriptor.PERMISSION_WRITE,
            )
        )

        service.addCharacteristic(writable(KEY_CHAR_UUID))
        service.addCharacteristic(rChar)
        service.addCharacteristic(readable(AID_CHAR_UUID))
        service.addCharacteristic(readable(COMMIT_CHAR_UUID))
        service.addCharacteristic(writable(CLIENT_NONCE_CHAR_UUID))
        service.addCharacteristic(readable(AUTH_NONCE_CHAR_UUID))
        server.addService(service)

        gattServer = server
        resultChar = rChar
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun stop() {
        gattServer?.close()
        gattServer = null
        resultChar = null
        connectedDevice = null
        authNonce = null
        clientNonce = null
        clientKey = null
        commitment = null
    }

    /** Notifies the connected client that enrollment was confirmed. */
    @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
    fun notifyEnrolled() {
        val server = gattServer ?: return
        val device = connectedDevice ?: return
        val rc = resultChar ?: return
        val payload = byteArrayOf(1)
        if (Build.VERSION.SDK_INT >= 33) {
            server.notifyCharacteristicChanged(device, rc, false, payload)
        } else {
            @Suppress("DEPRECATION")
            run {
                rc.value = payload
                server.notifyCharacteristicChanged(device, rc, false)
            }
        }
    }

    private val callback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(
            device: BluetoothDevice?, status: Int, newState: Int,
        ) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connectedDevice = device
            }
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice?,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic?,
        ) {
            connectedDevice = device
            val value: ByteArray? = when (characteristic?.uuid) {
                AID_CHAR_UUID -> aid
                COMMIT_CHAR_UUID -> commitment
                // Our nonce is revealed only once the client's is committed to
                // us: releasing it earlier would let the client choose its own
                // nonce with ours in hand, and bias the code.
                AUTH_NONCE_CHAR_UUID -> if (clientNonce != null) authNonce else null
                else -> null
            }
            if (value == null) {
                gattServer?.sendResponse(
                    device, requestId, BluetoothGatt.GATT_FAILURE, offset, null
                )
                return
            }
            val slice =
                if (offset in 1..value.size) value.copyOfRange(offset, value.size)
                else if (offset == 0) value
                else ByteArray(0)
            gattServer?.sendResponse(
                device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice
            )
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            connectedDevice = device
            var ok = false
            if (value != null) {
                when (characteristic?.uuid) {
                    KEY_CHAR_UUID -> ok = onKeyWritten(value)
                    CLIENT_NONCE_CHAR_UUID -> ok = onClientNonceWritten(value)
                    else -> ok = false
                }
            }
            if (responseNeeded) {
                gattServer?.sendResponse(
                    device,
                    requestId,
                    if (ok) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
                    offset,
                    value,
                )
            }
        }

        @RequiresPermission(Manifest.permission.BLUETOOTH_CONNECT)
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            descriptor: BluetoothGattDescriptor?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?,
        ) {
            // The client subscribes to notifications by writing the CCCD.
            if (responseNeeded) {
                gattServer?.sendResponse(
                    device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value
                )
            }
        }
    }

    /** Step 2: the client's public key arrives; draw Na and commit to it. */
    private fun onKeyWritten(payload: ByteArray): Boolean {
        val json = try {
            org.json.JSONObject(String(payload, Charsets.UTF_8))
        } catch (e: Exception) {
            Log.w(LOG_TAG, "invalid enrollment payload", e)
            return false
        }
        val key = try {
            android.util.Base64.decode(json.getString("key"), android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            return false
        }
        clientName = try {
            String(
                android.util.Base64.decode(
                    json.getString("name"), android.util.Base64.NO_WRAP
                )
            )
        } catch (e: Exception) {
            "(unknown)"
        }
        val na = ByteArray(16)
        SecureRandom().nextBytes(na)
        keyReceivedNs = System.nanoTime()
        clientKey = key
        authNonce = na
        clientNonce = null
        commitment = commitment(aid, key, na)
        Log.i(LOG_TAG, "client key received (${key.size} bytes); committed to Na")
        return true
    }

    /** Step 4: the client's nonce arrives; the code is now determined. */
    private fun onClientNonceWritten(value: ByteArray): Boolean {
        val key = clientKey ?: return false
        val na = authNonce ?: return false
        if (value.size != 16) return false
        clientNonce = value
        val code = verificationCode(aid, key, na, value)
        // MEASURE enrollment on the authenticator: key received -> code fixed.
        Log.i(LOG_TAG, "MEASURE enrollment comparison_ms=${(System.nanoTime() - keyReceivedNs) / 1_000_000}")
        onCodeReady(code, clientName, key)
        return true
    }
}
