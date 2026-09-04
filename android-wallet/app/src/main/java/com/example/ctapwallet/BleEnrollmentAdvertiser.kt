package com.example.ctapwallet

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertisingSet
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.AdvertisingSetParameters
import android.os.ParcelUuid
import android.util.Log
import androidx.annotation.RequiresPermission

/**
 * Advertises the authenticator's presence while it is in enrollment mode: a
 * connectable advertisement carrying the dedicated 128-bit enrollment service UUID. The
 * client (chrome://ctap-enrollment) scans for this UUID, then opens a direct
 * GATT connection to the authenticator (see [EnrollmentGattServer]). No secret
 * is broadcast here.
 */
object BleEnrollmentAdvertiser {
    private const val LOG_TAG = "CtapWallet"

    private var callback: AdvertisingSetCallback? = null

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun start(onResult: (Boolean) -> Unit) {
        val advertiser = BluetoothAdapter.getDefaultAdapter()?.bluetoothLeAdvertiser
        if (advertiser == null) {
            Log.e(LOG_TAG, "No BLE advertiser (adapter off or role unsupported)")
            onResult(false)
            return
        }
        stop()

        val parameters = AdvertisingSetParameters.Builder()
            .setLegacyMode(true)
            .setConnectable(true)
            .setScannable(true)
            .setInterval(AdvertisingSetParameters.INTERVAL_LOW)
            .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(EnrollmentGattServer.SERVICE_UUID))
            .build()

        val cb = object : AdvertisingSetCallback() {
            override fun onAdvertisingSetStarted(
                advertisingSet: AdvertisingSet?, txPower: Int, status: Int
            ) {
                Log.i(LOG_TAG, "advertising started status=$status")
                onResult(status == ADVERTISE_SUCCESS)
            }

            override fun onAdvertisingSetStopped(advertisingSet: AdvertisingSet?) {
                Log.i(LOG_TAG, "advertising stopped")
            }
        }
        callback = cb
        advertiser.startAdvertisingSet(parameters, data, null, null, null, cb)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stop() {
        val advertiser = BluetoothAdapter.getDefaultAdapter()?.bluetoothLeAdvertiser ?: return
        callback?.let { advertiser.stopAdvertisingSet(it) }
        callback = null
    }
}
