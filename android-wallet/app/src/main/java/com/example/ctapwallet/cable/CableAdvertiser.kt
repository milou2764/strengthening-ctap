package com.example.ctapwallet.cable

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertisingSet
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.AdvertisingSetParameters
import android.os.ParcelUuid
import android.util.Log
import androidx.annotation.RequiresPermission
import java.util.UUID

/**
 * Broadcasts the caBLE v2 BLE advertisement (service UUID 0xFFF9) that lets the
 * desktop client discover this authenticator's tunnel connection. The 20-byte
 * service data is the encrypted EID + HMAC tag derived from the QR secret.
 */
object CableAdvertiser {
    private const val TAG = "CableAdvertiser"
    private val CABLE_UUID = UUID.fromString("0000fff9-0000-1000-8000-00805f9b34fb")

    private var advertisingSet: AdvertisingSet? = null

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun start(serviceData: ByteArray) {
        val advertiser = BluetoothAdapter.getDefaultAdapter().bluetoothLeAdvertiser
        val parameters = AdvertisingSetParameters.Builder()
            .setLegacyMode(true)
            .setConnectable(true)
            .setScannable(true)
            .setInterval(AdvertisingSetParameters.INTERVAL_LOW)
            .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceData(ParcelUuid(CABLE_UUID), serviceData)
            .build()
        val callback = object : AdvertisingSetCallback() {
            override fun onAdvertisingSetStarted(set: AdvertisingSet, txPower: Int, status: Int) {
                Log.i(TAG, "advertising started: txPower=$txPower status=$status")
                advertisingSet = set
            }

            override fun onAdvertisingSetStopped(set: AdvertisingSet) {
                Log.i(TAG, "advertising stopped")
            }
        }
        advertiser.startAdvertisingSet(parameters, data, null, null, null, callback)
    }

    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    fun stop() {
        val advertiser = BluetoothAdapter.getDefaultAdapter()?.bluetoothLeAdvertiser ?: return
        try {
            advertiser.stopAdvertisingSet(object : AdvertisingSetCallback() {})
        } catch (e: Exception) {
            Log.w(TAG, "stop failed: ${e.message}")
        }
        advertisingSet = null
    }
}
