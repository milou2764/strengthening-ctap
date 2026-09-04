package com.example.ctapwallet

import android.content.Context
import android.util.Base64
import java.security.SecureRandom

/**
 * The authenticator's own stable identifier (AID).
 *
 * The client keeps a distinct identity key per authenticator, so it must be
 * able to tell which authenticator it is dealing with: the AID is handed to it
 * when the enrollment connection opens, and again at the start of every hybrid
 * session so it can select the matching private key.
 *
 * It is a random per-device value generated once. It never appears in the QR
 * code or the BLE advertisement -- a stable identifier there would let a
 * passive observer recognise the user's authenticator.
 */
object AuthenticatorIdentity {

    private const val PREFS = "ctap_authenticator"
    private const val KEY_AID = "aid"

    fun get(context: Context): ByteArray {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stored = prefs.getString(KEY_AID, null)
        if (stored != null) {
            val bytes = Base64.decode(stored, Base64.NO_WRAP)
            if (bytes.size == 32) return bytes
        }
        val aid = ByteArray(32)
        SecureRandom().nextBytes(aid)
        prefs.edit().putString(KEY_AID, Base64.encodeToString(aid, Base64.NO_WRAP)).apply()
        return aid
    }
}
