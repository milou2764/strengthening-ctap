package com.example.ctapwallet.cable

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.security.KeyPair

/**
 * A discoverable passkey created over the caBLE transport.
 * The P-256 key pair is Java-serialized (software-held, like the reference SDK).
 */
data class Passkey(
    val rpId: String,
    val credentialId: ByteArray,
    val userHandle: ByteArray,
    val displayName: String,
    val keyPair: KeyPair,
)

/** SharedPreferences-backed passkey storage, one JSON array of credentials. */
class PasskeyStore(context: Context) {
    private val prefs = context.getSharedPreferences("ctap_passkeys", Context.MODE_PRIVATE)

    fun save(passkey: Passkey) {
        val arr = load()
        arr.add(passkey)
        persist(arr)
    }

    /** Returns passkeys for [rpId] matching one of [credentialIds] (empty = any). */
    fun find(rpId: String, credentialIds: List<ByteArray>): List<Passkey> =
        load().filter { pk ->
            pk.rpId == rpId && (credentialIds.isEmpty() ||
                credentialIds.any { it.contentEquals(pk.credentialId) })
        }

    fun all(): List<Passkey> = load()

    fun remove(credentialId: ByteArray) {
        persist(load().filterNot { it.credentialId.contentEquals(credentialId) }.toMutableList())
    }

    private fun load(): MutableList<Passkey> {
        val raw = prefs.getString(KEY, null) ?: return mutableListOf()
        val out = mutableListOf<Passkey>()
        val arr = JSONArray(raw)
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out.add(
                Passkey(
                    rpId = o.getString("rpId"),
                    credentialId = b64(o.getString("credentialId")),
                    userHandle = b64(o.getString("userHandle")),
                    displayName = o.getString("displayName"),
                    keyPair = kpFromBytes(b64(o.getString("keyPair"))),
                )
            )
        }
        return out
    }

    private fun persist(list: List<Passkey>) {
        val arr = JSONArray()
        for (pk in list) {
            arr.put(
                JSONObject()
                    .put("rpId", pk.rpId)
                    .put("credentialId", b64(pk.credentialId))
                    .put("userHandle", b64(pk.userHandle))
                    .put("displayName", pk.displayName)
                    .put("keyPair", b64(kpToBytes(pk.keyPair)))
            )
        }
        prefs.edit().putString(KEY, arr.toString()).apply()
    }

    companion object {
        private const val KEY = "passkeys"

        private fun b64(b: ByteArray): String = Base64.encodeToString(b, Base64.NO_WRAP)
        private fun b64(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)

        private fun kpToBytes(kp: KeyPair): ByteArray {
            val baos = ByteArrayOutputStream()
            ObjectOutputStream(baos).use { it.writeObject(kp) }
            return baos.toByteArray()
        }

        private fun kpFromBytes(bytes: ByteArray): KeyPair =
            ObjectInputStream(ByteArrayInputStream(bytes)).use { it.readObject() as KeyPair }
    }
}
