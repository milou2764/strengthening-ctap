package com.example.ctapwallet.cable

import android.content.Context
import android.util.Base64
import android.util.Log
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.Number
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.example.ctapwallet.ClientTrustStore
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlin.math.abs

/**
 * Verifies the per-session client-authentication assertion (the CTAP client
 * countermeasure). The desktop client sends a COSE_Sign1, signed by its enrolled
 * identity key, binding this session's Noise handshake hash and a timestamp.
 *
 *   COSE_Sign1 = [ protected:bstr({1:-7}), {}, payload:bstr, sig:bstr(raw r||s) ]
 *   payload    = { 1: handshake_hash(32), 2: unix_millis(int) }
 *
 * The session is authorised only if the signed handshake hash matches this
 * session's, the timestamp is fresh, and the signature verifies against a key
 * in the trust store.
 */
object ClientAuthVerifier {
    private const val TAG = "ClientAuthVerifier"
    private const val MAX_SKEW_MS = 5 * 60 * 1000L

    data class Result(val ok: Boolean, val clientName: String?, val reason: String)

    fun verify(
        context: Context,
        coseSign1: ByteArray,
        expectedHandshakeHash: ByteArray,
    ): Result {
        return try {
            val cose = (CborDecoder.decode(coseSign1)[0] as co.nstant.`in`.cbor.model.Array).dataItems
            if (cose.size != 4) return Result(false, null, "malformed COSE_Sign1")
            val protectedBytes = (cose[0] as ByteString).bytes
            val payloadBytes = (cose[2] as ByteString).bytes
            val signature = (cose[3] as ByteString).bytes
            if (signature.size != 64) return Result(false, null, "signature not raw r||s")

            val payload = (CborDecoder.decode(payloadBytes)[0] as co.nstant.`in`.cbor.model.Map)
            val boundHash = (payload.get(UnsignedInteger(1L)) as ByteString).bytes
            val timestamp = (payload.get(UnsignedInteger(2L)) as Number).value.toLong()

            if (!boundHash.contentEquals(expectedHandshakeHash)) {
                return Result(false, null, "channel binding mismatch (wrong session)")
            }
            if (abs(System.currentTimeMillis() - timestamp) > MAX_SKEW_MS) {
                return Result(false, null, "stale assertion (replay window exceeded)")
            }

            // Sig_structure = ["Signature1", protected, external_aad(empty), payload].
            val sigStructure = ByteArrayOutputStream().also {
                CborEncoder(it).encode(
                    CborBuilder().addArray()
                        .add("Signature1")
                        .add(protectedBytes)
                        .add(ByteArray(0))
                        .add(payloadBytes)
                        .end()
                        .build()
                )
            }.toByteArray()

            val derSig = rawToDer(signature)
            val trustStore = ClientTrustStore(context)
            // Only non-expired enrollments may authorise a session; expired ones
            // are purged and the client must re-enroll.
            for (entry in trustStore.valid()) {
                val spki = Base64.decode(entry.publicKeyB64, Base64.NO_WRAP)
                val pub = try {
                    KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
                } catch (e: Exception) {
                    continue
                }
                val v = Signature.getInstance("SHA256withECDSA")
                v.initVerify(pub)
                v.update(sigStructure)
                if (v.verify(derSig)) {
                    return Result(true, entry.name, "verified")
                }
            }
            Result(false, null, "no enrolled client key matches the signature")
        } catch (e: Exception) {
            Log.e(TAG, "verification error", e)
            Result(false, null, "verification error: ${e.message}")
        }
    }

    /** Converts a 64-byte raw r||s ECDSA signature to a DER ECDSA-Sig-Value. */
    private fun rawToDer(raw: ByteArray): ByteArray {
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        val rEnc = derInteger(r)
        val sEnc = derInteger(s)
        val body = rEnc + sEnc
        return byteArrayOf(0x30) + derLength(body.size) + body
    }

    private fun derInteger(v: BigInteger): ByteArray {
        var bytes = v.toByteArray()  // already minimal two's-complement, sign-safe
        return byteArrayOf(0x02) + derLength(bytes.size) + bytes
    }

    private fun derLength(len: Int): ByteArray = if (len < 0x80) {
        byteArrayOf(len.toByte())
    } else {
        val enc = BigInteger.valueOf(len.toLong()).toByteArray().let {
            if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it
        }
        byteArrayOf((0x80 or enc.size).toByte()) + enc
    }
}
