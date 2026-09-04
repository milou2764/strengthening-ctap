package com.example.ctapwallet.cable

import android.Manifest
import android.content.Context
import android.util.Log
import androidx.annotation.RequiresPermission
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Authenticator side of the CTAP hybrid (caBLE v2) transport, driven from a
 * scanned QR. Connects to the tunnel server, runs the Noise handshake, then
 * serves getInfo / makeCredential / getAssertion.
 *
 * The CTAP client-authentication countermeasure hooks in right after the
 * handshake: the desktop client sends a COSE_Sign1 (message type `kUpdate`)
 * bound to this session's handshake hash. When [requireClientAuth] is set, the
 * session is aborted unless that assertion verifies against an enrolled key.
 */
class CableTunnel(
    private val appContext: Context,
    private val requireClientAuth: Boolean,
    private val onStatus: (String) -> Unit,
) : WebSocketListener() {

    companion object {
        private const val TAG = "CableTunnel"
        private const val MSG_SHUTDOWN = 0
        private const val MSG_CTAP = 1
        private const val MSG_UPDATE = 2   // carries the client-authentication assertion
        private const val MSG_JSON = 3     // DC API request / response (JSON)
        private const val CTAP_MAKE_CREDENTIAL = 0x01.toByte()
        private const val CTAP_GET_ASSERTION = 0x02.toByte()

        private val AAGUID = byteArrayOf(
            0x26, 0x72, 0x24, 0xB5.toByte(), 0x35, 0x1A, 0x51, 0x58,
            0x12, 0x82.toByte(), 0x50, 0xE4.toByte(), 0x3D, 0x7D, 0x5F, 0xA0.toByte()
        )
    }

    var qrSecret: ByteArray? = null
    var compressedPublicKey: ByteArray? = null

    private var advertPlainText: ByteArray? = null
    private var crypter: Crypter? = null
    private var handshakeHash: ByteArray? = null
    private var clientAuthVerified = false
    private var handshakeDoneNs = 0L   // measurement
    private var state = "handshake"

    private val passkeyStore = PasskeyStore(appContext)

    /** Derives the tunnel URL from the QR secret and opens the WebSocket. */
    @OptIn(ExperimentalStdlibApi::class)
    fun connect() {
        val secret = qrSecret ?: throw IllegalStateException("qrSecret not set")
        val tunnelId = ByteArray(16)
        KeyDerivation.derive(tunnelId, secret, null, KeyPurpose.TUNNEL_ID)
        val url = "wss://cable.ua5v.com/cable/new/" + tunnelId.toHex()
        Log.d(TAG, "tunnel URL: $url")
        val request = Request.Builder()
            .addHeader("Sec-WebSocket-Protocol", "fido.cable")
            .url(url)
            .build()
        val client = OkHttpClient.Builder()
            .connectionPool(ConnectionPool(0, 1, java.util.concurrent.TimeUnit.SECONDS))
            .build()
        client.newWebSocket(request, this)
    }

    @OptIn(ExperimentalStdlibApi::class)
    @RequiresPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    override fun onOpen(webSocket: WebSocket, response: Response) {
        onStatus("Tunnel open. Broadcasting BLE advert…")
        val secret = qrSecret ?: throw IllegalStateException("qrSecret not set")
        val eid = ByteArray(64)
        KeyDerivation.derive(eid, secret, null, KeyPurpose.EID_KEY)

        val routingIdStr = response.headers["X-Cable-Routing-Id"]
            ?: throw IllegalStateException("no routing id from tunnel")
        val routingId = routingIdStr.hexToByteArray()

        // The per-session advertisement nonce carries the whole of replay
        // resistance: an assertion is bound to it, so it must be fresh and
        // unpredictable. A CSPRNG, never java.util.Random.
        val nonce = ByteArray(10)
        SecureRandom().nextBytes(nonce)
        val plain = ByteArray(16)
        plain[0] = 0x00
        for (i in 1..10) plain[i] = nonce[i - 1]
        plain[11] = routingId[0]
        plain[12] = routingId[1]
        plain[13] = routingId[2]
        plain[14] = 0x00
        plain[15] = 0x00

        val cipher = Cipher.getInstance("AES")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(eid.copyOfRange(0, 32), "AES"))
        val aesEncrypted = cipher.doFinal(plain)

        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(eid.copyOfRange(32, 64), "HmacSHA256"))
        hmac.update(aesEncrypted, 0, 16)
        val tag = hmac.doFinal()

        val serviceData = ByteArray(20)
        System.arraycopy(aesEncrypted, 0, serviceData, 0, 16)
        System.arraycopy(tag, 0, serviceData, 16, 4)

        this.advertPlainText = plain
        CableAdvertiser.start(serviceData)
        onStatus("Advert broadcast. Waiting for the client to connect…")
    }

    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
        try {
            handleMessage(webSocket, bytes.toByteArray())
        } catch (e: Exception) {
            Log.e(TAG, "message handling failed", e)
            onStatus("Session error: ${e.message}")
            webSocket.close(1000, null)
        }
    }

    private fun handleMessage(webSocket: WebSocket, raw: ByteArray) {
        val secret = qrSecret ?: throw IllegalStateException("qrSecret not set")
        val compressed = compressedPublicKey ?: throw IllegalStateException("no QR public key")

        if (state == "handshake") {
            val psk = ByteArray(32)
            KeyDerivation.derive(psk, secret, advertPlainText, KeyPurpose.PSK)
            val peerIdentity = EcUtil.decompressP256PublicKey(compressed)
            val (response, result) = HandshakeHandler.respondToHandshake(psk, peerIdentity, raw)
            if (result == null) {
                onStatus("Handshake failed.")
                webSocket.close(1000, null)
                return
            }
            crypter = result.crypter
            handshakeHash = result.handshakeHash
            handshakeDoneNs = System.nanoTime()
            webSocket.send(response.toByteString())
            onStatus("Handshake complete. Sending capabilities…")
            sendPostHandshake(webSocket, result.crypter)
            state = "ready"
            return
        }

        val c = crypter ?: return
        val message = c.decrypt(raw)
        if (message.isEmpty()) return
        when (message[0].toInt()) {
            MSG_SHUTDOWN -> {
                onStatus("Session closed by client.")
                webSocket.close(1000, null)
            }
            MSG_UPDATE -> handleClientAuth(webSocket, message.copyOfRange(1, message.size))
            MSG_CTAP -> handleCtap(webSocket, c, message)
            MSG_JSON -> handleJson(webSocket, c, message.copyOfRange(1, message.size))
            else -> Log.d(TAG, "unknown message type ${message[0]}")
        }
    }

    /** The CTAP client-authentication assertion (the countermeasure). */
    private fun handleClientAuth(webSocket: WebSocket, cose: ByteArray) {
        val hash = handshakeHash ?: return
        val t0 = System.nanoTime()
        val result = ClientAuthVerifier.verify(appContext, cose, hash)
        val t1 = System.nanoTime()
        // MEASURE client-auth on the authenticator: verification cost and the
        // delay between our handshake completion and the assertion being verified.
        Log.i(TAG, "MEASURE client-auth verify_us=${(t1 - t0) / 1000} cose_bytes=${cose.size} " +
            "since_handshake_us=${(t1 - handshakeDoneNs) / 1000} ok=${result.ok}")
        if (result.ok) {
            clientAuthVerified = true
            onStatus("Client authenticated: \"${result.clientName}\".")
        } else {
            onStatus("REJECTED — unauthorized client: ${result.reason}")
            if (requireClientAuth) {
                webSocket.close(1000, "client authentication failed")
            }
        }
    }

    private fun handleCtap(webSocket: WebSocket, c: Crypter, message: ByteArray) {
        if (requireClientAuth && !clientAuthVerified) {
            onStatus("REJECTED — no client authentication presented; aborting session.")
            webSocket.close(1000, "client authentication required")
            return
        }
        val ctapCode = message[1]
        val command = message.copyOfRange(2, message.size)
        when (ctapCode) {
            CTAP_MAKE_CREDENTIAL -> makeCredential(webSocket, c, command)
            CTAP_GET_ASSERTION -> getAssertion(webSocket, c, command)
            else -> {
                // authenticatorSelection and friends: acknowledge success.
                c.encrypt(byteArrayOf(1, 0))?.let { webSocket.send(it.toByteString()) }
            }
        }
    }

    /**
     * A Digital Credentials API request (message type 3). The client sends
     * `{"origin":..., "requestType":"credential.get", "request":{"digital":{...}}}`
     * and expects `{"response":{"digital":{"data":{"protocol":..., "data":...}}}}`.
     *
     * The countermeasure gates this exactly as it gates CTAP: a session whose
     * client has not authenticated is aborted before any request is served.
     * The presentation itself is a minimal OpenID4VP-shaped response; what this
     * prototype demonstrates is that the digital-credential flow rides the same
     * authenticated session, not the credential format.
     */
    private fun handleJson(webSocket: WebSocket, c: Crypter, json: ByteArray) {
        if (requireClientAuth && !clientAuthVerified) {
            onStatus("REJECTED — no client authentication presented; aborting session.")
            webSocket.close(1000, "client authentication required")
            return
        }
        val origin: String
        val protocol: String
        try {
            val req = org.json.JSONObject(String(json, Charsets.UTF_8))
            origin = req.optString("origin", "?")
            protocol = req.getJSONObject("request").getJSONObject("digital")
                .getJSONArray("requests").getJSONObject(0).getString("protocol")
        } catch (e: Exception) {
            Log.w(TAG, "malformed DC API request", e)
            c.encrypt(byteArrayOf(MSG_JSON.toByte()) +
                "{\"response\":{\"digital\":{\"error\":\"invalid_request\"}}}".toByteArray())
                ?.let { webSocket.send(it.toByteString()) }
            return
        }
        onStatus("DC API request from $origin ($protocol); presenting credential.")
        val presentation = org.json.JSONObject()
            .put("vp_token", org.json.JSONObject()
                .put("ctap_wallet_demo", "eyJhbGciOiJFUzI1NiJ9.demo-presentation"))
        val data = org.json.JSONObject().put("protocol", protocol).put("data", presentation)
        val reply = org.json.JSONObject()
            .put("response", org.json.JSONObject()
                .put("digital", org.json.JSONObject().put("data", data)))
        c.encrypt(byteArrayOf(MSG_JSON.toByte()) + reply.toString().toByteArray())
            ?.let { webSocket.send(it.toByteString()) }
    }

    /** caBLE post-handshake message: getInfo response + supported operations. */
    private fun sendPostHandshake(webSocket: WebSocket, c: Crypter) {
        val getInfo = ByteArrayOutputStream().also {
            CborEncoder(it).encode(
                CborBuilder().addMap()
                    .putArray(1).add("FIDO_2_1").add("FIDO_2_0").add("ctap").end()
                    .put(3, AAGUID)
                    .end().build()
            )
        }.toByteArray()
        // Key 5 carries this authenticator's stable identifier. The client keeps
        // a distinct identity key per authenticator, so it needs to know which
        // one it is talking to before it can sign. It travels here, inside the
        // encrypted tunnel, and never in the QR code or the BLE advertisement.
        val message = ByteArrayOutputStream().also {
            CborEncoder(it).encode(
                CborBuilder().addMap()
                    .put(1, getInfo)
                    .putArray(3).add("dc").add("ctap").end()
                    .put(5, com.example.ctapwallet.AuthenticatorIdentity.get(appContext))
                    .end().build()
            )
        }.toByteArray()
        c.encrypt(message)?.let { webSocket.send(it.toByteString()) }
    }

    private fun makeCredential(webSocket: WebSocket, c: Crypter, command: ByteArray) {
        onStatus("Creating a passkey…")
        val fields = (CborDecoder.decode(command)[0] as co.nstant.`in`.cbor.model.Map).values.toTypedArray()
        val clientDataHash = (fields[0] as co.nstant.`in`.cbor.model.ByteString).bytes
        val rp = (fields[1] as co.nstant.`in`.cbor.model.Map).values.toTypedArray()
        val user = (fields[2] as co.nstant.`in`.cbor.model.Map).values.toTypedArray()
        val pubKeyCredParams = (fields[3] as co.nstant.`in`.cbor.model.Array).dataItems

        val supportsEs256 = pubKeyCredParams.any { param ->
            val alg = (param as co.nstant.`in`.cbor.model.Map).values.toTypedArray()[0]
                    as co.nstant.`in`.cbor.model.Number
            alg.value.toInt() == -7
        }
        if (!supportsEs256) throw IllegalStateException("CTAP2_ERR_UNSUPPORTED_ALGORITHM")

        val rpId = (rp[0] as co.nstant.`in`.cbor.model.UnicodeString).string
        val userHandle = (user[0] as co.nstant.`in`.cbor.model.ByteString).bytes
        val displayName = user.getOrNull(1)?.let {
            (it as? co.nstant.`in`.cbor.model.UnicodeString)?.string
        } ?: rpId

        val credentialId = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        passkeyStore.save(Passkey(rpId, credentialId, userHandle, displayName, keyPair))

        val pub = keyPair.public as ECPublicKey
        val x32 = coord(pub.w.affineX.toByteArray())
        val y32 = coord(pub.w.affineY.toByteArray())
        val coseKey = ByteArrayOutputStream().also {
            CborEncoder(it).encode(
                CborBuilder().addMap()
                    .put(1, 2).put(3, -7).put(-1, 1).put(-2, x32).put(-3, y32)
                    .end().build()
            )
        }.toByteArray()

        val attestedCredentialData =
            byteArrayOf(*AAGUID, 0, credentialId.size.toByte(), *credentialId, *coseKey)
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = byteArrayOf(*rpIdHash, 69, 0, 0, 0, 0, *attestedCredentialData)

        val toBeSigned = byteArrayOf(*authData, *clientDataHash)
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private); update(toBeSigned); sign()
        }
        val attestationObject = ByteArrayOutputStream().also {
            CborEncoder(it).encode(
                CborBuilder().addMap()
                    .put(1, "packed")
                    .put(2, authData)
                    .putMap(3).put("alg", -7L).put("sig", sig).end()
                    .end().build()
            )
        }.toByteArray()

        c.encrypt(byteArrayOf(1, 0, *attestationObject))?.let { webSocket.send(it.toByteString()) }
        onStatus("Passkey created for $rpId.")
    }

    private fun getAssertion(webSocket: WebSocket, c: Crypter, command: ByteArray) {
        onStatus("Signing an assertion…")
        val fields = (CborDecoder.decode(command)[0] as co.nstant.`in`.cbor.model.Map).values.toTypedArray()
        val rpId = (fields[0] as co.nstant.`in`.cbor.model.UnicodeString).string
        val clientDataHash = (fields[1] as co.nstant.`in`.cbor.model.ByteString).bytes

        val allowedIds = mutableListOf<ByteArray>()
        if (fields.size >= 3) {
            val list = (fields[2] as co.nstant.`in`.cbor.model.Array).dataItems
            for (descriptor in list) {
                val id = (descriptor as co.nstant.`in`.cbor.model.Map)
                    .get(CborBuilder().add("id").build()[0]) as co.nstant.`in`.cbor.model.ByteString
                allowedIds.add(id.bytes)
            }
        }

        val match = passkeyStore.find(rpId, allowedIds).firstOrNull()
            ?: throw IllegalStateException("no passkey for $rpId")

        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val authData = byteArrayOf(*rpIdHash, 0x05, 0, 0, 0, 0)
        val toBeSigned = byteArrayOf(*authData, *clientDataHash)
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(match.keyPair.private); update(toBeSigned); sign()
        }
        val assertion = ByteArrayOutputStream().also {
            CborEncoder(it).encode(
                CborBuilder().addMap()
                    .putMap(1).put("type", "public-key").put("id", match.credentialId).end()
                    .put(2, authData)
                    .put(3, sig)
                    .end().build()
            )
        }.toByteArray()

        c.encrypt(byteArrayOf(1, 0, *assertion))?.let { webSocket.send(it.toByteString()) }
        onStatus("Signed in to $rpId as \"${match.displayName}\".")
    }

    /** Normalises a BigInteger.toByteArray() coordinate to 32 bytes. */
    private fun coord(bytes: ByteArray): ByteArray = when {
        bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
        bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
        else -> bytes
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        Log.e(TAG, "tunnel error", t)
        onStatus("Tunnel error: ${t.message}")
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        Log.d(TAG, "tunnel closed: $code / $reason")
    }
}
