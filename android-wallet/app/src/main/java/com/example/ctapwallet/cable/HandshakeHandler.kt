package com.example.ctapwallet.cable

import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

/** Result of a completed caBLE Noise handshake. */
data class HandshakeResult(val crypter: Crypter, val handshakeHash: ByteArray)

/**
 * Authenticator (responder) side of the caBLE QR handshake: `Noise_KNpsk0`,
 * where the initiator's static key comes from the QR (`peerIdentity`) and the
 * pre-shared key is derived from the QR secret. Processes the initiator's
 * message and returns the response bytes plus the transport keys / handshake
 * hash. Returns a null result on any failure.
 */
object HandshakeHandler {
    private const val P256_X962_LEN = 65

    fun respondToHandshake(
        psk: ByteArray,
        peerIdentity: ByteArray,
        input: ByteArray,
    ): Pair<ByteArray, HandshakeResult?> {
        if (input.size < P256_X962_LEN) return Pair(ByteArray(0), null)

        val peerPointBytes = input.copyOfRange(0, P256_X962_LEN)
        val ciphertext = input.copyOfRange(P256_X962_LEN, input.size)

        val noise = Noise()
        noise.init(Noise.HandshakeType.KN_PSK0)
        noise.mixHash(byteArrayOf(1))              // prologue for the KN pattern
        noise.mixHash(peerIdentity)                // initiator static (from QR)
        noise.mixKeyAndHash(psk)

        noise.mixHash(peerPointBytes)
        noise.mixKey(peerPointBytes)

        val peerPoint = EcUtil.decodeX962Point(peerPointBytes) ?: return Pair(ByteArray(0), null)
        val peerPublicKey = EcUtil.createPublicKey(peerPoint) ?: return Pair(ByteArray(0), null)

        val ephemeral = EcUtil.generateKeyPair()
        val ephemeralPriv = ephemeral.private as ECPrivateKey
        val ephemeralPub = ephemeral.public as ECPublicKey

        val plaintext = noise.decryptAndHash(ciphertext)
        if (plaintext == null || plaintext.isNotEmpty()) return Pair(ByteArray(0), null)

        val ephemeralPubBytes = EcUtil.encodePublicKeyToX962(ephemeralPub)
        noise.mixHash(ephemeralPubBytes)
        noise.mixKey(ephemeralPubBytes)

        val ee = EcUtil.computeSharedKey(ephemeralPriv, peerPublicKey)
            ?: return Pair(ByteArray(0), null)
        noise.mixKey(ee)

        // SE: the KN pattern's `se` token — DH(our ephemeral, the initiator's
        // static key carried in the QR). Omitting this diverges the transcript
        // and the desktop rejects the response ("caBLEv2 handshake failed").
        val peerIdentityPoint = EcUtil.decodeX962Point(peerIdentity)
            ?: return Pair(ByteArray(0), null)
        val peerIdentityPub = EcUtil.createPublicKey(peerIdentityPoint)
            ?: return Pair(ByteArray(0), null)
        val se = EcUtil.computeSharedKey(ephemeralPriv, peerIdentityPub)
            ?: return Pair(ByteArray(0), null)
        noise.mixKey(se)

        val myCiphertext = noise.encryptAndHash(ByteArray(0))
        val response = ephemeralPubBytes + myCiphertext

        val (readKey, writeKey) = noise.trafficKeys()
        return Pair(response, HandshakeResult(Crypter(readKey, writeKey), noise.handshakeHash()))
    }
}
