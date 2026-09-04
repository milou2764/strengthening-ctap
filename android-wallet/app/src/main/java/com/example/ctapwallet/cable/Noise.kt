package com.example.ctapwallet.cable

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Minimal Noise protocol state machine as used by caBLE v2:
 * P-256 DH, AES-256-GCM, SHA-256. Supports the KNpsk0 / NKpsk0 / NK patterns.
 */
class Noise {
    enum class HandshakeType { NK_PSK0, KN_PSK0, NK }

    companion object {
        private const val HASH_LEN = 32
        private const val NKPSK0 = "Noise_NKpsk0_P256_AESGCM_SHA256"
        private const val KNPSK0 = "Noise_KNpsk0_P256_AESGCM_SHA256"
        private const val NK = "Noise_NK_P256_AESGCM_SHA256"

        private fun hkdf2(ck: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
            val out = hkdf(ikm, ck, null, 64)
            return Pair(out.copyOfRange(0, 32), out.copyOfRange(32, 64))
        }

        private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray?, length: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            val prk = mac.doFinal(ikm)
            val okm = ByteArray(length)
            var offset = 0
            var counter = 1
            while (offset < length) {
                mac.init(SecretKeySpec(prk, "HmacSHA256"))
                if (offset > 0) mac.update(okm, offset - 32, 32)
                info?.let { mac.update(it) }
                mac.update(counter.toByte())
                val t = mac.doFinal()
                val n = minOf(32, length - offset)
                System.arraycopy(t, 0, okm, offset, n)
                offset += n
                counter++
            }
            return okm
        }
    }

    private var chainingKey = ByteArray(HASH_LEN)
    private var h = ByteArray(HASH_LEN)
    private var symmetricKey = ByteArray(HASH_LEN)
    private var symmetricNonce = 0L

    fun init(type: HandshakeType) {
        val name = when (type) {
            HandshakeType.NK_PSK0 -> NKPSK0
            HandshakeType.KN_PSK0 -> KNPSK0
            HandshakeType.NK -> NK
        }
        val nameBytes = name.toByteArray()
        chainingKey.fill(0)
        System.arraycopy(nameBytes, 0, chainingKey, 0, minOf(nameBytes.size, HASH_LEN))
        h = chainingKey.copyOf()
    }

    fun mixHash(data: ByteArray) {
        val d = MessageDigest.getInstance("SHA-256")
        d.update(h)
        d.update(data)
        h = d.digest()
    }

    fun mixKey(ikm: ByteArray) {
        val (ck, tempKey) = hkdf2(chainingKey, ikm)
        chainingKey = ck
        initializeKey(tempKey)
    }

    fun mixKeyAndHash(ikm: ByteArray) {
        val out = hkdf(ikm, chainingKey, null, 96)
        chainingKey = out.copyOfRange(0, 32)
        mixHash(out.copyOfRange(32, 64))
        initializeKey(out.copyOfRange(64, 96))
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ciphertext = gcm(Cipher.ENCRYPT_MODE, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray? {
        val plaintext = gcm(Cipher.DECRYPT_MODE, ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    private fun gcm(mode: Int, input: ByteArray): ByteArray {
        val nonce = ByteArray(12)
        ByteBuffer.wrap(nonce).order(ByteOrder.BIG_ENDIAN).putInt(symmetricNonce.toInt())
        symmetricNonce++
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(symmetricKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(h)
        return cipher.doFinal(input)
    }

    fun handshakeHash(): ByteArray = h.copyOf()

    fun mixHashPoint(point: ECPoint) = mixHash(EcUtil.encodePointToX962(point))

    fun mixHashPoint(publicKey: ECPublicKey) = mixHashPoint(publicKey.w)

    fun trafficKeys(): Pair<ByteArray, ByteArray> = hkdf2(chainingKey, ByteArray(0))

    private fun initializeKey(key: ByteArray) {
        System.arraycopy(key, 0, symmetricKey, 0, minOf(key.size, symmetricKey.size))
        symmetricNonce = 0
    }
}
