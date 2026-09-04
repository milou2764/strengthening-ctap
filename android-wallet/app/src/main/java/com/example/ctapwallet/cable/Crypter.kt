package com.example.ctapwallet.cable

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * caBLE post-handshake transport cipher: AES-256-GCM with per-direction 48-bit
 * big-endian sequence-number nonces (bytes 4..11), empty AAD, and CTAP2 padding
 * to a 32-byte granularity (last plaintext byte = number of zero pad bytes).
 */
class Crypter(private val readKey: ByteArray, private val writeKey: ByteArray) {
    private var readSeq = 0L
    private var writeSeq = 0L

    companion object {
        private const val PADDING_GRANULARITY = 32
    }

    fun encrypt(message: ByteArray): ByteArray? {
        val padded = applyPadding(message)
        val nonce = constructNonce(writeSeq++) ?: return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(writeKey, "AES"), GCMParameterSpec(128, nonce))
            cipher.doFinal(padded)
        } catch (e: Exception) {
            null
        }
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        val nonce = constructNonce(readSeq) ?: throw IllegalStateException("nonce overflow")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(readKey, "AES"), GCMParameterSpec(128, nonce))
        val plaintext = cipher.doFinal(ciphertext)
        readSeq++
        return removePadding(plaintext)
    }

    private fun applyPadding(message: ByteArray): ByteArray {
        val withLen = message.size + 1
        val paddedSize = ((withLen + PADDING_GRANULARITY - 1) / PADDING_GRANULARITY) * PADDING_GRANULARITY
        val numZeros = paddedSize - message.size - 1
        require(numZeros < 256) { "padding too large" }
        val out = ByteArray(paddedSize)
        System.arraycopy(message, 0, out, 0, message.size)
        out[out.size - 1] = numZeros.toByte()
        return out
    }

    private fun removePadding(plaintext: ByteArray): ByteArray {
        if (plaintext.isEmpty()) throw IllegalStateException("empty plaintext")
        val padLen = plaintext[plaintext.size - 1].toInt() and 0xFF
        if (padLen + 1 > plaintext.size) throw IllegalStateException("bad padding")
        return plaintext.copyOfRange(0, plaintext.size - padLen - 1)
    }

    private fun constructNonce(seq: Long): ByteArray? {
        if (seq < 0 || seq >= (1L shl 48)) return null
        val nonce = ByteArray(12)
        ByteBuffer.wrap(nonce, 4, 8).order(ByteOrder.BIG_ENDIAN).putLong(seq)
        return nonce
    }
}
