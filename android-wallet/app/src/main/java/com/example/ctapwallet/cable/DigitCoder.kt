package com.example.ctapwallet.cable

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * FIDO CTAP 2.2 base-10 "digit encoding" used inside the caBLE `FIDO:/...` QR.
 * The URL after the `FIDO:/` prefix is a string of decimal digits that decode
 * to the CBOR blob carrying the QR public key, secret, and flow. Only decoding
 * is needed on the authenticator side.
 *
 * Mirrored (not copied) from the reference caBLE implementation.
 */
object DigitCoder {
    private const val CHUNK_SIZE = 7
    private const val CHUNK_DIGITS = 17

    fun digitDecode(digitString: String): ByteArray? {
        val result = mutableListOf<Byte>()
        var remaining = digitString

        while (remaining.length >= CHUNK_DIGITS) {
            val chunkStr = remaining.substring(0, CHUNK_DIGITS)
            val value = try {
                chunkStr.toULong()
            } catch (e: NumberFormatException) {
                return null
            }
            val buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putLong(value.toLong())
            result.addAll(buffer.array().take(CHUNK_SIZE))
            remaining = remaining.substring(CHUNK_DIGITS)
        }

        if (remaining.isNotEmpty()) {
            val originalLength = originalLengthFromDigits(remaining.length)
            if (originalLength <= 0) return null
            val value = try {
                remaining.toULong()
            } catch (e: NumberFormatException) {
                return null
            }
            val buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            buffer.putLong(value.toLong())
            result.addAll(buffer.array().take(originalLength))
        }
        return result.toByteArray()
    }

    private fun originalLengthFromDigits(digitsCount: Int): Int = when (digitsCount) {
        15 -> 6
        13 -> 5
        10 -> 4
        8 -> 3
        5 -> 2
        3 -> 1
        0 -> 0
        else -> -1
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
