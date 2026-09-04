package com.example.ctapwallet.cable

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/** caBLE HKDF key-derivation purposes (the info's first byte). */
enum class KeyPurpose(val value: Int) {
    EID_KEY(1),
    TUNNEL_ID(2),
    PSK(3),
}

object KeyDerivation {
    /**
     * caBLE HKDF-SHA256: `info` is a 4-byte little-endian-ish tag whose first
     * byte is the purpose. Fills [output] with the derived key material.
     */
    fun derive(output: ByteArray, secret: ByteArray, salt: ByteArray?, purpose: KeyPurpose) {
        require(purpose.value < 0x100) { "unsupported purpose" }
        val info = ByteArray(4)
        info[0] = purpose.value.toByte()

        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(secret, salt, info))
        val generated = hkdf.generateBytes(output, 0, output.size)
        if (generated != output.size) throw IllegalStateException("HKDF error")
    }
}
