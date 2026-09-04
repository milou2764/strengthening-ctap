package com.example.ctapwallet.cable

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import javax.crypto.KeyAgreement

/** P-256 helpers for the caBLE Noise handshake (ECDH, X9.62 point coding). */
object EcUtil {

    fun generateKeyPair(): KeyPair {
        val g = KeyPairGenerator.getInstance("EC")
        g.initialize(ECGenParameterSpec("secp256r1"))
        return g.generateKeyPair()
    }

    /** ECDH producing the 32-byte big-endian x-coordinate. */
    fun computeSharedKey(privateKey: ECPrivateKey, publicKey: ECPublicKey): ByteArray? = try {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(publicKey, true)
        val s = ka.generateSecret()
        when {
            s.size == 32 -> s
            s.size > 32 -> s.copyOfRange(s.size - 32, s.size)
            else -> ByteArray(32).also { System.arraycopy(s, 0, it, 32 - s.size, s.size) }
        }
    } catch (e: Exception) {
        null
    }

    fun decodeX962Point(bytes: ByteArray): ECPoint? {
        if (bytes.size != 65 || bytes[0] != 0x04.toByte()) return null
        return try {
            ECPoint(BigInteger(1, bytes.copyOfRange(1, 33)), BigInteger(1, bytes.copyOfRange(33, 65)))
        } catch (e: Exception) {
            null
        }
    }

    fun createPublicKey(point: ECPoint): ECPublicKey? = try {
        KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(point, p256Spec())) as ECPublicKey
    } catch (e: Exception) {
        null
    }

    fun encodePublicKeyToX962(publicKey: ECPublicKey): ByteArray = encodePointToX962(publicKey.w)

    fun encodePointToX962(point: ECPoint): ByteArray {
        val x = point.affineX.toByteArray()
        val y = point.affineY.toByteArray()
        val xb = if (x.size > 32) x.copyOfRange(x.size - 32, x.size) else x
        val yb = if (y.size > 32) y.copyOfRange(y.size - 32, y.size) else y
        val out = ByteArray(65)
        out[0] = 0x04
        System.arraycopy(xb, 0, out, 1 + (32 - xb.size), xb.size)
        System.arraycopy(yb, 0, out, 33 + (32 - yb.size), yb.size)
        return out
    }

    /** Decompresses a 33-byte compressed P-256 point to 65-byte X9.62. */
    fun decompressP256PublicKey(compressed: ByteArray): ByteArray {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val params = ECNamedCurveTable.getParameterSpec("secp256r1")
        return params.curve.decodePoint(compressed).getEncoded(false)
    }

    private fun p256Spec(): ECParameterSpec {
        val p = BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")
        val a = BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948")
        val b = BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291")
        val gx = BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286")
        val gy = BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109")
        val n = BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369")
        val curve = EllipticCurve(ECFieldFp(p), a, b)
        return ECParameterSpec(curve, ECPoint(gx, gy), n, 1)
    }
}
