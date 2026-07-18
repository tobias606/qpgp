package org.qpgp.protocol

import org.qpgp.crypto.Hybrid
import java.util.Base64

/**
 * ASCII armor so ciphertext and key bundles can travel over any channel
 * (paste into any messenger, print, QR later). Base64 + explicit type label
 * + truncated SHA-512 checksum line. Strict parsing: reject anything irregular.
 */
object Armor {

    const val TYPE_MESSAGE = "MESSAGE"
    const val TYPE_IDENTITY = "IDENTITY"

    fun encode(type: String, data: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(data)
        val body = b64.chunked(64).joinToString("\n")
        val check = Base64.getEncoder().encodeToString(Hybrid.sha512(data).copyOf(6))
        return "-----BEGIN QPGP $type-----\n$body\n=$check\n-----END QPGP $type-----"
    }

    fun decode(type: String, text: String): ByteArray {
        val begin = "-----BEGIN QPGP $type-----"
        val end = "-----END QPGP $type-----"
        val t = text.trim()
        val s = t.indexOf(begin)
        val e = t.indexOf(end)
        if (s < 0 || e < 0 || e <= s) throw Wire.MalformedException("not a QPGP $type block")
        val lines = t.substring(s + begin.length, e).trim().lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) throw Wire.MalformedException("empty armor")
        val checkLine = lines.lastOrNull { it.startsWith("=") } ?: throw Wire.MalformedException("missing checksum")
        val dataLines = lines.filter { !it.startsWith("=") }
        val data = try {
            Base64.getDecoder().decode(dataLines.joinToString(""))
        } catch (ex: IllegalArgumentException) {
            throw Wire.MalformedException("invalid base64")
        }
        val expect = Base64.getEncoder().encodeToString(Hybrid.sha512(data).copyOf(6))
        if ("=$expect" != checkLine) throw Wire.MalformedException("checksum mismatch — corrupted in transit")
        return data
    }
}
