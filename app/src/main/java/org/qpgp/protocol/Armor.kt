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
        // Strip invisible characters some clipboards/IMEs inject (zero-width
        // spaces, BOM, directional marks) — they corrupt marker matching.
        val t = text.filter { it.code !in INVISIBLES }.trim()
        val s = t.indexOf(begin)
        val e = t.indexOf(end)
        if (s < 0 && t.contains("-----BEGIN QPGP"))
            throw Wire.MalformedException("this is a QPGP block, but not a $type block — check what you pasted")
        if (s < 0) throw Wire.MalformedException("no 'BEGIN QPGP $type' marker found — did the paste come through empty?")
        if (e < 0) throw Wire.MalformedException(
            "the END marker is missing: the paste was TRUNCATED (got ${t.length - s} chars). " +
            "Emulator/clipboard often cuts long text — try sharing via a file or app instead.")
        if (e <= s) throw Wire.MalformedException("markers out of order — paste is garbled")
        val lines = t.substring(s + begin.length, e).trim().lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) throw Wire.MalformedException("empty armor")
        val checkLine = lines.lastOrNull { it.startsWith("=") } ?: throw Wire.MalformedException("missing checksum line")
        val dataLines = lines.filter { !it.startsWith("=") }
        val data = try {
            Base64.getDecoder().decode(dataLines.joinToString(""))
        } catch (ex: IllegalArgumentException) {
            throw Wire.MalformedException("invalid base64 — characters were altered in transit")
        }
        val expect = Base64.getEncoder().encodeToString(Hybrid.sha512(data).copyOf(6))
        if ("=$expect" != checkLine)
            throw Wire.MalformedException("checksum mismatch — content was corrupted or partially truncated in transit")
        return data
    }

    /** Invisible/zero-width code points commonly injected by clipboards and IMEs. */
    private val INVISIBLES = setOf(0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x2060, 0x00AD)
}
