package org.kelopatra.protocol

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Rigid, length-prefixed binary wire format helpers.
 *
 * SECURITY: every read is capped. Anything malformed throws immediately.
 * No text formats, no interpretation, no extensibility beyond the version byte.
 */
object Wire {
    /** Hard cap for any single field (largest legit field is an ML-DSA-87 sig ~4.6 KB). */
    const val MAX_FIELD = 16 * 1024
    /** Hard cap for a whole message body (plaintext limit). */
    const val MAX_MESSAGE = 64 * 1024

    class Writer {
        private val buf = ByteArrayOutputStream()
        private val out = DataOutputStream(buf)
        fun byte(v: Int) = apply { out.writeByte(v) }
        fun bytes(v: ByteArray) = apply {
            require(v.size <= MAX_FIELD + MAX_MESSAGE) { "field too large" }
            out.writeInt(v.size); out.write(v)
        }
        fun raw(v: ByteArray) = apply { out.write(v) }
        fun done(): ByteArray = buf.toByteArray()
    }

    class Reader(data: ByteArray) {
        private val inp = DataInputStream(ByteArrayInputStream(data))
        fun byte(): Int = inp.readUnsignedByte()
        fun bytes(cap: Int = MAX_FIELD): ByteArray {
            val len = inp.readInt()
            if (len < 0 || len > cap) throw MalformedException("field length $len exceeds cap $cap")
            val b = ByteArray(len)
            inp.readFully(b)
            return b
        }
        fun raw(n: Int): ByteArray {
            require(n in 0..MAX_FIELD)
            val b = ByteArray(n)
            inp.readFully(b)
            return b
        }
        fun atEnd(): Boolean = inp.available() == 0
        fun requireEnd() { if (!atEnd()) throw MalformedException("trailing garbage") }
    }

    class MalformedException(msg: String) : Exception(msg)
}
