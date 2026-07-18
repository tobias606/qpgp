package org.qpgp.protocol

/**
 * Multi-frame QR transport for armored blocks.
 *
 * An identity block (~5.7 KB armored) exceeds what a phone camera reliably
 * scans in one QR (~1 KB practical), so blocks are split into frames the
 * sender's screen cycles through and the receiver collects in any order.
 *
 * Frame format (plain text inside each QR):
 *   QPGP1|<type>|<setId>|<index>|<total>|<chunk>
 *
 *   setId  = 8 hex chars of SHA-512(payload) — frames from different
 *            payloads can never be mixed into one assembly.
 *   index  = 1-based.
 *
 * SECURITY: frames are TRANSPORT only. The assembled text goes through the
 * exact same strict Armor/Wire parsing as a manual paste. A malicious QR can
 * therefore do nothing a malicious paste couldn't.
 */
object Qr {
    const val VERSION_TAG = "QPGP1"
    const val TYPE_IDENTITY = "I"
    /** chars per frame — comfortable scan density on phone screens */
    const val CHUNK = 700
    private const val MAX_FRAMES = 64

    fun split(type: String, text: String): List<String> {
        require(text.isNotEmpty() && text.length <= CHUNK * MAX_FRAMES) { "payload size" }
        val setId = setIdOf(text)
        val chunks = text.chunked(CHUNK)
        return chunks.mapIndexed { i, c -> "$VERSION_TAG|$type|$setId|${i + 1}|${chunks.size}|$c" }
    }

    private fun setIdOf(text: String): String =
        org.qpgp.crypto.Hybrid.sha512(text.toByteArray(Charsets.UTF_8))
            .copyOf(4).joinToString("") { "%02x".format(it) }

    /** Collects frames in any order; ignores garbage; resets if a new set appears. */
    class Assembler(private val expectType: String) {
        private var setId: String? = null
        private var total = -1
        private val parts = HashMap<Int, String>()

        val received: Int get() = parts.size
        val expected: Int get() = if (total > 0) total else 0

        /** Feed one scanned string. Returns the assembled payload when complete, else null. */
        fun collect(frame: String): String? {
            val p = frame.split('|', limit = 6)
            if (p.size != 6 || p[0] != VERSION_TAG || p[1] != expectType) return null
            val id = p[2]
            val idx = p[3].toIntOrNull() ?: return null
            val tot = p[4].toIntOrNull() ?: return null
            if (tot !in 1..MAX_FRAMES || idx !in 1..tot) return null
            if (id.length != 8 || id.any { it !in "0123456789abcdef" }) return null

            if (setId != id) {          // new payload — start over
                setId = id; total = tot; parts.clear()
            }
            if (tot != total) return null
            parts[idx] = p[5]
            if (parts.size < total) return null

            val whole = (1..total).joinToString("") { parts[it]!! }
            // integrity: the setId must match the assembled text
            return if (setIdOf(whole) == id) whole else run { parts.clear(); setId = null; null }
        }
    }
}
