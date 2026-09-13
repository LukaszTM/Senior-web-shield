package pl.seniorshield.app.dns

/** The question section of a DNS query. */
class DnsQuestion(
    val name: String,
    val qtype: Int,
    /** Offset right past the first question (header + QNAME + QTYPE + QCLASS). */
    val questionEnd: Int,
)

object Dns {

    /**
     * Parses the first question of a DNS query message.
     * Returns null for responses, empty questions and malformed packets.
     */
    fun parseQuestion(msg: ByteArray): DnsQuestion? {
        if (msg.size < 17) return null
        val flags = u16(msg, 2)
        if (flags and 0x8000 != 0) return null // QR=1: a response, not a query
        if (u16(msg, 4) < 1) return null       // QDCOUNT
        val sb = StringBuilder()
        var i = 12
        while (true) {
            if (i >= msg.size) return null
            val labelLen = msg[i].toInt() and 0xFF
            if (labelLen == 0) {
                i++
                break
            }
            if (labelLen and 0xC0 != 0) return null // compression in a question: malformed
            if (i + 1 + labelLen > msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (j in 1..labelLen) {
                val c = msg[i + j].toInt() and 0xFF
                sb.append(if (c in 'A'.code..'Z'.code) (c + 32).toChar() else c.toChar())
            }
            i += 1 + labelLen
            if (sb.length > 255) return null
        }
        if (i + 4 > msg.size) return null
        return DnsQuestion(sb.toString(), u16(msg, i), i + 4)
    }

    /**
     * Builds an NXDOMAIN response for a blocked query: the original header and
     * question are kept, QR/RA are set and RCODE=3 (no such domain). Apps treat
     * this as "host does not exist", so ad SDKs fail fast and quietly.
     */
    fun buildNxDomain(query: ByteArray, question: DnsQuestion): ByteArray {
        val r = query.copyOf(question.questionEnd)
        // byte 2: QR=1, keep opcode (bits 6-3) and RD (bit 0), clear AA/TC
        r[2] = (0x80 or (query[2].toInt() and 0x79)).toByte()
        // byte 3: RA=1, RCODE=3
        r[3] = 0x83.toByte()
        r[4] = 0; r[5] = 1  // QDCOUNT = 1
        r[6] = 0; r[7] = 0  // ANCOUNT = 0
        r[8] = 0; r[9] = 0  // NSCOUNT = 0
        r[10] = 0; r[11] = 0 // ARCOUNT = 0 (any EDNS OPT record is cut off)
        return r
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
}
