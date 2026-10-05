package pl.seniorshield.app.dns

/** The question section of a DNS query. */
class DnsQuestion(
    val name: String,
    val qtype: Int,
    /** Offset right past the first question (header + QNAME + QTYPE + QCLASS). */
    val questionEnd: Int,
)

object Dns {

    const val RCODE_NOERROR = 0
    const val RCODE_NXDOMAIN = 3

    fun id(msg: ByteArray): Int = u16(msg, 0)

    fun setId(msg: ByteArray, id: Int) {
        msg[0] = ((id ushr 8) and 0xFF).toByte()
        msg[1] = (id and 0xFF).toByte()
    }

    fun isResponse(msg: ByteArray): Boolean = msg.size >= 12 && (msg[2].toInt() and 0x80) != 0

    fun isTruncated(msg: ByteArray): Boolean = msg.size >= 12 && (msg[2].toInt() and 0x02) != 0

    fun rcode(msg: ByteArray): Int = if (msg.size >= 12) msg[3].toInt() and 0x0F else -1

    fun answerCount(msg: ByteArray): Int = if (msg.size >= 12) u16(msg, 6) else 0

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

    /**
     * True when a DNS response answers with a zero address (A 0.0.0.0 or AAAA ::),
     * which is how ad-filtering resolvers such as AdGuard DNS signal a blocked name.
     */
    fun isZeroAnswer(msg: ByteArray): Boolean {
        if (!isResponse(msg) || rcode(msg) != RCODE_NOERROR) return false
        var zero = false
        walkAnswers(msg) { type, _, rdata, rdLength ->
            if ((type == 1 && rdLength == 4) || (type == 28 && rdLength == 16)) {
                var allZero = true
                for (j in rdata until rdata + rdLength) {
                    if (msg[j].toInt() != 0) { allZero = false; break }
                }
                if (allZero) zero = true
            }
            !zero
        }
        return zero
    }

    /**
     * The smallest TTL (seconds) among the answer records, or null when the
     * message has no answer records or is malformed.
     */
    fun minAnswerTtl(msg: ByteArray): Long? {
        if (!isResponse(msg)) return null
        var min = -1L
        val ok = walkAnswers(msg) { _, ttl, _, _ ->
            if (min < 0 || ttl < min) min = ttl
            true
        }
        return if (ok && min >= 0) min else null
    }

    /**
     * Visits every answer record as (type, ttl, rdataOffset, rdLength); the
     * visitor returns false to stop early. Returns false if the message is malformed.
     */
    private fun walkAnswers(msg: ByteArray, visitor: (Int, Long, Int, Int) -> Boolean): Boolean {
        if (msg.size < 12) return false
        val qdCount = u16(msg, 4)
        val anCount = u16(msg, 6)
        var i = 12
        repeat(qdCount) {
            i = skipName(msg, i) ?: return false
            i += 4
        }
        repeat(anCount) {
            i = skipName(msg, i) ?: return false
            if (i + 10 > msg.size) return false
            val type = u16(msg, i)
            val ttl = (u16(msg, i + 4).toLong() shl 16) or u16(msg, i + 6).toLong()
            val rdLength = u16(msg, i + 8)
            val rdata = i + 10
            if (rdata + rdLength > msg.size) return false
            if (!visitor(type, ttl, rdata, rdLength)) return true
            i = rdata + rdLength
        }
        return true
    }

    /** Returns the offset right after a (possibly compressed) name, or null if malformed. */
    private fun skipName(msg: ByteArray, start: Int): Int? {
        var i = start
        while (true) {
            if (i >= msg.size) return null
            val len = msg[i].toInt() and 0xFF
            if (len == 0) return i + 1
            if (len and 0xC0 == 0xC0) return if (i + 2 <= msg.size) i + 2 else null
            i += 1 + len
        }
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
}
