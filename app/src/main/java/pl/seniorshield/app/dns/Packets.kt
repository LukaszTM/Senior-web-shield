package pl.seniorshield.app.dns

/**
 * A parsed UDP datagram extracted from a raw IPv4/IPv6 packet read from the TUN interface.
 * Addresses are kept as raw bytes (4 or 16) so responses can be built without lookups.
 */
class UdpDatagram(
    val isIpv6: Boolean,
    val srcAddr: ByteArray,
    val dstAddr: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val payload: ByteArray,
)

object Packets {

    /**
     * Parses a raw IP packet. Returns null for anything that is not a plain,
     * unfragmented UDP datagram (other traffic is simply dropped by the service).
     */
    fun parseUdp(packet: ByteArray): UdpDatagram? {
        if (packet.size < 28) return null
        return when ((packet[0].toInt() ushr 4) and 0xF) {
            4 -> parseUdp4(packet)
            6 -> parseUdp6(packet)
            else -> null
        }
    }

    private fun parseUdp4(p: ByteArray): UdpDatagram? {
        val ihl = (p[0].toInt() and 0xF) * 4
        if (ihl < 20 || p.size < ihl + 8) return null
        if ((p[9].toInt() and 0xFF) != 17) return null // not UDP
        // Reject fragments (fragment offset != 0 or MF set)
        val fragField = u16(p, 6)
        if (fragField and 0x3FFF != 0) return null
        val totalLen = u16(p, 2)
        if (totalLen > p.size || totalLen < ihl + 8) return null
        val udpLen = u16(p, ihl + 4)
        if (udpLen < 8 || ihl + udpLen > totalLen) return null
        return UdpDatagram(
            isIpv6 = false,
            srcAddr = p.copyOfRange(12, 16),
            dstAddr = p.copyOfRange(16, 20),
            srcPort = u16(p, ihl),
            dstPort = u16(p, ihl + 2),
            payload = p.copyOfRange(ihl + 8, ihl + udpLen),
        )
    }

    private fun parseUdp6(p: ByteArray): UdpDatagram? {
        if (p.size < 48) return null
        if ((p[6].toInt() and 0xFF) != 17) return null // extension headers not supported
        val payloadLen = u16(p, 4)
        if (payloadLen < 8 || 40 + payloadLen > p.size) return null
        val udpLen = u16(p, 44)
        if (udpLen < 8 || udpLen > payloadLen) return null
        return UdpDatagram(
            isIpv6 = true,
            srcAddr = p.copyOfRange(8, 24),
            dstAddr = p.copyOfRange(24, 40),
            srcPort = u16(p, 40),
            dstPort = u16(p, 42),
            payload = p.copyOfRange(48, 40 + udpLen),
        )
    }

    /**
     * Builds a raw IP packet carrying [payload] as a UDP reply to [query]
     * (source/destination addresses and ports are swapped).
     */
    fun buildUdpReply(query: UdpDatagram, payload: ByteArray): ByteArray {
        return if (query.isIpv6) buildReply6(query, payload) else buildReply4(query, payload)
    }

    private fun buildReply4(q: UdpDatagram, payload: ByteArray): ByteArray {
        val totalLen = 20 + 8 + payload.size
        val p = ByteArray(totalLen)
        p[0] = 0x45 // version 4, IHL 5
        put16(p, 2, totalLen)
        p[6] = 0x40 // Don't Fragment
        p[8] = 64   // TTL
        p[9] = 17   // UDP
        q.dstAddr.copyInto(p, 12) // reply comes "from" the original destination
        q.srcAddr.copyInto(p, 16)
        put16(p, 10, checksum(sum16(p, 0, 20)))
        // UDP header
        put16(p, 20, q.dstPort)
        put16(p, 22, q.srcPort)
        put16(p, 24, 8 + payload.size)
        // UDP checksum is optional over IPv4; leave 0
        payload.copyInto(p, 28)
        return p
    }

    private fun buildReply6(q: UdpDatagram, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val p = ByteArray(40 + udpLen)
        p[0] = 0x60 // version 6
        put16(p, 4, udpLen)
        p[6] = 17 // next header: UDP
        p[7] = 64 // hop limit
        q.dstAddr.copyInto(p, 8)
        q.srcAddr.copyInto(p, 24)
        put16(p, 40, q.dstPort)
        put16(p, 42, q.srcPort)
        put16(p, 44, udpLen)
        payload.copyInto(p, 48)
        // Mandatory UDP checksum with IPv6 pseudo-header
        var sum = sum16(p, 8, 32)          // src + dst
        sum += udpLen.toLong()             // upper-layer length
        sum += 17L                         // next header
        sum += sum16(p, 40, udpLen)        // UDP header + payload (checksum field is 0)
        var c = checksum(sum)
        if (c == 0) c = 0xFFFF
        put16(p, 46, c)
        return p
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v ushr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    private fun sum16(data: ByteArray, off: Int, len: Int): Long {
        var s = 0L
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) s += (data[i].toInt() and 0xFF) shl 8
        return s
    }

    private fun checksum(sum: Long): Int {
        var s = sum
        while ((s shr 16) != 0L) s = (s and 0xFFFF) + (s shr 16)
        return (s.inv() and 0xFFFF).toInt()
    }
}
