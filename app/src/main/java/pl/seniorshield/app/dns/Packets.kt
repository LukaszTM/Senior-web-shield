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

/** The parts of a TCP segment needed to answer it with a reset. */
class TcpSegment(
    val isIpv6: Boolean,
    val srcAddr: ByteArray,
    val dstAddr: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val seq: Long,
    val ack: Long,
    val flags: Int,
    val dataLen: Int,
) {
    val hasAck: Boolean get() = flags and FLAG_ACK != 0
    val hasSyn: Boolean get() = flags and FLAG_SYN != 0
    val hasFin: Boolean get() = flags and FLAG_FIN != 0
    val hasRst: Boolean get() = flags and FLAG_RST != 0

    companion object {
        const val FLAG_FIN = 0x01
        const val FLAG_SYN = 0x02
        const val FLAG_RST = 0x04
        const val FLAG_ACK = 0x10
    }
}

object Packets {

    private const val PROTO_TCP = 6
    private const val PROTO_UDP = 17

    /** Fixed IP header fields shared by the parsers. */
    private class IpHeader(
        val isIpv6: Boolean,
        val headerLen: Int,
        val protocol: Int,
        val srcAddr: ByteArray,
        val dstAddr: ByteArray,
        /** Length of the transport segment (header + data). */
        val transportLen: Int,
    )

    private fun parseIp(p: ByteArray): IpHeader? {
        if (p.size < 20) return null
        return when ((p[0].toInt() ushr 4) and 0xF) {
            4 -> {
                val ihl = (p[0].toInt() and 0xF) * 4
                if (ihl < 20 || p.size < ihl) return null
                if (u16(p, 6) and 0x3FFF != 0) return null // fragments are not supported
                val totalLen = u16(p, 2)
                if (totalLen > p.size || totalLen < ihl) return null
                IpHeader(false, ihl, p[9].toInt() and 0xFF, p.copyOfRange(12, 16), p.copyOfRange(16, 20), totalLen - ihl)
            }
            6 -> {
                if (p.size < 40) return null
                val payloadLen = u16(p, 4)
                if (40 + payloadLen > p.size) return null
                // Extension headers are not supported; the next header must be the transport.
                IpHeader(true, 40, p[6].toInt() and 0xFF, p.copyOfRange(8, 24), p.copyOfRange(24, 40), payloadLen)
            }
            else -> null
        }
    }

    /**
     * Parses a raw IP packet. Returns null for anything that is not a plain,
     * unfragmented UDP datagram.
     */
    fun parseUdp(packet: ByteArray): UdpDatagram? {
        val ip = parseIp(packet) ?: return null
        if (ip.protocol != PROTO_UDP || ip.transportLen < 8) return null
        val off = ip.headerLen
        val udpLen = u16(packet, off + 4)
        if (udpLen < 8 || udpLen > ip.transportLen) return null
        return UdpDatagram(
            isIpv6 = ip.isIpv6,
            srcAddr = ip.srcAddr,
            dstAddr = ip.dstAddr,
            srcPort = u16(packet, off),
            dstPort = u16(packet, off + 2),
            payload = packet.copyOfRange(off + 8, off + udpLen),
        )
    }

    /** Parses a raw IP packet carrying TCP; null for anything else. */
    fun parseTcp(packet: ByteArray): TcpSegment? {
        val ip = parseIp(packet) ?: return null
        if (ip.protocol != PROTO_TCP || ip.transportLen < 20) return null
        val off = ip.headerLen
        val dataOffset = ((packet[off + 12].toInt() ushr 4) and 0xF) * 4
        if (dataOffset < 20 || dataOffset > ip.transportLen) return null
        return TcpSegment(
            isIpv6 = ip.isIpv6,
            srcAddr = ip.srcAddr,
            dstAddr = ip.dstAddr,
            srcPort = u16(packet, off),
            dstPort = u16(packet, off + 2),
            seq = u32(packet, off + 4),
            ack = u32(packet, off + 8),
            flags = packet[off + 13].toInt() and 0x3F,
            dataLen = ip.transportLen - dataOffset,
        )
    }

    /**
     * Builds a raw IP packet carrying [payload] as a UDP reply to [query]
     * (source/destination addresses and ports are swapped).
     */
    fun buildUdpReply(query: UdpDatagram, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val udp = ByteArray(udpLen)
        put16(udp, 0, query.dstPort)
        put16(udp, 2, query.srcPort)
        put16(udp, 4, udpLen)
        payload.copyInto(udp, 8)
        put16(udp, 6, transportChecksum(query.isIpv6, query.dstAddr, query.srcAddr, PROTO_UDP, udp))
        return buildIp(query.isIpv6, query.dstAddr, query.srcAddr, PROTO_UDP, udp)
    }

    /**
     * Builds a TCP reset answering [segment] (RFC 793 §3.4), so a client that
     * tries TCP against the fake DNS address fails immediately instead of
     * retransmitting SYNs for a minute.
     */
    fun buildTcpReset(segment: TcpSegment): ByteArray {
        val seq: Long
        val ack: Long
        val flags: Int
        if (segment.hasAck) {
            seq = segment.ack
            ack = 0
            flags = TcpSegment.FLAG_RST
        } else {
            seq = 0
            var consumed = segment.dataLen.toLong()
            if (segment.hasSyn) consumed++
            if (segment.hasFin) consumed++
            ack = (segment.seq + consumed) and 0xFFFFFFFFL
            flags = TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK
        }
        val tcp = ByteArray(20)
        put16(tcp, 0, segment.dstPort)
        put16(tcp, 2, segment.srcPort)
        put32(tcp, 4, seq)
        put32(tcp, 8, ack)
        tcp[12] = (5 shl 4).toByte() // data offset: 5 words
        tcp[13] = flags.toByte()
        put16(tcp, 16, transportChecksum(segment.isIpv6, segment.dstAddr, segment.srcAddr, PROTO_TCP, tcp))
        return buildIp(segment.isIpv6, segment.dstAddr, segment.srcAddr, PROTO_TCP, tcp)
    }

    private fun buildIp(isIpv6: Boolean, src: ByteArray, dst: ByteArray, protocol: Int, transport: ByteArray): ByteArray {
        return if (isIpv6) {
            val p = ByteArray(40 + transport.size)
            p[0] = 0x60
            put16(p, 4, transport.size)
            p[6] = protocol.toByte()
            p[7] = 64 // hop limit
            src.copyInto(p, 8)
            dst.copyInto(p, 24)
            transport.copyInto(p, 40)
            p
        } else {
            val p = ByteArray(20 + transport.size)
            p[0] = 0x45
            put16(p, 2, p.size)
            p[6] = 0x40 // Don't Fragment
            p[8] = 64   // TTL
            p[9] = protocol.toByte()
            src.copyInto(p, 12)
            dst.copyInto(p, 16)
            put16(p, 10, fold(sum16(p, 0, 20)))
            transport.copyInto(p, 20)
            p
        }
    }

    /** Transport checksum over the IPv4/IPv6 pseudo-header plus the segment. */
    private fun transportChecksum(isIpv6: Boolean, src: ByteArray, dst: ByteArray, protocol: Int, segment: ByteArray): Int {
        var sum = sum16(src, 0, src.size) + sum16(dst, 0, dst.size)
        sum += segment.size.toLong()
        sum += protocol.toLong()
        sum += sum16(segment, 0, segment.size)
        val c = fold(sum)
        // UDP uses 0 to mean "no checksum", so a computed zero is sent as all ones.
        return if (c == 0 && protocol == PROTO_UDP) 0xFFFF else c
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun u32(b: ByteArray, off: Int): Long =
        (u16(b, off).toLong() shl 16) or u16(b, off + 2).toLong()

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v ushr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    private fun put32(b: ByteArray, off: Int, v: Long) {
        put16(b, off, ((v ushr 16) and 0xFFFF).toInt())
        put16(b, off + 2, (v and 0xFFFF).toInt())
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

    private fun fold(sum: Long): Int {
        var s = sum
        while ((s shr 16) != 0L) s = (s and 0xFFFF) + (s shr 16)
        return (s.inv() and 0xFFFF).toInt()
    }
}
