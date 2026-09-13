package pl.seniorshield.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import pl.seniorshield.app.dns.Dns
import pl.seniorshield.app.dns.Packets

class DnsTest {

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    /** Ones-complement sum folded to 16 bits, for independent checksum verification. */
    private fun sum16(data: ByteArray, off: Int, len: Int): Long {
        var s = 0L
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) s += (data[i].toInt() and 0xFF) shl 8
        while ((s shr 16) != 0L) s = (s and 0xFFFF) + (s shr 16)
        return s
    }

    private fun buildDnsQuery(name: String, qtype: Int, id: Int = 0x1234): ByteArray {
        val out = ArrayList<Byte>()
        out.add((id ushr 8).toByte()); out.add(id.toByte())
        out.add(0x01); out.add(0x00) // RD=1
        out.add(0); out.add(1) // QDCOUNT
        repeat(6) { out.add(0) }
        for (label in name.split('.')) {
            out.add(label.length.toByte())
            for (c in label) out.add(c.code.toByte())
        }
        out.add(0)
        out.add((qtype ushr 8).toByte()); out.add(qtype.toByte())
        out.add(0); out.add(1) // class IN
        return out.toByteArray()
    }

    private fun wrapIpv4Udp(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val total = 20 + 8 + payload.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total ushr 8).toByte(); p[3] = total.toByte()
        p[8] = 64; p[9] = 17
        src.copyInto(p, 12); dst.copyInto(p, 16)
        val c = (sum16(p, 0, 20).inv() and 0xFFFF).toInt()
        p[10] = (c ushr 8).toByte(); p[11] = c.toByte()
        p[20] = (sport ushr 8).toByte(); p[21] = sport.toByte()
        p[22] = (dport ushr 8).toByte(); p[23] = dport.toByte()
        val ul = 8 + payload.size
        p[24] = (ul ushr 8).toByte(); p[25] = ul.toByte()
        payload.copyInto(p, 28)
        return p
    }

    private fun wrapIpv6Udp(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val p = ByteArray(40 + udpLen)
        p[0] = 0x60
        p[4] = (udpLen ushr 8).toByte(); p[5] = udpLen.toByte()
        p[6] = 17; p[7] = 64
        src.copyInto(p, 8); dst.copyInto(p, 24)
        p[40] = (sport ushr 8).toByte(); p[41] = sport.toByte()
        p[42] = (dport ushr 8).toByte(); p[43] = dport.toByte()
        p[44] = (udpLen ushr 8).toByte(); p[45] = udpLen.toByte()
        payload.copyInto(p, 48)
        var s = sum16(p, 8, 32) + udpLen + 17 + sum16(p, 40, udpLen)
        while ((s shr 16) != 0L) s = (s and 0xFFFF) + (s shr 16)
        var c = (s.inv() and 0xFFFF).toInt()
        if (c == 0) c = 0xFFFF
        p[46] = (c ushr 8).toByte(); p[47] = c.toByte()
        return p
    }

    private val query = buildDnsQuery("ads.doubleclick.net", 1)
    private val src4 = byteArrayOf(10, 111, 222.toByte(), 1)
    private val dst4 = byteArrayOf(10, 111, 222.toByte(), 53)

    @Test
    fun parsesIpv4UdpPacket() {
        val udp = Packets.parseUdp(wrapIpv4Udp(src4, dst4, 40000, 53, query))
        assertNotNull(udp)
        udp!!
        assertFalse(udp.isIpv6)
        assertEquals(40000, udp.srcPort)
        assertEquals(53, udp.dstPort)
        assertArrayEquals(query, udp.payload)
    }

    @Test
    fun parsesDnsQuestion() {
        val q = Dns.parseQuestion(query)
        assertNotNull(q)
        q!!
        assertEquals("ads.doubleclick.net", q.name)
        assertEquals(1, q.qtype)
        assertEquals(12 + 21 + 4, q.questionEnd)
    }

    @Test
    fun normalizesNameCase() {
        val q = Dns.parseQuestion(buildDnsQuery("ADS.DoubleClick.NET", 28))
        assertEquals("ads.doubleclick.net", q?.name)
        assertEquals(28, q?.qtype)
    }

    @Test
    fun rejectsResponsesAndMalformedPackets() {
        val resp = query.copyOf().also { it[2] = (it[2].toInt() or 0x80).toByte() }
        assertNull(Dns.parseQuestion(resp))
        assertNull(Dns.parseQuestion(ByteArray(12)))
        assertNull(Dns.parseQuestion(query.copyOf(query.size - 3)))
        val compressed = query.copyOf().also { it[12] = 0xC0.toByte() }
        assertNull(Dns.parseQuestion(compressed))
        assertNull(Packets.parseUdp(ByteArray(0)))
        assertNull(Packets.parseUdp(ByteArray(60)))
        val tcp = wrapIpv4Udp(src4, dst4, 40000, 53, query).also { it[9] = 6 }
        assertNull(Packets.parseUdp(tcp))
        val frag = wrapIpv4Udp(src4, dst4, 40000, 53, query).also { it[6] = 0x20 }
        assertNull(Packets.parseUdp(frag))
    }

    @Test
    fun buildsNxDomain() {
        val q = Dns.parseQuestion(query)!!
        val nx = Dns.buildNxDomain(query, q)
        assertEquals(q.questionEnd, nx.size)
        assertEquals(query[0], nx[0])
        assertEquals(query[1], nx[1])
        assertTrue((nx[2].toInt() and 0x80) != 0) // QR
        assertTrue((nx[2].toInt() and 0x01) != 0) // RD kept
        assertEquals(3, nx[3].toInt() and 0x0F)   // RCODE
        assertEquals(1, u16(nx, 4))               // QDCOUNT
        assertEquals(0, u16(nx, 6))               // ANCOUNT
    }

    @Test
    fun buildsValidIpv4Reply() {
        val udp = Packets.parseUdp(wrapIpv4Udp(src4, dst4, 40000, 53, query))!!
        val nx = Dns.buildNxDomain(query, Dns.parseQuestion(query)!!)
        val reply = Packets.buildUdpReply(udp, nx)
        assertEquals(28 + nx.size, reply.size)
        assertEquals(0xFFFFL, sum16(reply, 0, 20)) // header checksum validates
        assertArrayEquals(dst4, reply.copyOfRange(12, 16))
        assertArrayEquals(src4, reply.copyOfRange(16, 20))
        assertEquals(53, u16(reply, 20))
        assertEquals(40000, u16(reply, 22))
        assertEquals(reply.size, u16(reply, 2))
        assertEquals(8 + nx.size, u16(reply, 24))
        val reparsed = Packets.parseUdp(reply)
        assertNotNull(reparsed)
        assertArrayEquals(nx, reparsed!!.payload)
    }

    @Test
    fun buildsValidIpv6Reply() {
        val src6 = ByteArray(16).also { it[0] = 0xFD.toByte(); it[15] = 1 }
        val dst6 = ByteArray(16).also { it[0] = 0xFD.toByte(); it[15] = 0x53 }
        val udp = Packets.parseUdp(wrapIpv6Udp(src6, dst6, 51000, 53, query))
        assertNotNull(udp)
        udp!!
        assertTrue(udp.isIpv6)
        assertArrayEquals(query, udp.payload)
        val nx = Dns.buildNxDomain(query, Dns.parseQuestion(query)!!)
        val reply = Packets.buildUdpReply(udp, nx)
        assertEquals(48 + nx.size, reply.size)
        assertEquals(8 + nx.size, u16(reply, 4))
        assertArrayEquals(dst6, reply.copyOfRange(8, 24))
        assertArrayEquals(src6, reply.copyOfRange(24, 40))
        // UDP checksum over pseudo-header + datagram must fold to 0xFFFF
        var s = sum16(reply, 8, 32) + (8 + nx.size) + 17 + sum16(reply, 40, 8 + nx.size)
        while ((s shr 16) != 0L) s = (s and 0xFFFF) + (s shr 16)
        assertEquals(0xFFFFL, s)
    }
}
