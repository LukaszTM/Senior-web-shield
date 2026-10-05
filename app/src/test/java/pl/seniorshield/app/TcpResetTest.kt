package pl.seniorshield.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import pl.seniorshield.app.dns.Packets
import pl.seniorshield.app.dns.TcpSegment

class TcpResetTest {

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun u32(b: ByteArray, off: Int): Long =
        (u16(b, off).toLong() shl 16) or u16(b, off + 2).toLong()

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

    /** A bare IPv4 TCP packet with the given flags and payload; checksums left zero. */
    private fun tcp4(src: ByteArray, dst: ByteArray, sport: Int, dport: Int, seq: Long, ack: Long, flags: Int, data: Int): ByteArray {
        val total = 20 + 20 + data
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total ushr 8).toByte(); p[3] = total.toByte()
        p[8] = 64; p[9] = 6
        src.copyInto(p, 12); dst.copyInto(p, 16)
        p[20] = (sport ushr 8).toByte(); p[21] = sport.toByte()
        p[22] = (dport ushr 8).toByte(); p[23] = dport.toByte()
        for (k in 0 until 4) { p[24 + k] = (seq ushr (24 - 8 * k)).toByte(); p[28 + k] = (ack ushr (24 - 8 * k)).toByte() }
        p[32] = (5 shl 4).toByte()
        p[33] = flags.toByte()
        return p
    }

    private val client = byteArrayOf(10, 111, 222.toByte(), 1)
    private val fakeDns = byteArrayOf(10, 111, 222.toByte(), 53)

    @Test
    fun parsesSyn() {
        val seg = Packets.parseTcp(tcp4(client, fakeDns, 40001, 853, 1000, 0, TcpSegment.FLAG_SYN, 0))
        assertNotNull(seg)
        seg!!
        assertEquals(853, seg.dstPort)
        assertEquals(1000L, seg.seq)
        assertTrue(seg.hasSyn)
        assertEquals(0, seg.dataLen)
        assertNull(Packets.parseTcp(ByteArray(30)))
        assertNull(Packets.parseUdp(tcp4(client, fakeDns, 1, 2, 0, 0, 0, 0)))
    }

    @Test
    fun resetsSynWithRstAck() {
        val seg = Packets.parseTcp(tcp4(client, fakeDns, 40001, 853, 0xFFFFFFFFL, 0, TcpSegment.FLAG_SYN, 0))!!
        val rst = Packets.buildTcpReset(seg)
        assertEquals(40, rst.size)
        assertEquals(0xFFFFL, sum16(rst, 0, 20))                 // IP header checksum
        assertArrayEquals(fakeDns, rst.copyOfRange(12, 16))
        assertArrayEquals(client, rst.copyOfRange(16, 20))
        assertEquals(853, u16(rst, 20))
        assertEquals(40001, u16(rst, 22))
        assertEquals(0L, u32(rst, 24))                            // SEQ = 0
        assertEquals(0L, u32(rst, 28))                            // ACK = SYN.seq + 1, wrapped
        assertEquals(TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK, rst[33].toInt() and 0x3F)
        // TCP checksum over pseudo-header + segment folds to all ones
        var s = sum16(rst, 12, 8) + 6 + 20 + sum16(rst, 20, 20)
        while ((s shr 16) != 0L) s = (s and 0xFFFF) + (s shr 16)
        assertEquals(0xFFFFL, s)
    }

    @Test
    fun resetsAckedSegmentWithPlainRst() {
        val seg = Packets.parseTcp(tcp4(client, fakeDns, 40002, 53, 500, 777, TcpSegment.FLAG_ACK, 12))!!
        assertEquals(12, seg.dataLen)
        val rst = Packets.buildTcpReset(seg)
        assertEquals(777L, u32(rst, 24))                          // SEQ = incoming ACK
        assertEquals(TcpSegment.FLAG_RST, rst[33].toInt() and 0x3F)
    }
}
