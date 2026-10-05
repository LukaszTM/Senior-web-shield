package pl.seniorshield.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import pl.seniorshield.app.dns.Dns
import pl.seniorshield.app.dns.DnsCache

class DnsCacheTest {

    private var now = 1_000_000L
    private val cache = DnsCache(maxEntries = 2, clock = { now })

    private fun response(id: Int, rcode: Int): ByteArray {
        val r = ByteArray(17)
        Dns.setId(r, id)
        r[2] = 0x81.toByte()
        r[3] = (0x80 or rcode).toByte()
        r[5] = 1
        r[12] = 0; r[13] = 0; r[14] = 1; r[15] = 0; r[16] = 1
        return r
    }

    @Test
    fun servesCopyWithZeroedIdUntilExpiry() {
        cache.put("example.com", 1, response(0x1234, 0), 30)
        val hit = cache.get("example.com", 1)
        assertNotNull(hit)
        assertEquals(0, Dns.id(hit!!))
        now += 29_000
        assertNotNull(cache.get("example.com", 1))
        now += 2_000
        assertNull(cache.get("example.com", 1))
    }

    @Test
    fun clampsTtlAndKeysByType() {
        cache.put("example.com", 1, response(1, 0), 1)       // below the minimum
        now += (DnsCache.MIN_TTL_SECONDS - 1) * 1000
        assertNotNull(cache.get("example.com", 1))
        assertNull(cache.get("example.com", 28))               // other type is a miss
        cache.put("long.example", 1, response(1, 0), 999_999)  // above the maximum
        now += DnsCache.MAX_TTL_SECONDS * 1000 + 1
        assertNull(cache.get("long.example", 1))
    }

    @Test
    fun evictsLeastRecentlyUsed() {
        cache.put("a.example", 1, response(1, 0), 60)
        cache.put("b.example", 1, response(2, 0), 60)
        assertNotNull(cache.get("a.example", 1)) // touch a, so b is the eldest
        cache.put("c.example", 1, response(3, 0), 60)
        assertNull(cache.get("b.example", 1))
        assertNotNull(cache.get("a.example", 1))
        assertNotNull(cache.get("c.example", 1))
        assertEquals(2, cache.size)
    }

    @Test
    fun cacheTtlPolicy() {
        assertEquals(DnsCache.NEGATIVE_TTL_SECONDS, DnsCache.cacheTtlFor(response(1, Dns.RCODE_NXDOMAIN)))
        assertEquals(DnsCache.NEGATIVE_TTL_SECONDS, DnsCache.cacheTtlFor(response(1, Dns.RCODE_NOERROR))) // no answers
        assertNull(DnsCache.cacheTtlFor(response(1, 2)))                                    // SERVFAIL
        val truncated = response(1, 0).also { it[2] = (it[2].toInt() or 0x02).toByte() }
        assertNull(DnsCache.cacheTtlFor(truncated))
        val query = response(1, 0).also { it[2] = 0x01 }
        assertNull(DnsCache.cacheTtlFor(query))
        val stored = response(7, 0)
        cache.put("x.example", 1, stored, 60)
        assertArrayEquals(stored.copyOf().also { Dns.setId(it, 0) }, cache.get("x.example", 1))
    }
}
