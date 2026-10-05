package pl.seniorshield.app.dns

/**
 * A small LRU cache of upstream DNS responses keyed by (name, type). Serving
 * repeated lookups locally removes a network round-trip from most page loads.
 */
class DnsCache(
    private val maxEntries: Int = 2000,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class CacheEntry(val response: ByteArray, val expiresAt: Long)

    private val map = object : LinkedHashMap<String, CacheEntry>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>): Boolean =
            size > maxEntries
    }

    val size: Int get() = synchronized(map) { map.size }

    /** A copy of the cached response (with a zeroed transaction id), or null. */
    fun get(name: String, qtype: Int): ByteArray? {
        val key = key(name, qtype)
        synchronized(map) {
            val entry = map[key] ?: return null
            if (entry.expiresAt <= clock()) {
                map.remove(key)
                return null
            }
            return entry.response.copyOf()
        }
    }

    /**
     * Stores [response] for [ttlSeconds] (clamped to a sane range). The caller
     * decides what is cacheable; see [cacheTtlFor].
     */
    fun put(name: String, qtype: Int, response: ByteArray, ttlSeconds: Long) {
        val ttl = ttlSeconds.coerceIn(MIN_TTL_SECONDS, MAX_TTL_SECONDS)
        val copy = response.copyOf()
        Dns.setId(copy, 0)
        synchronized(map) {
            map[key(name, qtype)] = CacheEntry(copy, clock() + ttl * 1000)
        }
    }

    fun clear() = synchronized(map) { map.clear() }

    private fun key(name: String, qtype: Int) = "$name|$qtype"

    companion object {
        const val MIN_TTL_SECONDS = 10L
        const val MAX_TTL_SECONDS = 3600L
        const val NEGATIVE_TTL_SECONDS = 60L

        /**
         * How long an upstream response may be cached, or null when it must not be:
         * truncated answers and server errors are never cached; NXDOMAIN and empty
         * answers use a short negative TTL; positive answers use their smallest TTL.
         */
        fun cacheTtlFor(response: ByteArray): Long? {
            if (!Dns.isResponse(response) || Dns.isTruncated(response)) return null
            return when (Dns.rcode(response)) {
                Dns.RCODE_NOERROR -> Dns.minAnswerTtl(response) ?: NEGATIVE_TTL_SECONDS
                Dns.RCODE_NXDOMAIN -> NEGATIVE_TTL_SECONDS
                else -> null
            }
        }
    }
}
