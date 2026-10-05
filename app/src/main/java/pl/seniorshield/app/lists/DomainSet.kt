package pl.seniorshield.app.lists

/**
 * A set of domains where an entry matches itself and every subdomain.
 *
 * Entries are stored as sorted 64-bit hashes rather than strings, so a list
 * of 300 000 domains costs ~2.5 MB instead of tens of megabytes — this runs in
 * a background service on phones that may have little memory to spare. With a
 * 64-bit hash the chance of a false match across such a list is below 1e-8.
 */
class DomainSet private constructor(private val hashes: LongArray) {

    val size: Int get() = hashes.size

    fun contains(host: String): Boolean = match(host) != null

    /** The matching entry (the host itself or one of its parent domains), or null. */
    fun match(host: String): String? {
        if (hashes.isEmpty()) return null
        var h = host.lowercase().trimEnd('.')
        while (h.isNotEmpty()) {
            if (hashes.binarySearch(hash(h)) >= 0) return h
            val dot = h.indexOf('.')
            if (dot < 0) return null
            h = h.substring(dot + 1)
        }
        return null
    }

    /** Accumulates domains without keeping their strings around. */
    class Builder(expected: Int = 1024) {
        private var buf = LongArray(maxOf(16, expected))
        private var count = 0

        /** Adds a domain if it normalises to a usable host name; returns whether it did. */
        fun add(raw: String): Boolean {
            val domain = normalize(raw) ?: return false
            if (count == buf.size) buf = buf.copyOf(buf.size * 2)
            buf[count++] = hash(domain)
            return true
        }

        fun build(): DomainSet {
            if (count == 0) return EMPTY
            val sorted = buf.copyOf(count)
            sorted.sort()
            var n = 0
            for (i in sorted.indices) {
                if (i == 0 || sorted[i] != sorted[i - 1]) sorted[n++] = sorted[i]
            }
            return DomainSet(if (n == sorted.size) sorted else sorted.copyOf(n))
        }
    }

    companion object {
        val EMPTY = DomainSet(LongArray(0))

        fun of(domains: Collection<String>): DomainSet {
            val b = Builder(domains.size)
            for (d in domains) b.add(d)
            return b.build()
        }

        /** Normalises a candidate domain; null when it is not a usable host name. */
        fun normalize(raw: String): String? {
            val d = raw.trim().lowercase().trimEnd('.')
            if (d.isEmpty() || d.length > 253 || '.' !in d) return null
            if (d == "localhost" || d.endsWith(".localhost")) return null
            for (c in d) {
                if (!(c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '.' || c == '_')) return null
            }
            return d
        }

        /** FNV-1a over the UTF-8 bytes, then a 64-bit avalanche step. */
        internal fun hash(domain: String): Long {
            var h = -0x340d631b7bdddcdbL // FNV offset basis 0xcbf29ce484222325
            for (b in domain.toByteArray(Charsets.UTF_8)) {
                h = (h xor (b.toLong() and 0xFF)) * 0x100000001b3L
            }
            h = (h xor (h ushr 33)) * -0xae502812aa7333L // 0xff51afd7ed558ccd
            h = (h xor (h ushr 33)) * -0x3b314601e57a13adL // 0xc4ceb9fe1a85ec53
            return h xor (h ushr 33)
        }
    }
}
