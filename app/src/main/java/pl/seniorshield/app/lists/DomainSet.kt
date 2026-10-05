package pl.seniorshield.app.lists

/** A set of domains where an entry matches itself and every subdomain. */
class DomainSet(private val domains: Set<String>) {

    val size: Int get() = domains.size

    fun contains(host: String): Boolean = match(host) != null

    /** The matching entry (the host itself or one of its parent domains), or null. */
    fun match(host: String): String? {
        var h = host.lowercase().trimEnd('.')
        while (h.isNotEmpty()) {
            if (h in domains) return h
            val dot = h.indexOf('.')
            if (dot < 0) return null
            h = h.substring(dot + 1)
        }
        return null
    }

    companion object {
        val EMPTY = DomainSet(emptySet())

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
    }
}
