package pl.seniorshield.app

import android.content.Context

/**
 * A set of blocked domains loaded from assets/blocklist.txt.
 * A domain on the list blocks itself and every subdomain.
 */
class BlockList private constructor(private val domains: HashSet<String>) {

    val size: Int get() = domains.size

    fun isBlocked(host: String): Boolean {
        var h = host.lowercase().trimEnd('.')
        while (h.isNotEmpty()) {
            if (h in domains) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
        return false
    }

    companion object {
        fun load(context: Context): BlockList {
            val set = HashSet<String>(4096)
            context.assets.open("blocklist.txt").bufferedReader().useLines { lines ->
                for (raw in lines) {
                    var line = raw
                    val hash = line.indexOf('#')
                    if (hash >= 0) line = line.substring(0, hash)
                    line = line.trim()
                    if (line.isEmpty()) continue
                    // Accept both bare domains and hosts-file format ("0.0.0.0 domain")
                    val parts = line.split(' ', '\t').filter { it.isNotEmpty() }
                    val domain = when (parts.size) {
                        1 -> parts[0]
                        else -> parts[1]
                    }.lowercase().trimEnd('.')
                    if (domain.isNotEmpty() && domain != "localhost" && '.' in domain) {
                        set.add(domain)
                    }
                }
            }
            return BlockList(set)
        }
    }
}
