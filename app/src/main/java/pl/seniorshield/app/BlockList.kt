package pl.seniorshield.app

import android.content.Context
import java.io.Reader

/**
 * Blocked domains loaded from assets/blocklist.txt, each tagged with a [Category].
 * A domain on the list blocks itself and every subdomain.
 */
class BlockList private constructor(private val domains: HashMap<String, Category>) {

    val size: Int get() = domains.size

    /** Returns the category the host is blocked under, or null when it is allowed. */
    fun lookup(host: String): Category? {
        var h = host.lowercase().trimEnd('.')
        while (h.isNotEmpty()) {
            domains[h]?.let { return it }
            val dot = h.indexOf('.')
            if (dot < 0) return null
            h = h.substring(dot + 1)
        }
        return null
    }

    fun isBlocked(host: String): Boolean = lookup(host) != null

    companion object {
        fun load(context: Context): BlockList =
            context.assets.open("blocklist.txt").bufferedReader().use { parse(it) }

        /**
         * Parses the list format: one domain per line (bare or hosts-file style),
         * `#` comments, and `[category]` lines that set the category of what follows.
         */
        fun parse(reader: Reader): BlockList {
            val map = HashMap<String, Category>(4096)
            var category = Category.ADS
            reader.buffered().useLines { lines ->
                for (raw in lines) {
                    var line = raw
                    val hash = line.indexOf('#')
                    if (hash >= 0) line = line.substring(0, hash)
                    line = line.trim()
                    if (line.isEmpty()) continue
                    if (line.startsWith("[") && line.endsWith("]")) {
                        category = Category.fromKey(line.substring(1, line.length - 1).trim().lowercase())
                            ?: category
                        continue
                    }
                    val parts = line.split(' ', '\t').filter { it.isNotEmpty() }
                    val domain = (if (parts.size == 1) parts[0] else parts[1]).lowercase().trimEnd('.')
                    if (domain.isNotEmpty() && domain != "localhost" && '.' in domain) {
                        map[domain] = category
                    }
                }
            }
            return BlockList(map)
        }
    }
}
