package pl.seniorshield.app.lists

import java.io.Reader

/** Blocking and exception rules extracted from an AdGuard-syntax filter list. */
class AdGuardRules(val blocked: Set<String>, val allowed: Set<String>)

object ListParsers {

    /**
     * Parses the subset of AdGuard DNS filter syntax that maps to plain domain
     * blocking: `||domain^` blocks a domain and its subdomains, `@@||domain^`
     * exempts it. Rules with wildcards, regexes or modifiers (other than
     * `$important`) are ignored rather than approximated.
     */
    fun parseAdGuard(reader: Reader): AdGuardRules {
        val blocked = HashSet<String>(65536)
        val allowed = HashSet<String>(1024)
        reader.buffered().useLines { lines ->
            for (raw in lines) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("!") || line.startsWith("#") || line.startsWith("[")) continue
                var rule = line
                val exception = rule.startsWith("@@")
                if (exception) rule = rule.substring(2)
                if (!rule.startsWith("||")) continue
                rule = rule.substring(2)
                val dollar = rule.indexOf('$')
                if (dollar >= 0) {
                    val modifiers = rule.substring(dollar + 1)
                    rule = rule.substring(0, dollar)
                    if (modifiers != "important") continue
                }
                if (!rule.endsWith("^")) continue
                rule = rule.substring(0, rule.length - 1)
                if ('*' in rule || '/' in rule || '|' in rule) continue
                val domain = DomainSet.normalize(rule) ?: continue
                if (exception) allowed.add(domain) else blocked.add(domain)
            }
        }
        return AdGuardRules(blocked, allowed)
    }

    /**
     * Parses a plain domain list (one per line, `#` comments; hosts-file lines
     * such as `0.0.0.0 domain` are accepted too), e.g. the CERT Polska warning list.
     */
    fun parseDomainList(reader: Reader): Set<String> {
        val out = HashSet<String>(16384)
        reader.buffered().useLines { lines ->
            for (raw in lines) {
                var line = raw
                val hash = line.indexOf('#')
                if (hash >= 0) line = line.substring(0, hash)
                line = line.trim()
                if (line.isEmpty()) continue
                val parts = line.split(' ', '\t').filter { it.isNotEmpty() }
                val candidate = if (parts.size == 1) parts[0] else parts[1]
                DomainSet.normalize(candidate)?.let { out.add(it) }
            }
        }
        return out
    }
}
