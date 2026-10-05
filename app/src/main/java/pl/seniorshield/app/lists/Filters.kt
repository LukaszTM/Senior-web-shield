package pl.seniorshield.app.lists

import pl.seniorshield.app.BlockList
import pl.seniorshield.app.Category

/**
 * All blocking sources combined, in priority order:
 * 1. the bundled list (with its own categories),
 * 2. the CERT Polska warning list (Polish phishing and fraud sites),
 * 3. the AdGuard DNS filter (ads and trackers), honouring its exceptions.
 */
class Filters(
    private val builtin: BlockList,
    private val phishing: DomainSet = DomainSet.EMPTY,
    private val ads: DomainSet = DomainSet.EMPTY,
    private val allowed: DomainSet = DomainSet.EMPTY,
) {
    val builtinSize: Int get() = builtin.size
    val phishingSize: Int get() = phishing.size
    val adsSize: Int get() = ads.size
    val totalSize: Int get() = builtin.size + phishing.size + ads.size

    /** The category a host is blocked under, or null when it should resolve normally. */
    fun lookup(host: String): Category? {
        builtin.lookup(host)?.let { return it }
        if (phishing.contains(host)) return Category.PHISHING
        if (allowed.contains(host)) return null
        if (ads.contains(host)) return Category.ADS
        return null
    }
}
