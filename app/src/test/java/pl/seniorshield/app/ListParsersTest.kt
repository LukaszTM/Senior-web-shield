package pl.seniorshield.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import pl.seniorshield.app.lists.DomainSet
import pl.seniorshield.app.lists.Filters
import pl.seniorshield.app.lists.ListParsers
import java.io.StringReader

class ListParsersTest {

    @Test
    fun parsesAdGuardDomainRulesAndExceptions() {
        val rules = ListParsers.parseAdGuard(
            StringReader(
                """
                ! Title: AdGuard DNS filter
                [Adblock Plus 2.0]
                ||ads.example^
                ||tracker.example^${'$'}important
                @@||cdn.example^
                ||wild*.example^
                ||modifier.example^${'$'}dnstype=AAAA
                ||path.example/x^
                /regex.example/
                ||UPPER.Example^
                ||bad host.example^
                ||no-caret.example
                """.trimIndent()
            )
        )
        assertEquals(3, rules.blocked.size)
        for (d in listOf("ads.example", "tracker.example", "upper.example")) assertTrue(d, rules.blocked.contains(d))
        for (d in listOf("wild.example", "modifier.example", "path.example", "regex.example", "no-caret.example", "cdn.example")) {
            assertFalse(d, rules.blocked.contains(d))
        }
        assertEquals(1, rules.allowed.size)
        assertTrue(rules.allowed.contains("cdn.example"))
    }

    @Test
    fun parsesPlainDomainListsAndHostsFormat() {
        val set = ListParsers.parseDomainList(
            StringReader(
                """
                # CERT Polska
                oszustwo.example
                0.0.0.0 hosts.example
                Not-Lower.EXAMPLE.
                localhost
                garbage line here
                """.trimIndent()
            )
        )
        assertEquals(3, set.size)
        for (d in listOf("oszustwo.example", "hosts.example", "not-lower.example")) assertTrue(d, set.contains(d))
        assertFalse(set.contains("localhost"))
        assertFalse(set.contains("garbage"))
    }

    @Test
    fun domainSetMatchesSuffixes() {
        val set = DomainSet.of(setOf("ads.example", "ADS.example.", "dup.example", "dup.example"))
        assertEquals(2, set.size)
        assertTrue(set.contains("ads.example"))
        assertTrue(set.contains("x.y.ADS.example."))
        assertFalse(set.contains("notads.example"))
        assertFalse(set.contains("example"))
        assertEquals("ads.example", set.match("deep.ads.example"))
        assertNull(DomainSet.normalize("has space.example"))
        assertNull(DomainSet.normalize("nodot"))
        assertEquals("ok.example", DomainSet.normalize("  OK.Example. "))
    }

    @Test
    fun filtersApplyPriorityAndExceptions() {
        val builtin = BlockList.parse(StringReader("[scam]\npropellerads.com\n[tracking]\ngemius.pl"))
        val filters = Filters(
            builtin = builtin,
            phishing = DomainSet.of(setOf("doplata.example", "gemius.pl")),
            ads = DomainSet.of(setOf("doubleclick.net", "cdn.example", "propellerads.com")),
            allowed = DomainSet.of(setOf("cdn.example", "doplata.example")),
        )
        assertEquals(Category.SCAM, filters.lookup("propellerads.com"))      // builtin wins over ads
        assertEquals(Category.TRACKING, filters.lookup("hit.gemius.pl"))    // builtin wins over phishing
        assertEquals(Category.PHISHING, filters.lookup("x.doplata.example")) // phishing ignores exceptions
        assertEquals(Category.ADS, filters.lookup("ads.doubleclick.net"))
        assertNull(filters.lookup("static.cdn.example"))                    // exception beats ads
        assertNull(filters.lookup("google.com"))
        assertEquals(2 + 2 + 3, filters.totalSize)
    }

    @Test
    fun hashesAreStableAndWellSpread() {
        assertEquals(DomainSet.hash("example.com"), DomainSet.hash("example.com"))
        val hashes = (0 until 50_000).map { DomainSet.hash("host$it.example") }.toHashSet()
        assertEquals(50_000, hashes.size)
        val big = DomainSet.of((0 until 50_000).map { "host$it.example" })
        assertTrue(big.contains("a.host12345.example"))
        assertFalse(big.contains("host50000.example"))
    }
}
