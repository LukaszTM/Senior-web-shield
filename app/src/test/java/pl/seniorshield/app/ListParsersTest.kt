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
        assertEquals(setOf("ads.example", "tracker.example", "upper.example"), rules.blocked)
        assertEquals(setOf("cdn.example"), rules.allowed)
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
        assertEquals(setOf("oszustwo.example", "hosts.example", "not-lower.example"), set)
    }

    @Test
    fun domainSetMatchesSuffixes() {
        val set = DomainSet(setOf("ads.example"))
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
            phishing = DomainSet(setOf("doplata.example", "gemius.pl")),
            ads = DomainSet(setOf("doubleclick.net", "cdn.example", "propellerads.com")),
            allowed = DomainSet(setOf("cdn.example", "doplata.example")),
        )
        assertEquals(Category.SCAM, filters.lookup("propellerads.com"))      // builtin wins over ads
        assertEquals(Category.TRACKING, filters.lookup("hit.gemius.pl"))    // builtin wins over phishing
        assertEquals(Category.PHISHING, filters.lookup("x.doplata.example")) // phishing ignores exceptions
        assertEquals(Category.ADS, filters.lookup("ads.doubleclick.net"))
        assertNull(filters.lookup("static.cdn.example"))                    // exception beats ads
        assertNull(filters.lookup("google.com"))
        assertEquals(2 + 2 + 3, filters.totalSize)
    }
}
