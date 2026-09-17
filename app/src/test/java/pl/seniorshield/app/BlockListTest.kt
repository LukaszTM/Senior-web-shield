package pl.seniorshield.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.StringReader

class BlockListTest {

    private val list = BlockList.parse(
        StringReader(
            """
            # comment line
            doubleclick.net   # default category is ads
            [tracking]
            gemius.pl
            0.0.0.0 hosts-style.example
            [scam]
            propellerads.com
            [unknown-category]
            still-scam.example
            [ADS]
            adnxs.com
            """.trimIndent()
        )
    )

    @Test
    fun assignsCategoriesFromSectionHeaders() {
        assertEquals(Category.ADS, list.lookup("doubleclick.net"))
        assertEquals(Category.TRACKING, list.lookup("gemius.pl"))
        assertEquals(Category.TRACKING, list.lookup("hosts-style.example"))
        assertEquals(Category.SCAM, list.lookup("propellerads.com"))
        assertEquals(Category.SCAM, list.lookup("still-scam.example")) // unknown header keeps previous
        assertEquals(Category.ADS, list.lookup("adnxs.com"))            // header is case-insensitive
        assertEquals(6, list.size)
    }

    @Test
    fun matchesSubdomainsAndNormalizesCase() {
        assertEquals(Category.ADS, list.lookup("ads.g.doubleclick.net"))
        assertEquals(Category.TRACKING, list.lookup("HIT.Gemius.PL."))
        assertTrue(list.isBlocked("ib.adnxs.com"))
    }

    @Test
    fun allowsCleanDomains() {
        assertNull(list.lookup("example.com"))
        assertNull(list.lookup("notdoubleclick.net"))
        assertFalse(list.isBlocked("google.com"))
    }
}
