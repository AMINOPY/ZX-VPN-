package dev.cluvex.zedsecure.domain.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IranCdnAutoSelectorTest {
    @Test
    fun catalogContainsOnlyUniquePublicHostnames() {
        val candidates = IranianCdnCatalog.candidates
        assertTrue(candidates.size >= 20)
        assertEquals(
            candidates.size,
            candidates.map { it.provider to it.hostname }.distinct().size,
        )
        assertTrue(candidates.all { candidate ->
            candidate.hostname.contains('.') &&
                candidate.hostname.none { it.isWhitespace() || it == '/' || it == ':' }
        })
    }

    @Test
    fun catalogCoversSeveralIranianCdnNetworks() {
        val providers = IranianCdnCatalog.candidates.map { it.provider }.toSet()
        assertTrue("ArvanCloud" in providers)
        assertTrue("Sotoon" in providers)
        assertTrue("DigiCDN" in providers)
        assertTrue("Saba Idea" in providers)
    }
}
