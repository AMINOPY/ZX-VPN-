package dev.cluvex.zedsecure.domain.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CdnSniProfileTest {
    @Test
    fun parsesIpv4AndCidrAndRejectsInvalidAddresses() {
        assertEquals(
            listOf("1.1.1.1", "192.0.2.0/24"),
            CdnSniCandidates.ips("1.1.1.1, 999.1.1.1\n192.0.2.0/24"),
        )
    }

    @Test
    fun normalizesSniAndAcceptsPersianComma() {
        assertEquals(
            listOf("cdn.example.com", "edge.example.net"),
            CdnSniCandidates.hostnames("HTTPS://CDN.EXAMPLE.COM/path، edge.example.net"),
        )
    }

    @Test
    fun fallbackRequiresAnExplicitCompatibleXrayTemplate() {
        val profile = CdnSniProfile(
            ips = "1.1.1.1",
            sni = "cdn.example.com",
            fallbackEnabled = true,
        )
        assertTrue(profile.validate().any { it.contains("Xray outbound template") })
    }

    @Test
    fun convertsOnlyValidatedCandidatesToExistingPsiphonProfile() {
        val profile = CdnSniProfile(
            countryPreset = CountryPreset.US,
            ips = "1.1.1.1, invalid",
            sni = "cdn.example.com",
        ).toPsiphonProfile()

        assertEquals("US", profile.country)
        assertEquals(PsiphonConfigBuilder.MODE_CDN, profile.mode)
        assertEquals("1.1.1.1", profile.cdnIps)
        assertEquals("cdn.example.com", profile.cdnSni)
    }
}
