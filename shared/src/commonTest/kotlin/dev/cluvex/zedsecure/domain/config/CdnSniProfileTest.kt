package dev.cluvex.zedsecure.domain.config

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

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
            inputMode = CandidateInputMode.MANUAL,
            ips = "1.1.1.1, invalid",
            sni = "cdn.example.com",
        ).toPsiphonProfile()

        assertEquals("US", profile.country)
        assertEquals(PsiphonConfigBuilder.MODE_CDN, profile.mode)
        assertEquals("1.1.1.1", profile.cdnIps)
        assertEquals("cdn.example.com", profile.cdnSni)
    }
    @Test
    fun manualSocksIsAddedAsPsiphonUpstreamAndDisablesQuic() {
        val profile = PsiphonProfile(
            mode = PsiphonConfigBuilder.MODE_CDN,
            cdnIps = "1.1.1.1",
            cdnSni = "cdn.example.com",
            upstreamSocksMode = "manual",
            upstreamSocksHost = "127.0.0.1",
            upstreamSocksPort = 1080,
            upstreamSocksUsername = "user@name",
            upstreamSocksPassword = "p:ss",
        )
        val config = Json.parseToJsonElement(
            PsiphonConfigBuilder.build(profile, "/tmp/psiphon", 1081, 1082),
        ).jsonObject

        assertEquals(
            "socks5://user%40name:p%3Ass@127.0.0.1:1080",
            config["UpstreamProxyURL"]?.jsonPrimitive?.content,
        )
        val protocols = config["LimitTunnelProtocols"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertTrue(protocols.none { it.contains("QUIC") })
    }
    @Test
    fun dedicatedProfileRoundTripsPresetAndManualSocksSettings() {
        val original = CdnSniProfile(
            countryPreset = CountryPreset.US,
            inputMode = CandidateInputMode.MANUAL,
            ips = "1.1.1.1",
            sni = "cdn.example.com",
            socksMode = SocksMode.MANUAL,
            socksHost = "proxy.example.net",
            socksPort = 1080,
            socksUsername = "alice",
            socksPassword = "secret",
        )
        val restored = CdnSniProfile.fromPsiphon(original.toPsiphonProfile())

        assertEquals(CountryPreset.US, restored.countryPreset)
        assertEquals(CandidateInputMode.MANUAL, restored.inputMode)
        assertEquals(SocksMode.MANUAL, restored.socksMode)
        assertEquals("proxy.example.net", restored.socksHost)
        assertEquals("alice", restored.socksUsername)
        assertEquals("secret", restored.socksPassword)
    }


}
