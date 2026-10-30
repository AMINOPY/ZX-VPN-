package dev.cluvex.zedsecure.domain.config

/**
 * Iranian CDN/SNI candidate discovery for the dedicated CDN/SNI profile only.
 * Hostnames are public service endpoints; IPs are resolved on the device at scan time.
 */
data class IranCdnCandidate(
    val provider: String,
    val hostname: String,
)

data class IranCdnProbeResult(
    val provider: String,
    val ip: String,
    val sni: String,
    val latencyMs: Long,
    val successfulSamples: Int,
    val totalSamples: Int,
) {
    val reliability: Double
        get() = if (totalSamples == 0) 0.0 else successfulSamples.toDouble() / totalSamples
}

/**
 * Probe from the device's current default network. The platform implementation
 * must connect to the resolved IP while setting and verifying the supplied SNI.
 */
expect suspend fun scanIranianCdnCandidates(
    candidates: List<IranCdnCandidate> = IranianCdnCatalog.candidates,
    maxResults: Int = 1,
    samples: Int = 3,
    timeoutMs: Int = 3_000,
): List<IranCdnProbeResult>

object IranianCdnCatalog {
    /**
     * Seed list of public Iranian services reported on Iranian CDN networks.
     * DNS is resolved at runtime; no edge IP is hard-coded or assumed permanent.
     * Additions should be evidence-backed and reviewed before release.
     */
    val candidates: List<IranCdnCandidate> = listOf(
        // ArvanCloud-backed public sites
        "irna.ir", "isna.ir", "president.ir", "dolat.ir", "majlis.ir",
        "ut.ac.ir", "modares.ac.ir", "snapp.ir", "tapsi.ir", "sanjesh.org",
        "idpay.ir", "tums.ac.ir", "alef.ir", "mfa.ir", "moi.ir", "iribnews.ir", "sid.ir", "financialtribune.com",
        "arvancdn.ir", "autonovin.ir", "daramet.com", "faradars.org", "iau.ir", "irantarh.com",
        "irantic.com", "melipayamak.com", "milli.gold", "nobat.ir", "sabzlearn.ir", "tarh.ir",
        "whiteo.ir", "jobinja.ir", "varzesh3.com", "maktabkhooneh.org", "gapgpt.app", "nobitex.ir",
        "snappfood.ir", "tgju.org", "shecan.ir", "zarinpal.com", "skyroom.online", "tamin.ir",
        "hostiran.net", "asriran.com", "tabnak.ir", "paziresh24.com", "kanoon.ir", "eghtesadonline.com",
    ).map { IranCdnCandidate("ArvanCloud", it) } + listOf(
        // Other reported Iranian CDN networks
        "cafebazaar.ir", "divar.ir", "basalam.com", "bale.ai", "yektanet.com", "balad.ir", "cdn.ir",
        "neshan.org", "ramzinex.com", "gamefa.com", "darukade.com", "melligold.com", "zoomit.ir", "bama.ir",
        "zoomg.ir", "adivery.com", "mediaad.org", "neshanmap.ir", "virgool.io", "khodro45.com",
    ).map { IranCdnCandidate("Sotoon", it) } + listOf(
        "digikala.com",
    ).map { IranCdnCandidate("DigiCDN", it) } + listOf(
        "aparat.com", "filimo.com",
    ).map { IranCdnCandidate("Saba Idea", it) } + listOf(
        "gap.im", "igap.net",
    ).map { IranCdnCandidate("Gap", it) } + listOf(
        // Provider-owned endpoints; included as fallback discovery candidates
        "arvancloud.ir",
    ).map { IranCdnCandidate("ArvanCloud", it) }
}
