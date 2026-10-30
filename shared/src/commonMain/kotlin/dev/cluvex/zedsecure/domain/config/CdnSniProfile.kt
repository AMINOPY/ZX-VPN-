package dev.cluvex.zedsecure.domain.config

import kotlinx.serialization.Serializable

/**
 * Additive settings for the dedicated CDN/SNI workflow.
 *
 * The existing Psiphon and SNI-spoof profile formats remain untouched.  A
 * fallback Xray profile is deliberately an explicit, compatible Xray outbound
 * template: an IP and an SNI alone cannot describe an Xray server protocol.
 */
@Serializable
data class CdnSniProfile(
    val countryPreset: CountryPreset = CountryPreset.AUTO,
    val inputMode: CandidateInputMode = CandidateInputMode.AUTO,
    val ips: String = "",
    val sni: String = "",
    val primaryEngine: PrimaryEngine = PrimaryEngine.PSIPHON,
    val fallbackEnabled: Boolean = true,
    val fallbackXrayJson: String = "",
    val socksMode: SocksMode = SocksMode.NONE,
    val socksHost: String = "",
    val socksPort: Int = 1080,
    val socksUsername: String = "",
    val socksPassword: String = "",
    val connectTimeoutSeconds: Int = 25,
    val readinessTimeoutSeconds: Int = 12,
) {
    fun normalized(): CdnSniProfile = copy(
        ips = CdnSniCandidates.ips(ips).joinToString("\n"),
        sni = CdnSniCandidates.hostnames(sni).joinToString("\n"),
        socksHost = socksHost.trim(),
        socksPort = socksPort.coerceIn(1, 65535),
        connectTimeoutSeconds = connectTimeoutSeconds.coerceIn(5, 90),
        readinessTimeoutSeconds = readinessTimeoutSeconds.coerceIn(3, 45),
    )

    fun validate(): List<String> = buildList {
        if (CdnSniCandidates.ips(ips).isEmpty()) add("Add at least one valid IPv4 address or CIDR.")
        if (CdnSniCandidates.hostnames(sni).isEmpty()) add("Add at least one valid SNI hostname.")
        if (fallbackEnabled && fallbackXrayJson.isBlank()) {
            add("Xray fallback needs a compatible Xray outbound template; IP and SNI alone are insufficient.")
        }
        if (socksMode == SocksMode.MANUAL) {
            if (socksHost.isBlank()) add("Manual SOCKS host is required.")
            if (socksPort !in 1..65535) add("Manual SOCKS port must be between 1 and 65535.")
        }
    }

    fun toPsiphonProfile(): PsiphonProfile = PsiphonProfile(
        country = countryPreset.regionCode,
        mode = PsiphonConfigBuilder.MODE_CDN,
        cdnIps = CdnSniCandidates.ips(ips).joinToString(","),
        cdnSni = CdnSniCandidates.hostnames(sni).joinToString(","),
    )
}

@Serializable
enum class CountryPreset(val regionCode: String) {
    AUTO(""),
    IR("IR"),
    US("US"),
}

@Serializable
enum class CandidateInputMode { AUTO, MANUAL }

@Serializable
enum class PrimaryEngine { PSIPHON }

@Serializable
enum class SocksMode { NONE, AUTO, MANUAL }

/** Strict parsing shared by UI validation and engine configuration. */
object CdnSniCandidates {
    private val separators = Regex("[\\s,،;]+")

    fun ips(raw: String): List<String> = raw.split(separators)
        .map(String::trim)
        .filter { it.isNotEmpty() && (isIpv4(it) || isCidr(it)) }
        .distinct()

    fun hostnames(raw: String): List<String> = raw.split(separators)
        .mapNotNull(::normalizeHostname)
        .distinct()

    private fun isIpv4(value: String): Boolean {
        val octets = value.split('.')
        return octets.size == 4 && octets.all {
            it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) &&
                (it.toIntOrNull() ?: 256) in 0..255
        }
    }

    private fun isCidr(value: String): Boolean {
        val p = value.split('/')
        return p.size == 2 && isIpv4(p[0]) &&
            p[1].isNotEmpty() && p[1].all(Char::isDigit) &&
            (p[1].toIntOrNull() ?: 33) in 0..32
    }

    private fun normalizeHostname(raw: String): String? {
        val host = raw.trim().lowercase()
            .removePrefix("https://").removePrefix("http://")
            .substringBefore('/').substringBefore(':').trim('.')
        if (host.length !in 1..253 || !host.contains('.')) return null
        if (host.split('.').any { label ->
                label.isEmpty() || label.length > 63 ||
                    label.first() == '-' || label.last() == '-' ||
                    label.any { !(it.isLetterOrDigit() || it == '-') }
            }) return null
        return host
    }
}
