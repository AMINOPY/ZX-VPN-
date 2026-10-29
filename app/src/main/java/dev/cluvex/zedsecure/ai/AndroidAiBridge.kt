package dev.cluvex.zedsecure.ai

import android.content.Context

import dev.cluvex.zedsecure.core.DnsProbe
import dev.cluvex.zedsecure.core.VpnManager
import dev.cluvex.zedsecure.core.XrayController
import dev.cluvex.zedsecure.data.config.ConfigRepository
import dev.cluvex.zedsecure.data.net.MtuServerHint
import dev.cluvex.zedsecure.data.net.NetworkInfoRepository
import dev.cluvex.zedsecure.data.net.SpeedTestEngine
import dev.cluvex.zedsecure.data.settings.SettingsRepository
import dev.cluvex.zedsecure.domain.ai.AppAiBridge
import dev.cluvex.zedsecure.data.net.DohProbe
import dev.cluvex.zedsecure.data.net.PingService
import dev.cluvex.zedsecure.domain.config.ConfigParser
import dev.cluvex.zedsecure.domain.config.SingBoxJson
import dev.cluvex.zedsecure.domain.config.SingBoxLinks
import dev.cluvex.zedsecure.domain.config.VpnProfile
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import org.json.JSONObject
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

object AndroidAiBridge {
    private data class TestedCandidate(
        val id: String,
        val link: String,
        val protocol: String,
        val repository: String,
        val latencyMs: Long,
        val testedAtMs: Long,
    )

    private val testedCandidates = java.util.concurrent.ConcurrentHashMap<String, TestedCandidate>()
    private val configLinkRegex = Regex("""(?i)(?:vless|vmess|trojan|ss|socks5?|http|hysteria2?|hy2|tuic|wireguard|awg|ssh|vpn)://[^\s"<>]+""")
    private const val MAX_GITHUB_PROJECTS = 5
    private const val MAX_CONFIGS_PER_PROJECT = 40
    private const val MAX_CONFIGS_TO_PROBE = 12
    private const val MAX_CONFIGS_TO_RETURN = 5
    private const val CANDIDATE_TTL_MS = 30 * 60 * 1000L

    fun create(
        context: Context,
        repository: ConfigRepository,
        settings: SettingsRepository,
        toggleConnection: () -> Unit,
        mtuHint: () -> MtuServerHint?,
    ): AppAiBridge = AppAiBridge(
        repository = repository,
        readSettings = { settings.settings.value },
        writeSettings = { next -> settings.update { next } },
        coreReportFn = { XrayController.runtimeReport(14) },
        networkReportFn = { dev.cluvex.zedsecure.core.NetworkDiagnostics.createReport(context) },
        searchPublicSourcesFn = { query -> searchPublicSources(query) },
        findWorkingConfigsFn = { query, maxResults -> findWorkingConfigs(query, maxResults) },
        addTestedConfigsFn = { ids -> addTestedConfigs(repository, ids) },
        connectFn = { connect(toggleConnection) },
        disconnectFn = { disconnect(toggleConnection) },
        speedTestFn = { speedTest() },
        dnsTestFn = { server, mode, host -> testDns(server, mode, host) },
        exitInfoFn = { exitInfo() },
        mtuHintFn = mtuHint,
    )

    private fun httpText(url: String, timeoutMs: Int = 8_000): Pair<Int, String> {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("User-Agent", "ZX-VPN-AI-Assistant")
        }
        return try {
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            code to (stream?.bufferedReader()?.use { it.readText().take(512 * 1024) }.orEmpty())
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun findWorkingConfigs(query: String, requested: Int): String = withContext(Dispatchers.IO) {
        testedCandidates.clear()
        val q = query.trim().take(100).ifBlank { "v2ray configs" }
        val encoded = URLEncoder.encode("$q in:description", "UTF-8")
        val (code, body) = runCatching {
            httpText("https://api.github.com/search/repositories?q=$encoded&sort=updated&per_page=$MAX_GITHUB_PROJECTS")
        }.getOrElse { return@withContext "GitHub repository discovery failed: ${it.message ?: "network error"}" }
        if (code == 403 || code == 429) return@withContext "GitHub rate limit reached. No candidates were tested."
        if (code !in 200..299) return@withContext "GitHub repository search failed with HTTP $code."
        val items = runCatching { JSONObject(body).optJSONArray("items") }.getOrNull()
            ?: return@withContext "GitHub returned an invalid repository response."
        val discovered = linkedMapOf<String, Pair<String, String>>()
        for (i in 0 until minOf(items.length(), MAX_GITHUB_PROJECTS)) {
            val item = items.optJSONObject(i) ?: continue
            val fullName = item.optString("full_name").takeIf { it.matches(Regex("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")) } ?: continue
            val branch = item.optString("default_branch").ifBlank { "main" }
            val rawUrl = "https://raw.githubusercontent.com/$fullName/$branch/README.md"
            val readmeResult = runCatching { httpText(rawUrl) }.getOrNull() ?: continue
            val readme = readmeResult.second
            var count = 0
            for (match in configLinkRegex.findAll(readme)) {
                if (count >= MAX_CONFIGS_PER_PROJECT) break
                val link = match.value.trimEnd(',', ';', '.', ')', ']', '}')
                val supported = runCatching { ConfigParser.isSupportedLink(link) || SingBoxLinks.handles(link) }.getOrDefault(false)
                if (!supported) continue
                val id = "gh-" + fullName.hashCode().toUInt().toString(16) + "-" + link.hashCode().toUInt().toString(16)
                discovered.putIfAbsent(id, link to fullName)
                count++
            }
        }
        if (discovered.isEmpty()) return@withContext "No parser-supported configuration links were found in the README files of up to $MAX_GITHUB_PROJECTS public projects."
        val candidates = discovered.entries.take(MAX_CONFIGS_TO_PROBE)
        val permits = Semaphore(3)
        val measured = coroutineScope {
            candidates.map { (id, pair) ->
                async {
                    permits.withPermit {
                        val (link, project) = pair
                        val profile = runCatching {
                            if (SingBoxLinks.handles(link)) {
                                val parsed = SingBoxLinks.parse(link)
                                val server = SingBoxJson.servers(parsed.fragment).firstOrNull()
                                    ?: throw IllegalArgumentException("no sing-box outbound")
                                VpnProfile.fromSingBox(server, id, 0L, name = project.substringAfter('/') + " candidate", link = link)
                            } else {
                                val parsed = ConfigParser.parse(link)
                                VpnProfile(
                                    id = id,
                                    name = project.substringAfter('/') + " candidate",
                                    protocol = parsed.protocol.id.uppercase(),
                                    address = parsed.address,
                                    port = parsed.port,
                                    transportLabel = parsed.transportLabel,
                                    source = dev.cluvex.zedsecure.domain.config.ProfileSource.Link(link),
                                    addedAt = 0L,
                                )
                            }
                        }.getOrNull() ?: return@withPermit null
                        val samples = mutableListOf<Long>()
                        repeat(3) {
                            val delay = kotlinx.coroutines.withTimeoutOrNull(9_000L) {
                                PingService.realDelay(profile)
                            } ?: -1L
                            if (delay > 0L) samples += delay
                        }
                        if (samples.isEmpty()) null else {
                            val sorted = samples.sorted()
                            val median = sorted[sorted.size / 2]
                            TestedCandidate(id, link, profile.protocol, project, median, System.currentTimeMillis())
                        }
                    }
                }
            }.awaitAll().filterNotNull()
        }
        measured.sortedBy { it.latencyMs }.take(MAX_CONFIGS_TO_RETURN).forEach { testedCandidates[it.id] = it }
        val returned = testedCandidates.values.sortedBy { it.latencyMs }.take(requested.coerceIn(1, MAX_CONFIGS_TO_RETURN))
        if (returned.isEmpty()) return@withContext "No candidate passed the real engine latency probe. Nothing was added."
        buildString {
            append("Real engine-probe results; three samples per candidate, median reported. Tested at ")
            append(System.currentTimeMillis())
            append(". Only up to five candidates are returned; raw links and credentials are withheld. ")
            append("This is not full-device TUN, UDP/DNS, leak, privacy, or security validation.")
            returned.forEachIndexed { index, candidate ->
                append("\\n").append(index + 1).append(". id=").append(candidate.id)
                append(" protocol=").append(candidate.protocol)
                append(" latencyMs=").append(candidate.latencyMs)
                append(" project=").append(candidate.repository)
            }
        }
    }

    private fun addTestedConfigs(repository: ConfigRepository, idsText: String): String {
        val ids = idsText.split(',', '\\n').map { it.trim() }.filter { it.isNotBlank() }.distinct().take(MAX_CONFIGS_TO_RETURN)
        if (ids.isEmpty()) return "No candidate IDs supplied. Nothing was added."
        val now = System.currentTimeMillis()
        val candidates = ids.mapNotNull { id -> testedCandidates[id]?.takeIf { now - it.testedAtMs in 0..CANDIDATE_TTL_MS } }
        if (candidates.isEmpty() || candidates.size != ids.size) return "One or more candidate IDs are missing, expired, or were not successfully tested in this session. Nothing was added."
        val links = candidates.map { it.link }.distinct()
        val result = repository.importText(links.joinToString("\\n"))
        return result.fold(
            onSuccess = { added ->
                candidates.forEach { testedCandidates.remove(it.id) }
                "Added $added tested configuration(s) to the server list. They were measured at the time shown by the discovery result; future availability is not guaranteed."
            },
            onFailure = { "Import failed; no tested configuration was confirmed as added: ${it.message ?: "invalid config"}" },
        )
    }

    private suspend fun searchPublicSources(query: String): String = withContext(Dispatchers.IO) {
        val encoded = URLEncoder.encode(query.take(160), "UTF-8")
        val connection = (URL("https://api.github.com/search/repositories?q=$encoded&sort=updated&per_page=5")
            .openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 6_000
            readTimeout = 6_000
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("User-Agent", "ZX-VPN-AI-Assistant")
        }
        try {
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader()?.use { it.readText().take(120_000) }.orEmpty()
            if (code !in 200..299) {
                return@withContext when (code) {
                    403, 429 -> "GitHub rate limit reached; try again later."
                    else -> "GitHub search failed with HTTP $code."
                }
            }
            val root = JSONObject(body)
            val items = root.optJSONArray("items")
                ?: return@withContext "GitHub returned no repository results."
            if (items.length() == 0) return@withContext "No public repositories matched this query."
            buildString {
                append("Public GitHub repository metadata only; not a security or IP validation. ")
                for (i in 0 until minOf(items.length(), 5)) {
                    val item = items.optJSONObject(i) ?: continue
                    val name = item.optString("full_name", "unknown")
                    val description = item.optString("description", "").take(240)
                    val url = item.optString("html_url", "")
                    val stars = item.optInt("stargazers_count", 0)
                    val updated = item.optString("updated_at", "")
                    append("\n- ").append(name).append(" (stars=").append(stars)
                    append(", updated=").append(updated).append("): ").append(description)
                    append(" — ").append(url)
                }
            }
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun connect(toggle: () -> Unit): String {
        val before = VpnManager.status.value
        if (before.state.isActive) return "already connected to ${before.serverName ?: "a server"}"
        toggle()
        val settled = withTimeoutOrNull(45_000) {
            VpnManager.status.first { !it.state.isTransitioning }
        } ?: return "still connecting after 45 seconds — read_logs will say what it is waiting on"
        return when {
            settled.state.isActive -> "connected to ${settled.serverName ?: "the selected server"}"
            settled.error != null -> "did not connect: ${settled.error}"
            else -> "did not connect, and the core gave no reason — read_logs for the detail"
        }
    }

    private suspend fun disconnect(toggle: () -> Unit): String {
        if (!VpnManager.status.value.state.isActive) return "it was not connected"
        toggle()
        withTimeoutOrNull(15_000) { VpnManager.status.first { !it.state.isActive } }
        return "disconnected"
    }

    private suspend fun speedTest(): String {
        if (!VpnManager.status.value.state.isActive) {
            return "there is no active connection to measure — connect first"
        }
        val engine = SpeedTestEngine(VpnManager.activeSocksPort)
        engine.run()
        val s = engine.state.value
        return buildJsonObject {
            s.downloadMbps?.let { put("downloadMbps", it) }
            s.uploadMbps?.let { put("uploadMbps", it) }
            s.pingMs?.let { put("latencyMs", it) }
            s.jitterMs?.let { put("jitterMs", it) }
            s.loadedPingMs?.let { put("latencyUnderLoadMs", it) }
            put("bytesUsed", s.bytesUsed)
            s.error?.let { put("error", it) }
        }.toString()
    }

    private suspend fun testDns(server: String, mode: String, host: String): String = when (mode.lowercase()) {
        "doh", "https" -> DohProbe.resolve(server, host).fold(
            onSuccess = { "$server resolved $host to ${it.joinToString(", ")}" },
            onFailure = { it.message ?: "$server did not answer" },
        )

        "udp", "plain", "" -> {
            val reachable = runCatching {
                DnsProbe.fastest(listOf(server), count = 1, timeoutMs = 3_000)
            }.getOrDefault(emptyList())
            if (reachable.isEmpty()) {
                "$server did not answer a query for $host within 3 seconds"
            } else {
                "$server answered — it resolves and the path to it works"
            }
        }

        else -> "this build can test plain DNS and DoH. It has no prober for \"$mode\", so it " +
            "cannot tell you whether that resolver works before you set it."
    }

    private suspend fun exitInfo(): String {
        val info = NetworkInfoRepository().fetchInfo()
        return buildJsonObject {
            info.ipv4?.let { put("ip", it) }
            info.country?.let { put("country", it) }
            info.countryCode?.let { put("countryCode", it) }
            info.city?.let { put("city", it) }
            info.isp?.let { put("isp", it) }
            put("viaTunnel", info.viaTunnel)
            info.error?.let { put("error", it) }
        }.toString()
    }
}
