package dev.cluvex.zedsecure.domain.config

import java.net.InetSocketAddress
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

/**
 * JVM implementation is also used by Android (androidMain depends on jvmMain).
 * Every probe uses the device's current default network and a real TLS handshake
 * to the resolved address with SNI + certificate hostname verification enabled.
 */
actual suspend fun scanIranianCdnCandidates(
    candidates: List<IranCdnCandidate>,
    maxResults: Int,
    samples: Int,
    timeoutMs: Int,
): List<IranCdnProbeResult> = withContext(Dispatchers.IO) {
    val safeSamples = samples.coerceIn(1, 5)
    val safeTimeout = timeoutMs.coerceIn(750, 8_000)
    val permits = Semaphore(5)

    coroutineScope {
        candidates.distinctBy { it.provider to it.hostname }
            .map { candidate ->
                async(Dispatchers.IO) {
                    permits.withPermit {
                        probeCandidate(candidate, safeSamples, safeTimeout)
                    }
                }
            }
            .awaitAll()
            .filterNotNull()
            .filter { it.successfulSamples >= ((safeSamples + 1) / 2) }
            .sortedWith(
                compareByDescending<IranCdnProbeResult> { it.reliability }
                    .thenBy { it.latencyMs }
            )
            .distinctBy { it.provider to it.sni }
            .take(maxResults.coerceIn(1, 10))
    }
}

private fun probeCandidate(
    candidate: IranCdnCandidate,
    samples: Int,
    timeoutMs: Int,
): IranCdnProbeResult? {
    val host = candidate.hostname.trim().lowercase()
    if (!isSafeHostname(host)) return null

    val addresses = runCatching { InetAddress.getAllByName(host).take(2) }
        .getOrDefault(emptyList())
    if (addresses.isEmpty()) return null

    val results = addresses.mapNotNull { address ->
        val timings = ArrayList<Long>(samples)
        repeat(samples) {
            probeTlsHttp(address, host, timeoutMs)?.let(timings::add)
        }
        if (timings.isEmpty()) null else {
            val sorted = timings.sorted()
            val median = sorted[sorted.size / 2]
            IranCdnProbeResult(
                provider = candidate.provider,
                ip = address.hostAddress ?: return@mapNotNull null,
                sni = host,
                latencyMs = median,
                successfulSamples = timings.size,
                totalSamples = samples,
            )
        }
    }
    return results.minByOrNull { it.latencyMs }
}

private fun probeTlsHttp(
    address: InetAddress,
    sni: String,
    timeoutMs: Int,
): Long? {
    val started = System.nanoTime()
    val raw = Socket()
    return try {
        raw.tcpNoDelay = true
        raw.connect(InetSocketAddress(address, 443), timeoutMs)
        raw.soTimeout = timeoutMs

        val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
            .createSocket(raw, sni, 443, true) as SSLSocket
        ssl.use { socket ->
            val parameters = socket.sslParameters
            parameters.serverNames = listOf(SNIHostName(sni))
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            socket.sslParameters = parameters
            socket.soTimeout = timeoutMs
            socket.startHandshake()

            val request = "HEAD / HTTP/1.1\r\nHost: $sni\r\nUser-Agent: G-ST-VPN-AUTO-IR\r\nConnection: close\r\n\r\n"
            socket.outputStream.write(request.toByteArray(Charsets.US_ASCII))
            socket.outputStream.flush()

            val reader = socket.inputStream.bufferedReader(Charsets.US_ASCII)
            val status = reader.readLine() ?: return null
            val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: return null
            // 2xx..4xx means the TLS/SNI route reached an HTTP service.
            // 5xx and malformed responses are not considered usable candidates.
            if (code !in 200..499) return null
        }
        ((System.nanoTime() - started) / 1_000_000).coerceAtLeast(1)
    } catch (_: Exception) {
        null
    } finally {
        runCatching { raw.close() }
    }
}

private fun isSafeHostname(host: String): Boolean =
    host.length in 1..253 && host.contains('.') &&
        host.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 &&
                label.first() != '-' && label.last() != '-' &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
