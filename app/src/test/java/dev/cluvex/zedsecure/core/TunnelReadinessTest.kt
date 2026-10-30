package dev.cluvex.zedsecure.core

import java.io.DataInputStream
import java.net.ServerSocket
import kotlin.concurrent.thread
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelReadinessTest {
    @Test
    fun acceptsSuccessfulHttpResponseThroughSocksTunnel() {
        assertReadiness(statusCode = 204, expected = true)
    }

    @Test
    fun rejectsServerErrorThroughSocksTunnel() {
        assertReadiness(statusCode = 503, expected = false)
    }

    private fun assertReadiness(statusCode: Int, expected: Boolean) {
        ServerSocket(0).use { server ->
            val worker = thread(isDaemon = true) {
                server.accept().use { socket ->
                    val input = DataInputStream(socket.getInputStream())
                    val output = socket.getOutputStream()

                    // SOCKS5 no-auth negotiation.
                    input.readUnsignedByte()
                    val methodCount = input.readUnsignedByte()
                    repeat(methodCount) { input.readUnsignedByte() }
                    output.write(byteArrayOf(0x05, 0x00))
                    output.flush()

                    // Consume the SOCKS5 CONNECT request.
                    input.readUnsignedByte() // version
                    input.readUnsignedByte() // command
                    input.readUnsignedByte() // reserved
                    when (input.readUnsignedByte()) {
                        0x01 -> repeat(4) { input.readUnsignedByte() }
                        0x03 -> {
                            val length = input.readUnsignedByte()
                            repeat(length) { input.readUnsignedByte() }
                        }
                        0x04 -> repeat(16) { input.readUnsignedByte() }
                        else -> error("Unsupported SOCKS address type")
                    }
                    input.readUnsignedShort() // destination port

                    output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80))
                    output.flush()

                    // Consume the HTTP request before replying.
                    var matched = 0
                    val terminator = byteArrayOf(13, 10, 13, 10)
                    while (matched < terminator.size) {
                        val next = input.read()
                        if (next < 0) break
                        matched = if (next == (terminator[matched].toInt() and 0xFF)) {
                            matched + 1
                        } else if (next == 13) 1 else 0
                    }
                    output.write(
                        "HTTP/1.1 $statusCode Test\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n"
                            .toByteArray(Charsets.US_ASCII),
                    )
                    output.flush()
                }
            }

            val result = TunnelReadiness.verify(
                socksPort = server.localPort,
                timeoutMs = 1_000,
                host = "example.com",
                port = 80,
                attempts = 1,
            )
            worker.join(1_000)
            if (expected) assertTrue(result) else assertFalse(result)
        }
    }
}
