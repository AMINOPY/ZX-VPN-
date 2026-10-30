package dev.cluvex.zedsecure.core

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CdnSniFailoverGateTest {
    @Test
    fun onlyOneFallbackCanBeClaimed() {
        val gate = CdnSniFailoverGate()
        assertTrue(gate.primaryFailed())
        assertFalse(gate.primaryFailed())
        assertTrue(gate.mayStartFallback(fallbackEnabled = true))
        assertFalse(gate.mayStartFallback(fallbackEnabled = false))
    }

    @Test
    fun successfulPrimaryDoesNotFallback() {
        val gate = CdnSniFailoverGate()
        assertTrue(gate.primaryReady())
        assertFalse(gate.primaryFailed())
        assertFalse(gate.mayStartFallback(fallbackEnabled = true))
    }

    @Test
    fun userDisconnectSuppressesFallback() {
        val gate = CdnSniFailoverGate()
        assertTrue(gate.primaryFailed())
        gate.userDisconnect()
        assertFalse(gate.mayStartFallback(fallbackEnabled = true))
        assertFalse(gate.primaryFailed())
    }
}
