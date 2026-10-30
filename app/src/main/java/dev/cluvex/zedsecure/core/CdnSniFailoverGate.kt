package dev.cluvex.zedsecure.core

import java.util.concurrent.atomic.AtomicBoolean

/**
 * Per-session failover gate for the dedicated CDN/SNI feature.
 *
 * The service owns engine startup/cleanup. This class only guarantees that a
 * single fallback decision can be made and that user disconnect suppresses it.
 */
internal class CdnSniFailoverGate {
    enum class State { PRIMARY_STARTING, PRIMARY_READY, FALLBACK_REQUESTED, STOPPED }

    @Volatile
    var state: State = State.PRIMARY_STARTING
        private set

    private val fallbackClaimed = AtomicBoolean(false)
    private val userStopped = AtomicBoolean(false)

    fun primaryReady(): Boolean {
        if (userStopped.get() || state != State.PRIMARY_STARTING) return false
        state = State.PRIMARY_READY
        return true
    }

    fun primaryFailed(): Boolean {
        if (userStopped.get() || !fallbackClaimed.compareAndSet(false, true)) return false
        state = State.FALLBACK_REQUESTED
        return true
    }

    fun userDisconnect() {
        userStopped.set(true)
        state = State.STOPPED
    }

    fun mayStartFallback(fallbackEnabled: Boolean): Boolean =
        fallbackEnabled && !userStopped.get() && state == State.FALLBACK_REQUESTED
}
