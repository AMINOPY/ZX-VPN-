package dev.cluvex.zedsecure.domain.ai

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AiToolsPermissionTest {
    @Test
    fun readOnlyModeBlocksEveryMutatingTool() {
        val mutating = listOf(
            "apply_settings",
            "set_active_server",
            "connect",
            "disconnect",
            "import_config",
            "delete_server",
            "create_server",
        )
        mutating.forEach { assertTrue(AiTools.isBlockedByReadOnly(it, allowChanges = false), it) }
    }

    @Test
    fun readOnlyModeKeepsDiagnosticsAvailable() {
        val readOnly = listOf(
            "get_settings",
            "list_servers",
            "get_status",
            "read_logs",
            "core_report",
            "network_diagnostics",
            "diagnose_connection",
            "compare_servers",
            "search_public_sources",
            "ping",
            "test_dns",
        )
        readOnly.forEach { assertFalse(AiTools.isBlockedByReadOnly(it, allowChanges = false), it) }
    }

    @Test
    fun mtuMeasurementCanBeReadOnlyButReconnectAndApplyCannot() {
        assertFalse(AiTools.isBlockedByPermission("probe_mtu", "{}", allowChanges = false))
        assertTrue(AiTools.isBlockedByPermission("probe_mtu", """{"reconnect":true}""", allowChanges = false))
        assertTrue(AiTools.isBlockedByPermission("probe_mtu", """{"apply":true}""", allowChanges = false))
        assertFalse(AiTools.isBlockedByPermission("probe_mtu", """{"apply":true}""", allowChanges = true))
    }

    @Test
    fun mutatingToolsAreAvailableOnlyWhenUserEnabledChanges() {
        assertFalse(AiTools.isBlockedByReadOnly("connect", allowChanges = true))
        assertFalse(AiTools.isBlockedByReadOnly("apply_settings", allowChanges = true))
    }
}
