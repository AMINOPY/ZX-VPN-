@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package dev.cluvex.zedsecure.ui.servers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.cluvex.zedsecure.domain.config.CandidateInputMode
import dev.cluvex.zedsecure.domain.config.CdnSniProfile
import dev.cluvex.zedsecure.domain.config.CountryPreset
import dev.cluvex.zedsecure.domain.config.SocksMode

/**
 * Dedicated, deliberately small CDN/SNI editor. Auto mode leaves candidates
 * empty so Psiphon's built-in CDN scanner is used; manual mode validates the
 * user's IP and SNI candidate lists before saving.
 */
@Composable
fun CdnSniSheet(
    initial: CdnSniProfile? = null,
    initialName: String = "",
    onDismiss: () -> Unit,
    onSave: (name: String, CdnSniProfile) -> Unit,
) {
    var name by remember { mutableStateOf(initialName.ifBlank { "CDN / SNI" }) }
    var inputMode by remember { mutableStateOf(initial?.inputMode ?: CandidateInputMode.AUTO) }
    var country by remember { mutableStateOf(initial?.countryPreset ?: CountryPreset.AUTO) }
    var ips by remember { mutableStateOf(initial?.ips.orEmpty()) }
    var sni by remember { mutableStateOf(initial?.sni.orEmpty()) }
    var socksMode by remember { mutableStateOf(initial?.socksMode ?: SocksMode.NONE) }
    var socksHost by remember { mutableStateOf(initial?.socksHost.orEmpty()) }
    var socksPort by remember { mutableStateOf(initial?.socksPort?.toString() ?: "1080") }
    var socksUsername by remember { mutableStateOf(initial?.socksUsername.orEmpty()) }
    var socksPassword by remember { mutableStateOf(initial?.socksPassword.orEmpty()) }
    var error by remember { mutableStateOf("") }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberBottomSheetState(
            SheetValue.Hidden,
            setOf(SheetValue.Hidden, SheetValue.Expanded),
        ),
    ) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).imePadding()
                .padding(start = 20.dp, end = 20.dp, bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("CDN / SNI", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(
                "اتصال CDN با Psiphon Fronted-Meek؛ در حالت خودکار از اسکن داخلی Psiphon استفاده می‌شود.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("نام پروفایل") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Text("انتخاب مسیر", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = { country = CountryPreset.AUTO }, label = { Text("AUTO") })
                AssistChip(onClick = { country = CountryPreset.IR }, label = { Text("AUTO IR") })
                AssistChip(onClick = { country = CountryPreset.US }, label = { Text("AUTO US") })
            }
            Text(
                when (country) {
                    CountryPreset.AUTO -> "انتخاب خودکار منطقه توسط Psiphon"
                    CountryPreset.IR -> "حالت محلی IR: خروجی کشور خاصی به Psiphon تحمیل نمی‌شود."
                    CountryPreset.US -> "پروفایل انتخاب‌شده: US"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Text("ورودی IP و SNI", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { inputMode = CandidateInputMode.AUTO; ips = ""; sni = ""; error = "" }) {
                    Text("AUTO")
                }
                TextButton(onClick = { inputMode = CandidateInputMode.MANUAL; error = "" }) {
                    Text("MANUAL")
                }
            }
            OutlinedTextField(
                value = ips,
                onValueChange = { ips = it; error = "" },
                enabled = inputMode == CandidateInputMode.MANUAL,
                label = { Text("IP addresses") },
                supportingText = { Text("IPv4 / CIDR — جداکننده: Enter یا کاما") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = sni,
                onValueChange = { sni = it; error = "" },
                enabled = inputMode == CandidateInputMode.MANUAL,
                label = { Text("SNI hostnames") },
                supportingText = { Text("مثلاً cdn.example.com") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )

            Text("SOCKS upstream", style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { socksMode = SocksMode.NONE }) { Text("خاموش") }
                TextButton(onClick = { socksMode = SocksMode.MANUAL }) { Text("دستی") }
            }
            if (socksMode == SocksMode.MANUAL) {
                OutlinedTextField(
                    value = socksHost,
                    onValueChange = { socksHost = it; error = "" },
                    label = { Text("SOCKS host / IP") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = socksPort,
                    onValueChange = { socksPort = it.filter(Char::isDigit).take(5); error = "" },
                    label = { Text("Port") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = socksUsername,
                    onValueChange = { socksUsername = it },
                    label = { Text("Username (اختیاری)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = socksPassword,
                    onValueChange = { socksPassword = it },
                    label = { Text("Password (اختیاری)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (error.isNotBlank()) {
                Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Button(
                onClick = {
                    val profile = CdnSniProfile(
                        countryPreset = country,
                        inputMode = inputMode,
                        ips = ips,
                        sni = sni,
                        fallbackEnabled = false,
                        socksMode = socksMode,
                        socksHost = socksHost,
                        socksPort = socksPort.toIntOrNull() ?: 0,
                        socksUsername = socksUsername,
                        socksPassword = socksPassword,
                    )
                    val problems = profile.validate()
                    if (name.isBlank()) error = "نام پروفایل را وارد کن."
                    else if (problems.isNotEmpty()) error = problems.joinToString("\n")
                    else onSave(name.trim(), profile)
                },
                shape = RoundedCornerShape(18.dp),
                modifier = Modifier.fillMaxWidth().height(54.dp),
            ) {
                Text("ذخیره و افزودن سرور", fontWeight = FontWeight.SemiBold)
            }
        }
    }
}
