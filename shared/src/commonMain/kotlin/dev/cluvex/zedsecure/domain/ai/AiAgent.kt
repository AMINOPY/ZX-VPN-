package dev.cluvex.zedsecure.domain.ai

class AiAgent(
    private val client: AiClient,
    private val bridge: AiAppBridge,
    private val model: String,
    private val systemPrompt: String,
    private val allowChanges: Boolean,
) {
    private val maxRounds = 12

    private suspend fun safeChat(turns: List<AiTurn>, tools: List<AiTool>): AiReply = try {
        client.chat(model, systemPrompt, turns, tools)
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Throwable) {
        AiReply.Failed(
            "could not reach ${client.provider.label}: ${e.message ?: e::class.simpleName}. " +
                "If the VPN is off, the provider may be unreachable from this network.",
        )
    }

    sealed interface Step {
        data class Thinking(val round: Int) : Step
        data class Calling(val name: String, val argumentsJson: String) : Step
        data class Called(val result: AiToolResult) : Step
        data class Said(val text: String) : Step
        data class Failed(val message: String) : Step
    }

    private fun hasExplicitDeleteConfirmation(history: List<AiTurn>, userMessage: String): Boolean {
        val previousAssistant = history.lastOrNull { it.role == AiRole.ASSISTANT }?.text.orEmpty().lowercase()
        val askedForDeleteConfirmation =
            (("delete" in previousAssistant || "remove" in previousAssistant || "حذف" in previousAssistant) &&
                ("confirm" in previousAssistant || "are you sure" in previousAssistant ||
                    "yes or no" in previousAssistant || "تأیید" in previousAssistant || "مطمئن" in previousAssistant))
        if (!askedForDeleteConfirmation) return false

        val reply = userMessage.trim().lowercase()
        return listOf(
            "yes", "yes, delete", "confirm", "confirmed", "do it", "go ahead",
            "بله", "آره", "تأیید", "تایید", "حذف کن", "انجام بده",
        ).any { phrase -> reply == phrase || reply.startsWith("$phrase ") || reply.startsWith("$phrase،") }
    }

    suspend fun ask(
        history: List<AiTurn>,
        userMessage: String,
        onStep: (Step) -> Unit = {},
    ): List<AiTurn> {
        val tools = AiTools.forSettings(allowChanges)
        val produced = mutableListOf<AiTurn>(AiTurn(AiRole.USER, userMessage))

        repeat(maxRounds) { round ->
            onStep(Step.Thinking(round + 1))
            when (val reply = safeChat(history + produced, tools)) {
                is AiReply.Failed -> {
                    onStep(Step.Failed(reply.message))
                    produced += AiTurn(AiRole.ASSISTANT, "", error = reply.message)
                    return produced
                }

                is AiReply.Ok -> {
                    val turn = reply.turn
                    produced += turn
                    if (turn.text.isNotBlank()) onStep(Step.Said(turn.text))
                    if (turn.calls.isEmpty()) return produced

                    val results = turn.calls.map { call ->
                        onStep(Step.Calling(call.name, call.argumentsJson))
                        val deleteConfirmationMissing = call.name == "delete_server" &&
                            !hasExplicitDeleteConfirmation(history, userMessage)
                        val result = if (deleteConfirmationMissing) {
                            AiToolResult(
                                call.id,
                                call.name,
                                "blocked: deleting a server requires the assistant to ask for confirmation " +
                                    "in a previous assistant turn and the user to clearly confirm in this turn. " +
                                    "No server was deleted.",
                                failed = true,
                            )
                        } else {
                            AiTools.run(call, bridge, allowChanges)
                        }
                        onStep(Step.Called(result))
                        result
                    }
                    produced += AiTurn(AiRole.TOOL, results = results)
                }
            }
        }

        val message = "stopped after $maxRounds rounds of tool calls without a final answer"
        onStep(Step.Failed(message))
        produced += AiTurn(AiRole.ASSISTANT, "", error = message)
        return produced
    }
}
