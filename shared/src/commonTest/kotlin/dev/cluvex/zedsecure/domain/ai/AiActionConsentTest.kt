package dev.cluvex.zedsecure.domain.ai

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AiActionConsentTest {
    private val speedTopics = listOf("speed test", "speed_test", "تست سرعت", "آزمایش سرعت")
    private val dataContext = listOf("data", "allowance", "volume", "حجم", "دیتا", "مصرف")

    @Test
    fun speedTestNeedsPriorExplanationAndAffirmativeReply() {
        val history = listOf(
            AiTurn(
                AiRole.ASSISTANT,
                "The speed test uses real data from your allowance. Do you confirm?",
            ),
        )
        assertTrue(AiActionConsent.hasExplicitConsent(history, "yes please", speedTopics, dataContext))
        assertFalse(AiActionConsent.hasExplicitConsent(history, "no", speedTopics, dataContext))
    }

    @Test
    fun standaloneYesDoesNotAuthorizeAnUnexplainedAction() {
        assertFalse(
            AiActionConsent.hasExplicitConsent(
                emptyList(),
                "yes",
                speedTopics,
                dataContext,
            ),
        )
    }

    @Test
    fun unrelatedPreviousQuestionDoesNotAuthorizeSpeedTest() {
        val history = listOf(AiTurn(AiRole.ASSISTANT, "Do you want me to check the network status?"))
        assertFalse(AiActionConsent.hasExplicitConsent(history, "yes", speedTopics, dataContext))
    } 
    @Test
    fun testedConfigImportNeedsExplicitPriorQuestionAndAffirmativeReply() {
        val previous = listOf(
            AiTurn(AiRole.ASSISTANT, "I tested these configurations. Do you want me to add them to your server list?"),
        )
        val topics = listOf("tested configurations", "tested configs")
        val context = listOf("server list", "add")
        assertTrue(AiActionConsent.hasExplicitConsent(previous, "yes, add them", topics, context))
        assertFalse(AiActionConsent.hasExplicitConsent(previous, "no, do not add", topics, context))
        assertFalse(AiActionConsent.hasExplicitConsent(emptyList(), "yes", topics, context))
    }

}
