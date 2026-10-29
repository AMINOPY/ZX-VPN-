package dev.cluvex.zedsecure.ai

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import dev.cluvex.zedsecure.domain.ai.AiVoiceController
import java.util.Locale

/** Turn-based speech input and spoken responses; not a persistent full-duplex audio stream. */
class AndroidAiVoiceController(private val activity: Activity) :
    AiVoiceController, RecognitionListener, TextToSpeech.OnInitListener {

    private var recognizer: SpeechRecognizer? = null
    private var tts: TextToSpeech? = TextToSpeech(activity.applicationContext, this)
    private var ttsReady = false
    private var pendingSpeech: String? = null
    private var onResult: ((String) -> Unit)? = null
    private var onError: ((String) -> Unit)? = null

    override fun startListening(onResult: (String) -> Unit, onError: (String) -> Unit) {
        this.onResult = onResult
        this.onError = onError
        if (ContextCompat.checkSelfPermission(activity, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(activity, arrayOf(Manifest.permission.RECORD_AUDIO), REQUEST_MIC_PERMISSION)
            return
        }
        beginListening()
    }

    fun onMicrophonePermissionResult(granted: Boolean) {
        if (granted) beginListening() else {
            onError?.invoke("Microphone permission was denied.")
            clearCallbacks()
        }
    }

    private fun beginListening() {
        if (!SpeechRecognizer.isRecognitionAvailable(activity)) {
            onError?.invoke("Speech recognition is not available on this device.")
            clearCallbacks()
            return
        }
        runCatching {
            recognizer?.destroy()
            recognizer = SpeechRecognizer.createSpeechRecognizer(activity).also { it.setRecognitionListener(this) }
            val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
                putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
                putExtra(RecognizerIntent.EXTRA_LANGUAGE, Locale.getDefault().toLanguageTag())
                putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, false)
                putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 1)
            }
            recognizer?.startListening(intent)
        }.onFailure {
            onError?.invoke(it.message ?: "Could not start speech recognition.")
            clearCallbacks()
        }
    }

    override fun stopListening() { runCatching { recognizer?.stopListening() } }

    override fun speak(text: String) {
        val clean = text.trim().take(4_000)
        if (clean.isBlank()) return
        if (!ttsReady) { pendingSpeech = clean; return }
        tts?.speak(clean, TextToSpeech.QUEUE_FLUSH, null, "zx-ai-reply")
    }

    override fun stopSpeaking() {
        tts?.stop()
        pendingSpeech = null
    }

    fun shutdown() {
        runCatching { recognizer?.destroy() }
        recognizer = null
        tts?.stop()
        tts?.shutdown()
        tts = null
        clearCallbacks()
    }

    private fun clearCallbacks() { onResult = null; onError = null }

    override fun onReadyForSpeech(params: Bundle?) = Unit
    override fun onBeginningOfSpeech() = Unit
    override fun onRmsChanged(rmsdB: Float) = Unit
    override fun onBufferReceived(buffer: ByteArray?) = Unit
    override fun onEndOfSpeech() = Unit

    override fun onError(error: Int) {
        val message = when (error) {
            SpeechRecognizer.ERROR_AUDIO -> "Speech recognition audio error."
            SpeechRecognizer.ERROR_CLIENT -> "Speech recognition was cancelled."
            SpeechRecognizer.ERROR_INSUFFICIENT_PERMISSIONS -> "Microphone permission is required."
            SpeechRecognizer.ERROR_NETWORK -> "Speech recognition network error."
            SpeechRecognizer.ERROR_NO_MATCH -> "No speech was recognized. Try again."
            SpeechRecognizer.ERROR_RECOGNIZER_BUSY -> "Speech recognizer is busy. Try again."
            SpeechRecognizer.ERROR_SPEECH_TIMEOUT -> "No speech was heard. Try again."
            else -> "Speech recognition failed (code $error)."
        }
        onError?.invoke(message)
        clearCallbacks()
    }

    override fun onResults(results: Bundle?) {
        val spoken = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)?.firstOrNull()
        if (spoken.isNullOrBlank()) onError?.invoke("No speech was recognized.") else onResult?.invoke(spoken)
        clearCallbacks()
    }

    override fun onPartialResults(partialResults: Bundle?) = Unit
    override fun onEvent(eventType: Int, params: Bundle?) = Unit

    override fun onInit(status: Int) {
        ttsReady = status == TextToSpeech.SUCCESS
        if (ttsReady) {
            tts?.language = Locale.getDefault()
            tts?.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                override fun onStart(utteranceId: String?) = Unit
                override fun onDone(utteranceId: String?) = Unit
                @Deprecated("Deprecated in Java")
                override fun onError(utteranceId: String?) = Unit
            })
            pendingSpeech?.let { pendingSpeech = null; speak(it) }
        }
    }

    companion object { const val REQUEST_MIC_PERMISSION = 7713 }
}
