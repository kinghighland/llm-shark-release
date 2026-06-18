package com.llmshark.mobile

import android.content.Context
import android.os.Handler
import android.os.Looper
import org.json.JSONObject

/**
 * Callback interface for LLM stream responses
 */
interface LlmCallback {
    fun onSuccess(content: String)
    fun onError(error: String)
}

/**
 * Callback interface for LLM streaming - called from JNI for each chunk
 */
interface LlmStreamCallback {
    /**
     * Called for each chunk of the streaming response
     * @param chunk A small piece of the response content
     */
    fun onChunk(chunk: String)
}

/**
 * Callback interface for LLM validation
 */
interface LlmValidateCallback {
    fun onSuccess(message: String)
    fun onError(error: String)
}

/**
 * Manages LLM chat interactions
 */
class LlmChatManager(private val context: Context) {
    private val handler = Handler(Looper.getMainLooper())
    private val prefs = context.getSharedPreferences("llmshark_mobile_prefs", Context.MODE_PRIVATE)
    
    /**
     * Get current LLM configuration
     */
    fun getConfig(): LlmConfig {
        return LlmConfig.fromSharedPreferences(prefs)
    }
    
    /**
     * Save LLM configuration
     */
    fun saveConfig(config: LlmConfig) {
        config.toSharedPreferences(prefs)
    }
    
    /**
     * Get default LLM configuration from FFI
     */
    fun getDefaultConfig(): LlmConfig {
        return try {
            val jsonStr = FfiBridge.defaultLlmConfig()
            val json = JSONObject(jsonStr)
            LlmConfig.fromJson(json)
        } catch (e: Exception) {
            LlmConfig()
        }
    }
    
    /**
     * Validate LLM API configuration
     */
    fun validateConfig(config: LlmConfig, callback: LlmValidateCallback) {
        Thread {
            try {
                val configJson = config.toJson().toString()
                val resultJson = FfiBridge.validateLlm(configJson)
                val result = JSONObject(resultJson)
                
                val ok = result.optBoolean("ok", false)
                if (ok) {
                    val message = result.optString("data", "")
                    handler.post { callback.onSuccess(message) }
                } else {
                    val error = result.optString("error", "验证失败")
                    handler.post { callback.onError(error) }
                }
            } catch (e: Exception) {
                handler.post { callback.onError("验证异常: ${e.message}") }
            }
        }.start()
    }
    
    /**
     * Build mobile diagnostic prompt
     */
    fun buildPrompt(queryJson: String, casesText: String, callDescription: String = "", uiLang: String = ""): String {
        return try {
            FfiBridge.buildMobilePrompt(queryJson, casesText, callDescription, uiLang)
        } catch (e: Exception) {
            ""
        }
    }
    
    /**
     * Send chat message to LLM (non-streaming)
     */
    fun chat(config: LlmConfig, messages: List<ChatMessage>, callback: LlmCallback) {
        Thread {
            try {
                val configJson = config.toJson().toString()
                val messagesJson = messages.toJsonArray().toString()
                
                val resultJson = FfiBridge.llmChat(configJson, messagesJson)
                val result = JSONObject(resultJson)
                
                val ok = result.optBoolean("ok", false)
                if (ok) {
                    val content = result.optString("data", "")
                    handler.post { callback.onSuccess(content) }
                } else {
                    val error = result.optString("error", "LLM 调用失败")
                    handler.post { callback.onError(error) }
                }
            } catch (e: Exception) {
                handler.post { callback.onError("LLM 调用异常: ${e.message}") }
            }
        }.start()
    }
    
    /**
     * Send chat message to LLM with streaming response
     * @param config LLM configuration
     * @param messages Chat messages
     * @param streamCallback Callback for each chunk (called on background thread)
     * @param callback Final result callback (called on main thread)
     */
    fun chatStream(
        config: LlmConfig,
        messages: List<ChatMessage>,
        streamCallback: LlmStreamCallback,
        callback: LlmCallback
    ) {
        Thread {
            try {
                val configJson = config.toJson().toString()
                val messagesJson = messages.toJsonArray().toString()
                
                // Create a wrapper callback that posts chunks to main thread
                val mainThreadStreamCallback = object : LlmStreamCallback {
                    override fun onChunk(chunk: String) {
                        handler.post { streamCallback.onChunk(chunk) }
                    }
                }
                
                val resultJson = FfiBridge.llmChatStream(configJson, messagesJson, mainThreadStreamCallback)
                val result = JSONObject(resultJson)
                
                val ok = result.optBoolean("ok", false)
                if (ok) {
                    val content = result.optString("data", "")
                    handler.post { callback.onSuccess(content) }
                } else {
                    val error = result.optString("error", "LLM 调用失败")
                    handler.post { callback.onError(error) }
                }
            } catch (e: Exception) {
                handler.post { callback.onError("LLM 调用异常: ${e.message}") }
            }
        }.start()
    }
    
    /**
     * Send chat message with system prompt
     */
    fun chatWithSystemPrompt(
        config: LlmConfig,
        systemPrompt: String,
        userMessages: List<ChatMessage>,
        callback: LlmCallback
    ) {
        val allMessages = mutableListOf<ChatMessage>()
        
        // Add system message first
        if (systemPrompt.isNotEmpty()) {
            allMessages.add(ChatMessage(role = "system", content = systemPrompt))
        }
        
        // Add user messages
        allMessages.addAll(userMessages)
        
        chat(config, allMessages, callback)
    }
    
    /**
     * Send chat message with system prompt using streaming
     */
    fun chatStreamWithSystemPrompt(
        config: LlmConfig,
        systemPrompt: String,
        userMessages: List<ChatMessage>,
        streamCallback: LlmStreamCallback,
        callback: LlmCallback
    ) {
        val allMessages = mutableListOf<ChatMessage>()
        
        // Add system message first
        if (systemPrompt.isNotEmpty()) {
            allMessages.add(ChatMessage(role = "system", content = systemPrompt))
        }
        
        // Add user messages
        allMessages.addAll(userMessages)
        
        chatStream(config, allMessages, streamCallback, callback)
    }
}
