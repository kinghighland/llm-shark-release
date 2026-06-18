package com.llmshark.mobile

import android.content.SharedPreferences
import org.json.JSONObject

/**
 * LLM configuration for API calls
 */
data class LlmConfig(
    val endpoint: String = LlmDefaults.ENDPOINT,
    val model: String = LlmDefaults.MODEL,
    val apiKey: String = LlmDefaults.TRIAL_KEY_PLACEHOLDER,
    val temperature: Double = 0.7,
    val useTrialKey: Boolean = true
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("endpoint", endpoint)
            put("model", model)
            put("api_key", apiKey)
            put("temperature", temperature)
        }
    }
    
    fun toSharedPreferences(prefs: SharedPreferences) {
        prefs.edit().apply {
            putString("llm_endpoint", endpoint)
            putString("llm_model", model)
            putString("llm_api_key", apiKey)
            putBoolean("llm_use_trial_key", useTrialKey)
            apply()
        }
    }
    
    companion object {
        fun fromSharedPreferences(prefs: SharedPreferences): LlmConfig {
            return LlmConfig(
                endpoint = prefs.getString("llm_endpoint", LlmDefaults.ENDPOINT) ?: LlmDefaults.ENDPOINT,
                model = prefs.getString("llm_model", LlmDefaults.MODEL) ?: LlmDefaults.MODEL,
                apiKey = prefs.getString("llm_api_key", LlmDefaults.TRIAL_KEY_PLACEHOLDER) ?: LlmDefaults.TRIAL_KEY_PLACEHOLDER,
                useTrialKey = prefs.getBoolean("llm_use_trial_key", true)
            )
        }
        
        fun fromJson(json: JSONObject): LlmConfig {
            return LlmConfig(
                endpoint = json.optString("endpoint", LlmDefaults.ENDPOINT),
                model = json.optString("model", LlmDefaults.MODEL),
                apiKey = json.optString("api_key", LlmDefaults.TRIAL_KEY_PLACEHOLDER),
                temperature = json.optDouble("temperature", 0.7)
            )
        }
    }
}

/**
 * Default LLM configuration values
 */
object LlmDefaults {
    const val ENDPOINT = "https://api.siliconflow.cn"
    const val MODEL = "Deepseek-ai/DeepSeek-V4-Flash"
    const val TRIAL_KEY_PLACEHOLDER = "__LLMSHARK_TRIAL_KEY__"
    
    // Invite link for SiliconFlow
    const val INVITE_URL = "https://cloud.siliconflow.cn/i/S45uICVN"
}

/**
 * Chat message for LLM API
 */
data class ChatMessage(
    val role: String,  // "user", "assistant", "system"
    val content: String
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("role", role)
            put("content", content)
        }
    }
    
    companion object {
        fun fromJson(json: JSONObject): ChatMessage {
            return ChatMessage(
                role = json.optString("role", ""),
                content = json.optString("content", "")
            )
        }
    }
}

/**
 * Helper to convert list of ChatMessage to JSONArray
 */
fun List<ChatMessage>.toJsonArray(): org.json.JSONArray {
    return org.json.JSONArray().apply {
        for (msg in this@toJsonArray) {
            put(msg.toJson())
        }
    }
}
