package com.llmshark.mobile

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONObject
import java.util.Locale

/**
 * Internationalization helper for loading and accessing UI strings from JSON resources.
 * Follows the same pattern as the desktop version (ui\i18n\app\*.json).
 */
object I18nHelper {
    private var strings: JSONObject? = null
    private var currentLocale: String? = null
    private var prefs: SharedPreferences? = null
    
    private const val PREFS_NAME = "llmshark_i18n"
    private const val KEY_LANGUAGE = "selected_language"
    
    // Supported languages with display names
    val SUPPORTED_LANGUAGES = listOf(
        "system" to "跟随系统 / Follow System",
        "zh-Hans" to "简体中文",
        "en-US" to "English",
        "ru-RU" to "Русский",
        "fr-FR" to "Français",
        "es-ES" to "Español",
        "pt-PT" to "Português"
    )

    /**
     * Get the current locale code (e.g., "zh-Hans", "en-US")
     */
    fun getLocaleCode(): String {
        val locale = Locale.getDefault()
        val language = locale.language
        val script = locale.script
        val country = locale.country

        return when {
            // Chinese variants
            language == "zh" -> {
                when {
                    script == "Hant" || country == "TW" || country == "HK" -> "zh-Hant"
                    else -> "zh-Hans" // Default to Simplified Chinese
                }
            }
            // Map common language codes to locale codes
            language == "en" -> "en-US"
            language == "ru" -> "ru-RU"
            language == "fr" -> "fr-FR"
            language == "es" -> "es-ES"
            language == "pt" -> if (country == "BR") "pt-BR" else "pt-PT"
            language == "de" -> "de-DE"
            language == "ar" -> "ar-SA"
            language == "ja" -> "ja-JP"
            language == "ko" -> "ko-KR"
            language == "it" -> "it-IT"
            language == "nl" -> "nl-NL"
            language == "pl" -> "pl-PL"
            language == "tr" -> "tr-TR"
            language == "vi" -> "vi-VN"
            language == "th" -> "th-TH"
            language == "id" -> "id-ID"
            language == "ms" -> "ms-MY"
            language == "hi" -> "hi-IN"
            language == "fa" -> "fa-IR"
            language == "ro" -> "ro-RO"
            else -> "en-US" // Fallback to English
        }
    }
    
    /**
     * Get the user-selected language, or "system" if following system.
     */
    fun getSelectedLanguage(): String {
        return prefs?.getString(KEY_LANGUAGE, "system") ?: "system"
    }
    
    /**
     * Set the user-selected language.
     * @param languageCode "system" to follow system, or a specific locale code like "en-US"
     */
    fun setSelectedLanguage(languageCode: String) {
        prefs?.edit()?.putString(KEY_LANGUAGE, languageCode)?.apply()
    }
    
    /**
     * Get the effective locale code (considering user selection).
     */
    fun getEffectiveLocaleCode(): String {
        val selected = getSelectedLanguage()
        return if (selected == "system") {
            getLocaleCode()
        } else {
            selected
        }
    }

    /**
     * Initialize the i18n helper with the appropriate language file.
     * Should be called once in Application.onCreate() or Activity.onCreate().
     */
    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        
        val localeCode = getEffectiveLocaleCode()
        
        // Skip if already initialized with the same locale
        if (strings != null && currentLocale == localeCode) {
            return
        }

        loadStringsForLocale(context, localeCode)
    }

    /**
     * Force reload strings for the current effective locale.
     * Used when the user changes language at runtime.
     */
    fun forceReload(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val localeCode = getEffectiveLocaleCode()
        loadStringsForLocale(context, localeCode)
    }

    /**
     * Load strings JSON for the given locale code.
     */
    private fun loadStringsForLocale(context: Context, localeCode: String) {
        // Try to load the locale-specific file, fall back to English, then Chinese
        val jsonStr = loadJsonForLocale(context, localeCode)
        strings = if (jsonStr != null) {
            try {
                JSONObject(jsonStr)
            } catch (e: Exception) {
                null
            }
        } else {
            null
        }
        
        currentLocale = localeCode
    }

    /**
     * Load JSON content for a specific locale, with fallback chain.
     */
    private fun loadJsonForLocale(context: Context, localeCode: String): String? {
        // Try exact locale match first
        val exactMatch = loadJsonFromAssets(context, "i18n/ui-$localeCode.json")
        if (exactMatch != null) return exactMatch

        // Try language-only match (e.g., "en" for "en-GB")
        val languageOnly = localeCode.substringBefore("-")
        val langMatch = loadJsonFromAssets(context, "i18n/ui-$languageOnly.json")
        if (langMatch != null) return langMatch

        // Fallback to English
        val english = loadJsonFromAssets(context, "i18n/ui-en-US.json")
        if (english != null) return english

        // Final fallback to Chinese
        return loadJsonFromAssets(context, "i18n/ui-zh-Hans.json")
    }

    /**
     * Load a JSON file from assets.
     */
    private fun loadJsonFromAssets(context: Context, path: String): String? {
        return try {
            context.assets.open(path).use { it.bufferedReader().readText() }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Get a string by key path (e.g., "app.title", "buttons.search").
     * Returns the key itself if not found.
     */
    fun getString(key: String): String {
        val parts = key.split(".")
        var current: Any? = strings
        
        for (part in parts) {
            current = when (current) {
                is JSONObject -> current.opt(part)
                else -> return key
            }
        }
        
        return (current as? String) ?: key
    }

    /**
     * Get a string with parameter substitution.
     * Example: getString("chat.roundCount", "current" to "1", "max" to "5")
     */
    fun getString(key: String, vararg params: Pair<String, String>): String {
        var result = getString(key)
        for ((paramKey, value) in params) {
            result = result.replace("{$paramKey}", value)
        }
        return result
    }

    /**
     * Get a string with parameter substitution using map.
     */
    fun getString(key: String, params: Map<String, String>): String {
        var result = getString(key)
        for ((paramKey, value) in params) {
            result = result.replace("{$paramKey}", value)
        }
        return result
    }

    // Convenience methods for common string categories

    fun app(key: String): String = getString("app.$key")
    fun menu(key: String): String = getString("menu.$key")
    fun options(key: String): String = getString("options.$key")
    fun checkboxes(key: String): String = getString("checkboxes.$key")
    fun spinners(key: String): String = getString("spinners.$key")
    fun dsm(key: String): String = getString("dsm.$key")
    fun buttons(key: String): String = getString("buttons.$key")
    fun chat(key: String, vararg params: Pair<String, String>): String = 
        getString("chat.$key", *params)
    fun settings(key: String): String = getString("settings.$key")
    fun about(key: String): String = getString("about.$key")
    fun status(key: String): String = getString("status.$key")
    fun status(key: String, vararg params: Pair<String, String>): String = 
        getString("status.$key", *params)
    fun usage(key: String, vararg params: Pair<String, String>): String = 
        getString("usage.$key", *params)
    fun toast(key: String): String = getString("toast.$key")
    fun errors(key: String, vararg params: Pair<String, String>): String = 
        getString("errors.$key", *params)
}
