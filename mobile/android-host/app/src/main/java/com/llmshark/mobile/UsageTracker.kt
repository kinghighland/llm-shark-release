package com.llmshark.mobile

import android.content.Context
import android.content.SharedPreferences
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * 每日诊断使用次数追踪器
 * - 内置服务每日限额 10 次
 * - 使用自有 API Key 无限制
 * - 数据简单加密存储
 */
class UsageTracker(private val context: Context) {
    
    companion object {
        private const val PREFS_NAME = "llmshark_usage"
        private const val KEY_DATE = "date"
        private const val KEY_COUNT = "count"
        private const val KEY_ENCRYPTED = "encrypted_data"
        
        // 每日限额
        const val DAILY_LIMIT = 10
        
        // 加密密钥 (16 bytes for AES-128)
        private val ENCRYPTION_KEY = byteArrayOf(
            0x4C, 0x6C, 0x6D, 0x53, 0x68, 0x61, 0x72, 0x6B,
            0x4D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x4B, 0x79
        )
    }
    
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    
    /**
     * 获取今日已使用次数
     */
    fun getTodayCount(): Int {
        val today = getTodayString()
        val storedDate = decryptData(KEY_DATE)
        
        // 如果日期不是今天，重置计数
        if (storedDate != today) {
            resetCount()
            return 0
        }
        
        return decryptData(KEY_COUNT)?.toIntOrNull() ?: 0
    }
    
    /**
     * 增加使用次数，返回增加后的次数
     */
    fun incrementCount(): Int {
        val today = getTodayString()
        val currentCount = getTodayCount()
        val newCount = currentCount + 1
        
        // 加密存储日期和计数
        encryptAndStore(KEY_DATE, today)
        encryptAndStore(KEY_COUNT, newCount.toString())
        
        return newCount
    }
    
    /**
     * 重置计数
     */
    fun resetCount() {
        prefs.edit().clear().apply()
    }
    
    /**
     * 检查是否可以使用内置服务
     * @return true 如果还有剩余次数
     */
    fun canUseTrialService(): Boolean {
        return getTodayCount() < DAILY_LIMIT
    }
    
    /**
     * 获取使用状态文本
     * @param isUsingOwnKey 是否使用自有 API Key
     */
    fun getStatusText(isUsingOwnKey: Boolean): String {
        return if (isUsingOwnKey) {
            I18nHelper.usage("trialCount", "used" to "--", "limit" to "∞")
        } else {
            val count = getTodayCount()
            I18nHelper.usage("trialCount", "used" to count.toString(), "limit" to DAILY_LIMIT.toString())
        }
    }
    
    // ============== 加密相关 ==============
    
    private fun encryptAndStore(key: String, value: String) {
        try {
            val encrypted = encrypt(value)
            prefs.edit().putString(key, encrypted).apply()
        } catch (e: Exception) {
            // 加密失败时直接存储（降级处理）
            prefs.edit().putString(key, value).apply()
        }
    }
    
    private fun decryptData(key: String): String? {
        val encrypted = prefs.getString(key, null) ?: return null
        return try {
            decrypt(encrypted)
        } catch (e: Exception) {
            // 解密失败，可能是未加密的数据，直接返回
            encrypted
        }
    }
    
    private fun encrypt(data: String): String {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val keySpec = SecretKeySpec(ENCRYPTION_KEY, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(encrypted)
    }
    
    private fun decrypt(encryptedData: String): String {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val keySpec = SecretKeySpec(ENCRYPTION_KEY, "AES")
        cipher.init(Cipher.DECRYPT_MODE, keySpec)
        val decoded = Base64.getDecoder().decode(encryptedData)
        val decrypted = cipher.doFinal(decoded)
        return String(decrypted, Charsets.UTF_8)
    }
    
    private fun getTodayString(): String {
        val sdf = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.getDefault())
        return sdf.format(java.util.Date())
    }
}
