package com.llmshark.mobile

object FfiBridge {
    init {
        System.loadLibrary("ffi_bridge")
    }

    // License & policy
    external fun mobileQrPublicKeyPem(): String
    external fun validateLicense(requestJson: String): String
    external fun buildPolicy(requestJson: String): String

    // Case crypto
    external fun generateCkB64(): String
    external fun wrapCk(requestJson: String): String
    external fun unwrapCk(requestJson: String): String
    external fun encryptCasePlaintext(requestJson: String): String
    external fun decryptCandidateCases(requestJson: String): String

    // Case search
    external fun parseKbCases(kbText: String): String
    external fun searchCases(requestJson: String): String
    external fun decryptAndParseKb(encB64: String): String

    // LLM
    external fun defaultLlmConfig(): String
    external fun buildMobilePrompt(queryJson: String, casesText: String, callDescription: String, uiLang: String): String
    external fun validateLlm(configJson: String): String
    external fun llmChat(configJson: String, messagesJson: String): String
    
    /**
     * Streaming LLM chat - calls callback.onChunk() for each chunk
     * @param configJson LLM configuration JSON
     * @param messagesJson Messages array JSON
     * @param callback Callback object implementing LlmStreamCallback interface
     * @return Final result JSON with ok/data/error
     */
    external fun llmChatStream(configJson: String, messagesJson: String, callback: LlmStreamCallback): String
}
