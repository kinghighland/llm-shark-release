package com.llmshark.mobile

import android.content.Context
import android.content.SharedPreferences
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import org.json.JSONArray
import org.json.JSONObject

data class MobileAuthHostResult(
        val ok: Boolean,
        val verifyResponseJson: String,
        val policyResponseJson: String?,
)

data class MobileCaseCryptoBootstrapResult(
        val ok: Boolean,
        val responseJson: String,
)

data class DiagnoseResult(
        val ok: Boolean,
        val searchResultJson: String?,
        val decryptedCasesJson: String?,
        val error: String?,
)

/** User-input query for case search on the mobile side. Maps to the Rust CaseQuery struct. */
data class CaseQueryInput(
    // ============== 必选项 ==============
    val callSide: String? = null,
    val has183: Boolean? = null,
    val has180: Boolean? = null,
    val has200Invite: Boolean? = null,
    val hasAck200: Boolean? = null,
    val hasCancel: Boolean? = null,
    val hasBye: Boolean? = null,
    val sipResponseCode: String? = null,
    val sipText: String? = null,
    // ============== 可选项 ==============
    val sipProvisionalCode: String? = null,
    val halfConnected: String? = null,
    val sipRetrans: String? = null,
    val mediaType: String? = null,
    val mmEvent: String? = null,
    val supplementaryService: String? = null,
    // ============== 高级可选项 ==============
    val dsmState: String? = null,
    // ============== 兼容旧字段 ==============
    val errorCode: String? = null,
    val callType: String? = null,
) {
    fun toJson(): JSONObject {
        val obj = JSONObject()
        // 必选项
        callSide?.let { obj.put("call_side", it) }
        has183?.let { obj.put("has_183", it) }
        has180?.let { obj.put("has_180", it) }
        has200Invite?.let { obj.put("has_200_invite", it) }
        hasAck200?.let { obj.put("has_ack_200", it) }
        hasCancel?.let { obj.put("has_cancel", it) }
        hasBye?.let { obj.put("has_bye", it) }
        sipResponseCode?.let { obj.put("sip_response_code", it) }
        sipText?.let { obj.put("sip_text", it) }
        // 可选项
        sipProvisionalCode?.let { obj.put("sip_provisional_code", it) }
        halfConnected?.let { obj.put("half_connected", it) }
        sipRetrans?.let { obj.put("sip_retrans", it) }
        mediaType?.let { obj.put("media_type", it) }
        mmEvent?.let { obj.put("mm_event", it) }
        supplementaryService?.let { obj.put("supplementary_service", it) }
        // 高级可选项
        dsmState?.let { obj.put("dsm_state", it) }
        // 兼容旧字段
        errorCode?.let { obj.put("error_code", it) }
        callType?.let { obj.put("call_type", it) }
        return obj
    }
}

class MobileAuthHost(private val context: Context) {
    private val prefs: SharedPreferences =
            context.getSharedPreferences("llmshark_mobile_auth_v1", Context.MODE_PRIVATE)

    private val kekManager = KekManager(context)

    // ---------------------------------------------------------------------------
    // Authorization flow
    // ---------------------------------------------------------------------------

    fun importPayloadAndBuildPolicy(payloadJson: String): MobileAuthHostResult {
        return try {
            val nowUtc = nowUtcIso()
            val state = loadState()
            val today = todayLocalDateString()
            val usedToday = if (state.usedDay == today) state.usedToday else 0

            val req = JSONObject()
            req.put("payload_json", payloadJson)
            req.put("public_key_pem", FfiBridge.mobileQrPublicKeyPem())
            req.put("now_utc", nowUtc)
            req.put("used_today", usedToday)
            req.put("seen_nonces", JSONArray(state.seenNonces.toList()))
            req.put("last_trusted_timestamp", state.lastTrustedTimestamp)

            val verifyOut = FfiBridge.validateLicense(req.toString())
            val verifyParsed = JSONObject(verifyOut)
            val ok = verifyParsed.optBoolean("ok", false)
            if (!ok) {
                return MobileAuthHostResult(
                        ok = false,
                        verifyResponseJson = verifyOut,
                        policyResponseJson = null
                )
            }

            val data = verifyParsed.optJSONObject("data") ?: JSONObject()
            val nonce = data.optString("nonce", "")
            val newSeen = LinkedHashSet(state.seenNonces)
            if (nonce.isNotBlank()) {
                newSeen.add(nonce)
            }
            val capped = newSeen.toList().takeLast(256).toSet()

            saveState(
                    HostState(
                            usedDay = today,
                            usedToday = usedToday,
                            lastTrustedTimestamp = nowUtc,
                            seenNonces = capped,
                            wrappedCkBlobJson = state.wrappedCkBlobJson,
                    )
            )

            val policyReq = JSONObject()
            policyReq.put("plan_tier", data.optString("plan_tier"))
            policyReq.put("topn_limit", data.optInt("topn_limit"))
            policyReq.put("daily_analysis_limit", data.optInt("daily_analysis_limit"))
            policyReq.put("used_today", usedToday)

            val policyOut = FfiBridge.buildPolicy(policyReq.toString())
            MobileAuthHostResult(
                    ok = true,
                    verifyResponseJson = verifyOut,
                    policyResponseJson = policyOut
            )
        } catch (t: Throwable) {
            MobileAuthHostResult(
                    ok = false,
                    verifyResponseJson =
                            """{"ok":false,"error":"importPayloadAndBuildPolicy exception: ${t.message ?: t::class.java.simpleName}"}""",
                    policyResponseJson = null
            )
        }
    }

    fun buildPolicy(planTier: String, topnLimit: Int, dailyAnalysisLimit: Int): String {
        return try {
            val state = loadState()
            val today = todayLocalDateString()
            val usedToday = if (state.usedDay == today) state.usedToday else 0
            val req = JSONObject()
            req.put("plan_tier", planTier)
            req.put("topn_limit", topnLimit)
            req.put("daily_analysis_limit", dailyAnalysisLimit)
            req.put("used_today", usedToday)
            FfiBridge.buildPolicy(req.toString())
        } catch (t: Throwable) {
            """{"ok":false,"error":"buildPolicy exception: ${t.message ?: t::class.java.simpleName}"}"""
        }
    }

    fun onAnalyzeConsumedOne() {
        val today = todayLocalDateString()
        val state = loadState()
        val usedToday = if (state.usedDay == today) state.usedToday else 0
        saveState(state.copy(usedDay = today, usedToday = usedToday + 1))
    }

    // ---------------------------------------------------------------------------
    // Case crypto flow (KEK from Android Keystore, CK memory-only)
    // ---------------------------------------------------------------------------

    /**
     * Ensures a wrapped CK exists. The KEK is obtained from [KekManager] (backed by Android
     * Keystore), never from caller input.
     *
     * If a wrapped CK already exists in persisted state, returns it immediately. Otherwise:
     * generates a new CK, wraps it with the KEK, and persists the blob.
     */
    fun ensureWrappedCk(kekId: String = "android-keystore-v1"): MobileCaseCryptoBootstrapResult {
        return try {
            val state = loadState()
            val existing = state.wrappedCkBlobJson
            if (!existing.isNullOrBlank()) {
                return MobileCaseCryptoBootstrapResult(ok = true, responseJson = existing)
            }

            val kekB64 = kekManager.getOrGenerateKekB64()
            val ckB64 = FfiBridge.generateCkB64()
            val req = JSONObject()
            req.put("ck_b64", ckB64)
            req.put("kek_b64", kekB64)
            req.put("kek_id", kekId)
            val wrapOut = FfiBridge.wrapCk(req.toString())
            val parsed = JSONObject(wrapOut)
            val ok = parsed.optBoolean("ok", false)
            if (!ok) {
                return MobileCaseCryptoBootstrapResult(ok = false, responseJson = wrapOut)
            }

            val wrappedBlob = parsed.optJSONObject("data")
            if (wrappedBlob != null) {
                saveState(state.copy(wrappedCkBlobJson = wrappedBlob.toString()))
            }
            MobileCaseCryptoBootstrapResult(ok = true, responseJson = wrapOut)
        } catch (t: Throwable) {
            MobileCaseCryptoBootstrapResult(
                    ok = false,
                    responseJson =
                            """{"ok":false,"error":"ensureWrappedCk exception: ${t.message ?: t::class.java.simpleName}"}"""
            )
        }
    }

    /**
     * Encrypts a case plaintext string. The CK is unwrapped in-memory using the KEK from Android
     * Keystore, used for encryption, then the in-memory CK reference is discarded when the function
     * returns.
     */
    fun encryptCasePlaintext(plaintext: String): String {
        val unwrap = unwrapCurrentCk()
        if (!unwrap.ok) {
            return unwrap.errorJson.orEmpty()
        }
        return try {
            val req = JSONObject()
            req.put("plaintext", plaintext)
            req.put("ck_b64", unwrap.ckB64)
            FfiBridge.encryptCasePlaintext(req.toString())
        } finally {
            // CK was in UnwrapResult which is local — let it be GC'd promptly.
            // The base64 string itself cannot be zeroized from Kotlin, but
            // we ensure no long-lived reference is held.
        }
    }

    /**
     * Decrypts candidate cases by ID. The CK is unwrapped in-memory using the KEK from Android
     * Keystore, used for selective decryption, then the in-memory CK reference is discarded when
     * the function returns.
     */
    fun decryptCandidateCases(
            encryptedCasesJson: String,
            candidateCaseIds: List<String>,
    ): String {
        val unwrap = unwrapCurrentCk()
        if (!unwrap.ok) {
            return unwrap.errorJson.orEmpty()
        }
        val encryptedCases =
                try {
                    JSONArray(encryptedCasesJson)
                } catch (_: Throwable) {
                    return """{"ok":false,"error":"invalid encryptedCasesJson"}"""
                }
        return try {
            val req = JSONObject()
            req.put("encrypted_cases", encryptedCases)
            req.put("candidate_case_ids", JSONArray(candidateCaseIds))
            req.put("ck_b64", unwrap.ckB64)
            FfiBridge.decryptCandidateCases(req.toString())
        } finally {
            // Same as encryptCasePlaintext: no long-lived CK reference.
        }
    }

    // ---------------------------------------------------------------------------
    // Case search flow
    // ---------------------------------------------------------------------------

    /**
     * Decrypts and parses the bundled encrypted KB asset.
     * @param encB64 Base64-encoded content of the `.enc` KB file
     * @return FFI response JSON with parsed cases array
     */
    fun decryptAndParseKb(encB64: String): String {
        return try {
            FfiBridge.decryptAndParseKb(encB64)
        } catch (t: Throwable) {
            """{"ok":false,"error":"decryptAndParseKb exception: ${t.message ?: t::class.java.simpleName}"}"""
        }
    }

    /**
     * Parses the decrypted KB text into a JSON case array. Returns the FFI response JSON:
     * `{"ok":true,"data":[...]}`.
     */
    fun parseKbCases(kbText: String): String {
        return try {
            FfiBridge.parseKbCases(kbText)
        } catch (t: Throwable) {
            """{"ok":false,"error":"parseKbCases exception: ${t.message ?: t::class.java.simpleName}"}"""
        }
    }

    /**
     * Searches cases matching the query, returning at most [maxResults] hits. The [casesJson] is
     * the persisted case array from a previous `parseKbCases` call.
     *
     * Returns the FFI response JSON: `{"ok":true,"data":{"hits":[...],"trace":[...]}}`.
     */
    fun searchCases(
            casesJson: String,
            query: CaseQueryInput,
            maxResults: Int,
    ): String {
        return try {
            val req = JSONObject()
            req.put("cases", JSONArray(casesJson))
            req.put("query", query.toJson())
            req.put("max_results", maxResults)
            FfiBridge.searchCases(req.toString())
        } catch (t: Throwable) {
            """{"ok":false,"error":"searchCases exception: ${t.message ?: t::class.java.simpleName}"}"""
        }
    }

    /**
     * Full diagnostic pipeline:
     * 1. Search cases matching [query] → get candidate IDs + hits.
     * 2. Decrypt only the candidate cases from the encrypted KB.
     * 3. Return search hits (with decrypted content) + policy info.
     *
     * This is the main entry point for the mobile diagnostic flow.
     */
    fun diagnose(
            casesJson: String,
            encryptedCasesJson: String,
            query: CaseQueryInput,
            topnLimit: Int,
    ): DiagnoseResult {
        return try {
            // Step 1: Search
            val searchOut = searchCases(casesJson, query, topnLimit)
            val searchParsed = JSONObject(searchOut)
            if (!searchParsed.optBoolean("ok", false)) {
                return DiagnoseResult(
                        ok = false,
                        searchResultJson = searchOut,
                        decryptedCasesJson = null,
                        error = searchParsed.optString("error", "search failed")
                )
            }
            val searchData = searchParsed.optJSONObject("data") ?: JSONObject()
            val hits = searchData.optJSONArray("hits")

            // Step 2: Extract candidate IDs
            val candidateIds = mutableListOf<String>()
            if (hits != null) {
                for (i in 0 until hits.length()) {
                    val id = hits.optJSONObject(i)?.optString("id", "") ?: ""
                    if (id.isNotBlank()) candidateIds.add(id)
                }
            }

            if (candidateIds.isEmpty()) {
                return DiagnoseResult(
                        ok = true,
                        searchResultJson = searchOut,
                        decryptedCasesJson = null,
                        error = null
                )
            }

            // Step 3: Decrypt candidate cases
            val decryptOut = decryptCandidateCases(encryptedCasesJson, candidateIds)

            DiagnoseResult(
                    ok = true,
                    searchResultJson = searchOut,
                    decryptedCasesJson = decryptOut,
                    error = null
            )
        } catch (t: Throwable) {
            DiagnoseResult(
                    ok = false,
                    searchResultJson = null,
                    decryptedCasesJson = null,
                    error = "diagnose exception: ${t.message ?: t::class.java.simpleName}"
            )
        }
    }

    // ---------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------

    private fun nowUtcIso(): String {
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        return format.format(Date())
    }

    private fun todayLocalDateString(): String {
        val format = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        return format.format(Date())
    }

    private data class HostState(
            val usedDay: String,
            val usedToday: Int,
            val lastTrustedTimestamp: String?,
            val seenNonces: Set<String>,
            val wrappedCkBlobJson: String?,
    )

    private data class UnwrapResult(
            val ok: Boolean,
            val ckB64: String?,
            val errorJson: String?,
    )

    private fun loadState(): HostState {
        val usedDay = prefs.getString("used_day", "") ?: ""
        val usedToday = prefs.getInt("used_today", 0)
        val lastTrusted = prefs.getString("last_trusted_timestamp", null)
        val seenRaw = prefs.getStringSet("seen_nonces", emptySet()) ?: emptySet()
        val wrappedCkBlobJson = prefs.getString("wrapped_ck_blob_json", null)
        val seen = seenRaw.filter { it.isNotBlank() }.toSet()
        return HostState(
                usedDay = usedDay,
                usedToday = usedToday,
                lastTrustedTimestamp = lastTrusted?.takeIf { it.isNotBlank() },
                seenNonces = seen,
                wrappedCkBlobJson = wrappedCkBlobJson?.takeIf { it.isNotBlank() },
        )
    }

    private fun saveState(state: HostState) {
        prefs.edit()
                .putString("used_day", state.usedDay)
                .putInt("used_today", state.usedToday)
                .putString("last_trusted_timestamp", state.lastTrustedTimestamp)
                .putStringSet("seen_nonces", state.seenNonces)
                .putString("wrapped_ck_blob_json", state.wrappedCkBlobJson)
                .apply()
    }

    /**
     * Unwraps the current CK using the KEK from Android Keystore. The returned [UnwrapResult.ckB64]
     * should be used immediately and not stored in any long-lived field.
     */
    private fun unwrapCurrentCk(): UnwrapResult {
        val state = loadState()
        val wrappedBlobJson = state.wrappedCkBlobJson
        if (wrappedBlobJson.isNullOrBlank()) {
            return UnwrapResult(
                    ok = false,
                    ckB64 = null,
                    errorJson =
                            """{"ok":false,"error":"wrapped ck not initialized, call ensureWrappedCk first"}"""
            )
        }
        val kekB64 =
                try {
                    kekManager.getOrGenerateKekB64()
                } catch (t: Throwable) {
                    return UnwrapResult(
                            ok = false,
                            ckB64 = null,
                            errorJson =
                                    """{"ok":false,"error":"KEK unavailable: ${t.message ?: t::class.java.simpleName}"}"""
                    )
                }
        val req = JSONObject()
        req.put("wrapped_ck_blob", JSONObject(wrappedBlobJson))
        req.put("kek_b64", kekB64)
        val out = FfiBridge.unwrapCk(req.toString())
        val parsed = JSONObject(out)
        if (!parsed.optBoolean("ok", false)) {
            return UnwrapResult(ok = false, ckB64 = null, errorJson = out)
        }
        val ckB64 = parsed.optString("data", "")
        if (ckB64.isBlank()) {
            return UnwrapResult(
                    ok = false,
                    ckB64 = null,
                    errorJson = """{"ok":false,"error":"unwrap ck returned empty data"}"""
            )
        }
        return UnwrapResult(ok = true, ckB64 = ckB64, errorJson = null)
    }
}
