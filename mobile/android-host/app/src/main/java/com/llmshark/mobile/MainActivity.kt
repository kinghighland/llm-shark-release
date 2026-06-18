package com.llmshark.mobile

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.Menu
import android.view.MenuItem
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    // ============== 面板 ==============
    private lateinit var optionsPanel: View
    private lateinit var chatPanel: View
    private lateinit var settingsPanel: View
    private lateinit var aboutPanel: View

    // ============== 必选项控件 ==============
    private lateinit var callSideSpinner: Spinner
    // 两态复选框
    private lateinit var has183Check: CheckBox
    private lateinit var has180Check: CheckBox
    private lateinit var has200InviteCheck: CheckBox
    // 三态下拉框
    private lateinit var hasAck200Spinner: Spinner
    private lateinit var hasCancelSpinner: Spinner
    private lateinit var hasByeSpinner: Spinner
    // 文本输入
    private lateinit var sipResponseCodeInput: EditText
    private lateinit var sipTextInput: EditText

    // ============== 可选项控件 ==============
    private lateinit var sipProvisionalCodeInput: EditText
    private lateinit var halfConnectedSpinner: Spinner
    private lateinit var sipRetransSpinner: Spinner
    private lateinit var mediaTypeSpinner: Spinner
    private lateinit var mmEventSpinner: Spinner
    private lateinit var supplementaryServiceSpinner: Spinner

    // ============== 高级可选项控件 ==============
    private lateinit var dsmStateSpinner: Spinner

    // ============== 呼叫描述控件 ==============
    private lateinit var callDescriptionInput: EditText

    // ============== 操作按钮 ==============
    private lateinit var btnSearch: Button
    private lateinit var searchResultText: TextView
    private lateinit var btnDiagnose: Button
    // ============== 授权控件 (暂时隐藏) ==============
    // private lateinit var payloadInput: EditText
    // private lateinit var btnImport: Button
    // private lateinit var btnInitWrappedCk: Button
    private lateinit var statusText: TextView

    // ============== 聊天面板控件 ==============
    private lateinit var chatRecyclerView: RecyclerView
    private lateinit var chatInput: EditText
    private lateinit var btnSend: Button
    private lateinit var btnEndChat: Button
    private lateinit var btnClearChat: Button
    private lateinit var btnExecuteDiagnosis: Button
    private lateinit var roundCountText: TextView

    // ============== 设置面板控件 ==============
    private lateinit var endpointInput: EditText
    private lateinit var modelInput: EditText
    private lateinit var apiKeyInput: EditText
    private lateinit var btnValidateApi: Button
    private lateinit var btnSaveConfig: Button
    private lateinit var btnAutoFill: Button
    private lateinit var btnOpenInvite: Button
    private lateinit var validateStatusText: TextView
    private lateinit var languageSpinner: Spinner
    private lateinit var languageRestartHint: TextView
    
    // ============== 使用次数控件 ==============
    private lateinit var usageCountText: TextView
    
    // ============== 使用次数追踪器 ==============
    private lateinit var usageTracker: UsageTracker

    private lateinit var host: MobileAuthHost
    private lateinit var chatManager: LlmChatManager
    private lateinit var chatRepository: ChatRepository
    private lateinit var messageAdapter: MessageAdapter

    // Persisted parsed cases (from KB load)
    private var parsedCasesJson: String? = null

    // Last search result
    private var lastSearchResult: DiagnoseResult? = null
    private var lastDecryptedCasesText: String? = null

    // License state
    private var lastPlanTier: String? = null
    private var lastTopnLimit: Int? = null
    private var lastDailyLimit: Int? = null

    // Chat state
    private var currentConversationId: Long = -1
    private var currentRound: Int = 0
    private val maxRounds = 5
    private val chatMessages = mutableListOf<ChatMessage>()

    // DSM options based on call side (initialized lazily after I18nHelper is ready)
    private var callerDsmOptions: List<Pair<String, String?>> = emptyList()
    private var calleeDsmOptions: List<Pair<String, String?>> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize i18n first
        I18nHelper.init(this)
        initDsmOptions()

        host = MobileAuthHost(this)
        chatManager = LlmChatManager(this)
        chatRepository = ChatRepository(this)
        usageTracker = UsageTracker(this)

        initViews()
        setupActionBar()
        setupSpinners()
        setupListeners()
        loadConfig()
    }

    private fun initDsmOptions() {
        callerDsmOptions = listOf(
            I18nHelper.dsm("callerNotSelected") to null,
            I18nHelper.dsm("callerNoPrack") to "DSM: 未发送PRACK",
            I18nHelper.dsm("callerNoUpdate") to "DSM: 未发送UPDATE",
            I18nHelper.dsm("callerNo200Prack") to "DSM: 未收到200(PRACK)",
            I18nHelper.dsm("callerNo200Update") to "DSM: 未收到200(UPDATE)",
            I18nHelper.dsm("callerNo200Invite") to "DSM: 未收到摘机",
            I18nHelper.dsm("callerNo180") to "DSM: 未收到回铃"
        )
        calleeDsmOptions = listOf(
            I18nHelper.dsm("calleeNotSelected") to null,
            I18nHelper.dsm("calleeNoPrack") to "DSM: 未收到PRACK",
            I18nHelper.dsm("calleeNoUpdate") to "DSM: 未收到UPDATE",
            I18nHelper.dsm("calleeNo200Prack") to "DSM: 未回复200(PRACK)",
            I18nHelper.dsm("calleeNo200Update") to "DSM: 未回复200(UPDATE)",
            I18nHelper.dsm("calleeNo180") to "DSM: 未回铃",
            I18nHelper.dsm("calleeNo200Invite") to "DSM: 未摘机"
        )
    }

    private fun setupActionBar() {
        supportActionBar?.setDisplayShowHomeEnabled(false)
        supportActionBar?.setDisplayShowTitleEnabled(true)
        supportActionBar?.title = I18nHelper.app("title")
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> {
                showPanel("settings")
                true
            }
            R.id.action_about -> {
                showPanel("about")
                true
            }
            R.id.action_back -> {
                showPanel("options")
                true
            }
            R.id.action_back_to_options -> {
                showPanel("options")
                true
            }
            R.id.action_back_from_about -> {
                showPanel("options")
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    @Suppress("UNUSED_PARAMETER")
    private fun updateActionBar(panel: String) {
        // 根据当前面板更新ActionBar按钮
        invalidateOptionsMenu()
    }

    override fun onPrepareOptionsMenu(menu: Menu?): Boolean {
        // 根据当前面板显示/隐藏不同的菜单项
        menu?.findItem(R.id.action_settings)?.isVisible = (optionsPanel.visibility == View.VISIBLE)
        menu?.findItem(R.id.action_about)?.isVisible = (optionsPanel.visibility == View.VISIBLE)
        menu?.findItem(R.id.action_back)?.isVisible = (settingsPanel.visibility == View.VISIBLE)
        menu?.findItem(R.id.action_back_to_options)?.isVisible = (chatPanel.visibility == View.VISIBLE)
        menu?.findItem(R.id.action_back_from_about)?.isVisible = (aboutPanel.visibility == View.VISIBLE)
        return super.onPrepareOptionsMenu(menu)
    }

    private fun initViews() {
        // 面板
        optionsPanel = findViewById(R.id.optionsPanel)
        chatPanel = findViewById(R.id.chatPanel)
        settingsPanel = findViewById(R.id.settingsPanel)
        aboutPanel = findViewById(R.id.aboutPanel)

        // 必选项
        callSideSpinner = findViewById(R.id.callSideSpinner)
        // 两态复选框
        has183Check = findViewById(R.id.has183Check)
        has180Check = findViewById(R.id.has180Check)
        has200InviteCheck = findViewById(R.id.has200InviteCheck)
        // 三态下拉框
        hasAck200Spinner = findViewById(R.id.hasAck200Spinner)
        hasCancelSpinner = findViewById(R.id.hasCancelSpinner)
        hasByeSpinner = findViewById(R.id.hasByeSpinner)
        // 文本输入
        sipResponseCodeInput = findViewById(R.id.sipResponseCodeInput)
        sipTextInput = findViewById(R.id.sipTextInput)

        // 可选项
        sipProvisionalCodeInput = findViewById(R.id.sipProvisionalCodeInput)
        halfConnectedSpinner = findViewById(R.id.halfConnectedSpinner)
        sipRetransSpinner = findViewById(R.id.sipRetransSpinner)
        mediaTypeSpinner = findViewById(R.id.mediaTypeSpinner)
        mmEventSpinner = findViewById(R.id.mmEventSpinner)
        supplementaryServiceSpinner = findViewById(R.id.supplementaryServiceSpinner)

        // 高级可选项
        dsmStateSpinner = findViewById(R.id.dsmStateSpinner)

        // 呼叫描述
        callDescriptionInput = findViewById(R.id.callDescriptionInput)

        // 操作按钮
        btnSearch = findViewById(R.id.btnSearch)
        searchResultText = findViewById(R.id.searchResultText)
        btnDiagnose = findViewById(R.id.btnDiagnose)

        // 授权控件 (暂时隐藏，使用可空类型)
        // payloadInput = findViewById(R.id.payloadInput)
        // btnImport = findViewById(R.id.btnImport)
        // btnInitWrappedCk = findViewById(R.id.btnInitWrappedCk)
        statusText = findViewById(R.id.statusText)

        // 聊天面板
        chatRecyclerView = findViewById(R.id.chatRecyclerView)
        chatInput = findViewById(R.id.chatInput)
        btnSend = findViewById(R.id.btnSend)
        btnEndChat = findViewById(R.id.btnEndChat)
        btnClearChat = findViewById(R.id.btnClearChat)
        btnExecuteDiagnosis = findViewById(R.id.btnExecuteDiagnosis)
        roundCountText = findViewById(R.id.roundCountText)

        // 设置面板
        endpointInput = findViewById(R.id.endpointInput)
        modelInput = findViewById(R.id.modelInput)
        apiKeyInput = findViewById(R.id.apiKeyInput)
        btnValidateApi = findViewById(R.id.btnValidateApi)
        btnSaveConfig = findViewById(R.id.btnSaveConfig)
        btnAutoFill = findViewById(R.id.btnAutoFill)
        btnOpenInvite = findViewById(R.id.btnOpenInvite)
        validateStatusText = findViewById(R.id.validateStatusText)
        
        // 使用次数显示
        usageCountText = findViewById(R.id.usageCountText)
        
        // 语言选择器
        languageSpinner = findViewById(R.id.languageSpinner)
        languageRestartHint = findViewById(R.id.languageRestartHint)

        // 设置 RecyclerView
        messageAdapter = MessageAdapter()
        chatRecyclerView.layoutManager = LinearLayoutManager(this)
        chatRecyclerView.adapter = messageAdapter

        // Apply i18n to all views
        applyI18n()
    }

    /**
     * Apply i18n strings from I18nHelper to all UI elements.
     * Called after initViews() to override XML default strings.
     */
    private fun applyI18n() {
        // ============== 选项面板 ==============
        // 区块标题
        findViewById<TextView>(R.id.callInfoTitleText)?.text = I18nHelper.options("callInfoTitle")
        findViewById<TextView>(R.id.auxInfoTitleText)?.text = I18nHelper.options("auxInfoTitle")
        findViewById<TextView>(R.id.dsmTitleText)?.text = I18nHelper.options("dsmTitle")
        findViewById<TextView>(R.id.callDescTitleText)?.text = I18nHelper.options("callDescTitle")
        findViewById<TextView>(R.id.diagOpTitleText)?.text = I18nHelper.options("diagOpTitle")

        // 标签
        findViewById<TextView>(R.id.callSideLabelText)?.text = I18nHelper.options("callSide")
        findViewById<TextView>(R.id.responseCodeLabelText)?.text = I18nHelper.options("responseCode")
        findViewById<TextView>(R.id.sipTextLabelText)?.text = I18nHelper.options("sipText")
        findViewById<TextView>(R.id.provisionalCodeLabelText)?.text = I18nHelper.options("provisionalCode")

        // 复选框
        has183Check.text = I18nHelper.checkboxes("sip183")
        has180Check.text = I18nHelper.checkboxes("sip180")
        has200InviteCheck.text = I18nHelper.checkboxes("sip200")

        // 输入框 hint
        sipResponseCodeInput.hint = I18nHelper.options("responseCodeHint")
        sipTextInput.hint = I18nHelper.options("sipTextHint")
        sipProvisionalCodeInput.hint = I18nHelper.options("provisionalCodeHint")
        callDescriptionInput.hint = I18nHelper.options("callDescHint")

        // 按钮
        btnSearch.text = I18nHelper.buttons("search")
        btnDiagnose.text = I18nHelper.buttons("diagnose")
        statusText.text = I18nHelper.status("waiting")
        searchResultText.text = I18nHelper.status("searchResult", "count" to "0")

        // ============== 聊天面板 ==============
        btnExecuteDiagnosis.text = I18nHelper.buttons("executeDiagnosis")
        roundCountText.text = I18nHelper.chat("roundCount", "current" to "0", "max" to maxRounds.toString())
        btnEndChat.text = I18nHelper.buttons("endChat")
        btnClearChat.text = I18nHelper.buttons("clearChat")
        chatInput.hint = I18nHelper.chat("inputHint")
        btnSend.text = I18nHelper.buttons("send")

        // ============== 设置面板 ==============
        findViewById<TextView>(R.id.settingsApiTitleText)?.text = I18nHelper.settings("title")
        findViewById<TextView>(R.id.settingsEndpointLabelText)?.text = I18nHelper.settings("endpoint")
        endpointInput.hint = I18nHelper.settings("endpointHint")
        findViewById<TextView>(R.id.settingsModelLabelText)?.text = I18nHelper.settings("model")
        modelInput.hint = I18nHelper.settings("modelHint")
        findViewById<TextView>(R.id.settingsApiKeyLabelText)?.text = I18nHelper.settings("apiKey")
        apiKeyInput.hint = I18nHelper.settings("apiKeyHint")
        btnValidateApi.text = I18nHelper.settings("validate")
        btnSaveConfig.text = I18nHelper.settings("save")
        findViewById<TextView>(R.id.settingsQuickOpTitleText)?.text = I18nHelper.settings("quickOpTitle")
        btnAutoFill.text = I18nHelper.settings("autoFill")
        findViewById<TextView>(R.id.trialServiceHintText)?.text = I18nHelper.settings("trialHint")
        btnOpenInvite.text = I18nHelper.settings("openInvite")
        findViewById<TextView>(R.id.newUserHintText)?.text = I18nHelper.settings("newUserHint")
        findViewById<TextView>(R.id.settingsLanguageTitleText)?.text = I18nHelper.settings("languageTitle")
        findViewById<TextView>(R.id.settingsLanguageLabelText)?.text = I18nHelper.settings("language")
        languageRestartHint.text = I18nHelper.settings("languageRestartHint")

        // ============== 关于面板 ==============
        findViewById<TextView>(R.id.aboutTitleText)?.text = I18nHelper.about("title")
        findViewById<TextView>(R.id.aboutSubtitleText)?.text = I18nHelper.about("subtitle")
        findViewById<TextView>(R.id.aboutTaglineText)?.text = I18nHelper.about("tagline")
        // aboutVersionText is set separately with version info
        findViewById<TextView>(R.id.aboutDeveloperText)?.text = I18nHelper.about("developer")
        findViewById<TextView>(R.id.aboutDesktopTitleText)?.text = I18nHelper.about("desktopTitle")
        findViewById<TextView>(R.id.aboutDesktopDescText)?.text = I18nHelper.about("desktopDesc")
        findViewById<TextView>(R.id.aboutStoreHintText)?.text = I18nHelper.about("storeHint")
    }

    /**
     * Apply language change immediately without restarting the app.
     * Re-initializes I18nHelper and refreshes all UI elements.
     */
    private fun applyLanguageChange() {
        // Force I18nHelper to reload strings for the new locale
        I18nHelper.forceReload(this)

        // Refresh all UI text
        applyI18n()

        // Refresh spinners (options are locale-dependent)
        initDsmOptions()
        setupSpinners()

        // Refresh ActionBar title
        setupActionBar()

        // Refresh menu items
        invalidateOptionsMenu()

        // Refresh about version text
        val versionText = findViewById<TextView>(R.id.aboutVersionText)
        try {
            val packageInfo = packageManager.getPackageInfo(packageName, 0)
            versionText.text = I18nHelper.about("version").replace("{version}", packageInfo.versionName)
        } catch (e: Exception) {
            versionText.text = I18nHelper.about("version").replace("{version}", "1.0.x")
        }

        // Refresh usage count text
        updateUsageCountText()

        // Hide the restart hint (no longer needed)
        languageRestartHint.visibility = View.GONE
    }

    private fun setupSpinners() {
        // 呼叫侧
        callSideSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.options("callSideSelect"), I18nHelper.options("callSideCaller"), I18nHelper.options("callSideCallee"))
        )

        // SIP ACK (三态下拉框)
        hasAck200Spinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("ackDontCare"), I18nHelper.spinners("ackPresent"), I18nHelper.spinners("ackAbsent"))
        )

        // SIP CANCEL (三态下拉框)
        hasCancelSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("cancelDontCare"), I18nHelper.spinners("cancelPresent"), I18nHelper.spinners("cancelAbsent"))
        )

        // SIP BYE (三态下拉框)
        hasByeSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("byeDontCare"), I18nHelper.spinners("byePresent"), I18nHelper.spinners("byeAbsent"))
        )

        // SIP 半接通
        halfConnectedSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("halfConnected"), I18nHelper.spinners("halfConnectedYes"))
        )

        // SIP 重传
        sipRetransSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("retransDontCare"), I18nHelper.spinners("retransUplink"), I18nHelper.spinners("retransDownlink"), I18nHelper.spinners("retransBoth"))
        )

        // SIP 放音
        mediaTypeSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("mediaDontCare"), I18nHelper.spinners("media183"), I18nHelper.spinners("mediaUpdate"))
        )

        // 移动管理 MM
        mmEventSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("mmDontCare"), I18nHelper.spinners("mmDetach"), I18nHelper.spinners("mmTau"), I18nHelper.spinners("mmCsfb"), I18nHelper.spinners("mmIratHo"), I18nHelper.spinners("mmRegistration"), I18nHelper.spinners("mmDeregistration"))
        )

        // 补充业务 SS
        supplementaryServiceSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf(I18nHelper.spinners("ssDontCare"), I18nHelper.spinners("ssCf"), I18nHelper.spinners("ssCw"), I18nHelper.spinners("ssHold"), I18nHelper.spinners("ssConf"))
        )

        // DSM 状态 (默认显示主叫侧选项)
        updateDsmSpinner(I18nHelper.options("callSideCaller"))

        // 呼叫侧变化时更新 DSM 选项（放在 setupSpinners 末尾，确保 applyLanguageChange 后也能重新注册）
        val callerText = I18nHelper.options("callSideCaller")
        val calleeText = I18nHelper.options("callSideCallee")
        callSideSpinner.setOnItemSelectedListener(object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                val selected = parent?.getItemAtPosition(position) as? String ?: ""
                if (selected == callerText || selected == calleeText) {
                    updateDsmSpinner(selected)
                }
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        })
    }

    private fun updateDsmSpinner(callSide: String) {
        val calleeText = I18nHelper.options("callSideCallee")
        val options = if (callSide == calleeText) calleeDsmOptions else callerDsmOptions
        dsmStateSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            options.map { it.first }
        )
    }

    private fun setupListeners() {
        // 检索按钮
        btnSearch.setOnClickListener {
            performSearch()
        }

        // 诊断按钮
        btnDiagnose.setOnClickListener {
            performDiagnose()
        }

        // 授权验证 (暂时隐藏)
        /*
        btnImport.setOnClickListener {
            try {
                val payload = payloadInput.text?.toString()?.trim().orEmpty()
                if (payload.isEmpty()) {
                    statusText.text = "payload 为空"
                    return@setOnClickListener
                }

                val result = host.importPayloadAndBuildPolicy(payload)
                statusText.text = buildString {
                    appendLine("验证结果: ${if (result.ok) "成功" else "失败"}")
                    if (result.ok) {
                        val verifyRoot = JSONObject(result.verifyResponseJson)
                        val data = verifyRoot.optJSONObject("data") ?: JSONObject()
                        lastPlanTier = data.optString("plan_tier")
                        lastTopnLimit = data.optInt("topn_limit")
                        lastDailyLimit = data.optInt("daily_analysis_limit")
                        appendLine("计划: $lastPlanTier, TopN: $lastTopnLimit, 每日限额: $lastDailyLimit")
                    } else {
                        appendLine(result.verifyResponseJson.take(500))
                    }
                }
            } catch (t: Throwable) {
                statusText.text = "授权异常: ${t.message ?: t::class.java.simpleName}"
            }
        }

        // 初始化密钥
        btnInitWrappedCk.setOnClickListener {
            try {
                val initOut = host.ensureWrappedCk()
                statusText.text = buildString {
                    appendLine("密钥初始化: ${if (initOut.ok) "成功" else "失败"}")
                    if (!initOut.ok) {
                        appendLine(initOut.responseJson.take(500))
                    }
                }
            } catch (t: Throwable) {
                statusText.text = "密钥初始化异常: ${t.message ?: t::class.java.simpleName}"
            }
        }
        */

        // ============== 聊天面板监听器 ==============

        // 执行诊断按钮
        btnExecuteDiagnosis.setOnClickListener {
            startDiagnosis()
        }

        // 发送按钮
        btnSend.setOnClickListener {
            sendChatMessage()
        }

        // 结束对话按钮
        btnEndChat.setOnClickListener {
            endChat()
        }

        // 清除对话按钮
        btnClearChat.setOnClickListener {
            clearChat()
        }

        // ============== 设置面板监听器 ==============

        // 验证 API
        btnValidateApi.setOnClickListener {
            validateApi()
        }

        // 保存配置
        btnSaveConfig.setOnClickListener {
            saveConfig()
        }

        // 恢复默认参数（使用内置试用服务）
        btnAutoFill.setOnClickListener {
            useTrialService()
        }

        // 打开邀请链接
        btnOpenInvite.setOnClickListener {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(LlmDefaults.INVITE_URL))
            startActivity(intent)
        }

        // ============== 语言选择器 ==============
        
        // 初始化语言选择器
        val languageOptions = I18nHelper.SUPPORTED_LANGUAGES.map { it.second }
        languageSpinner.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            languageOptions
        )
        
        // 设置当前选中的语言
        val currentLang = I18nHelper.getSelectedLanguage()
        val langIndex = I18nHelper.SUPPORTED_LANGUAGES.indexOfFirst { it.first == currentLang }
        if (langIndex >= 0) {
            languageSpinner.setSelection(langIndex)
        }
        
        // 语言选择监听器
        languageSpinner.setOnItemSelectedListener(object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                val selectedLangCode = I18nHelper.SUPPORTED_LANGUAGES[position].first
                if (selectedLangCode != I18nHelper.getSelectedLanguage()) {
                    I18nHelper.setSelectedLanguage(selectedLangCode)
                    applyLanguageChange()
                }
            }
            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        })

        // ============== 关于面板初始化 ==============

        // 设置版本号
        val versionText = findViewById<TextView>(R.id.aboutVersionText)
        try {
            val packageInfo = packageManager.getPackageInfo(packageName, 0)
            versionText.text = I18nHelper.about("version").replace("{version}", packageInfo.versionName)
        } catch (e: Exception) {
            versionText.text = I18nHelper.about("version").replace("{version}", "1.0.x")
        }

        // 微软商店链接点击
        val storeLink = findViewById<TextView>(R.id.aboutStoreLink)
        storeLink.setOnClickListener {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://apps.microsoft.com/detail/9NJQ6N01CF65"))
            startActivity(intent)
        }
    }

    // ============== 面板切换 ==============

    private fun showPanel(panel: String) {
        optionsPanel.visibility = if (panel == "options") View.VISIBLE else View.GONE
        chatPanel.visibility = if (panel == "chat") View.VISIBLE else View.GONE
        settingsPanel.visibility = if (panel == "settings") View.VISIBLE else View.GONE
        aboutPanel.visibility = if (panel == "about") View.VISIBLE else View.GONE
        updateActionBar(panel)
    }

    // ============== 搜索和诊断 ==============

    private fun performSearch() {
        // 验证呼叫侧必须选择
        val callerText = I18nHelper.options("callSideCaller")
        val calleeText = I18nHelper.options("callSideCallee")
        val callSideRaw = callSideSpinner.selectedItem as? String ?: ""
        if (callSideRaw != callerText && callSideRaw != calleeText) {
            statusText.text = I18nHelper.status("selectCallSideFirst")
            return
        }
        
        statusText.text = I18nHelper.status("searching")
        
        try {
            val casesJson = loadOrParseKb()
            if (casesJson == null) {
                return
            }

            val ckInit = host.ensureWrappedCk()
            if (!ckInit.ok) {
                statusText.text = I18nHelper.status("keyNotInit", "error" to ckInit.responseJson.take(400))
                return
            }

            val query = buildQueryFromInputs()
            val topn = lastTopnLimit ?: 10

            // 输出查询参数日志
            android.util.Log.d("SearchDebug", "=== 搜索参数 ===")
            android.util.Log.d("SearchDebug", "query.toJson: ${query.toJson()}")
            android.util.Log.d("SearchDebug", "topn: $topn")
            android.util.Log.d("SearchDebug", "casesJson length: ${casesJson.length}")

            val searchOut = host.searchCases(casesJson, query, topn)
            android.util.Log.d("SearchDebug", "searchOut: ${searchOut.take(2000)}")

            val searchParsed = JSONObject(searchOut)

            if (!searchParsed.optBoolean("ok", false)) {
                statusText.text = I18nHelper.status("searchFailed", "error" to searchParsed.optString("error", "Unknown error"))
                return
            }

            val searchData = searchParsed.optJSONObject("data") ?: JSONObject()
            val hits = searchData.optJSONArray("hits") ?: org.json.JSONArray()
            val hitCount = hits.length()

            // 从 trace 中获取截断前的真实匹配数量
            val trace = searchData.optJSONArray("trace")
            val totalMatches = if (trace != null && trace.length() > 0) {
                // 查找 sort_and_truncate 步骤的 before 值
                var total = hitCount
                for (i in 0 until trace.length()) {
                    val step = trace.optJSONObject(i)
                    if (step?.optString("step") == "sort_and_truncate") {
                        total = step.optInt("before", hitCount)
                        break
                    }
                }
                total
            } else {
                hitCount
            }

            // 输出 trace 日志
            if (trace != null) {
                android.util.Log.d("SearchDebug", "=== 搜索轨迹 ===")
                for (i in 0 until trace.length()) {
                    val step = trace.optJSONObject(i)
                    android.util.Log.d("SearchDebug", "step=${step?.optString("step")}, " +
                        "criteria=${step?.optString("criteria")}, " +
                        "before=${step?.optInt("before")}, " +
                        "after=${step?.optInt("after")}, " +
                        "applied=${step?.optBoolean("applied")}")
                }
            }

            searchResultText.text = if (totalMatches > 10) {
                I18nHelper.status("searchResultWithMore", "count" to totalMatches.toString())
            } else {
                I18nHelper.status("searchResult", "count" to totalMatches.toString())
            }

            if (hitCount > 0) {
                btnDiagnose.isEnabled = true
                btnDiagnose.text = I18nHelper.buttons("diagnose")
                statusText.text = if (totalMatches > 10) {
                    I18nHelper.status("foundCasesTruncated", "count" to totalMatches.toString(), "topn" to "10")
                } else {
                    I18nHelper.status("foundCases", "count" to totalMatches.toString())
                }
                
                // 保存搜索结果，供诊断使用
                lastSearchResult = DiagnoseResult(
                    ok = true,
                    searchResultJson = searchOut,
                    decryptedCasesJson = null,
                    error = null
                )
            } else {
                btnDiagnose.isEnabled = false
                btnDiagnose.text = I18nHelper.buttons("diagnose")
                statusText.text = I18nHelper.status("noMatch")
                lastSearchResult = null
            }

        } catch (t: Throwable) {
            statusText.text = I18nHelper.status("searchError", "error" to "${t.message ?: t::class.java.simpleName}\n${t.stackTraceToString().take(500)}")
        }
    }

    private fun performDiagnose() {
        try {
            // 使用搜索结果中的案例
            val searchResult = lastSearchResult
            if (searchResult == null || searchResult.searchResultJson == null) {
                statusText.text = I18nHelper.status("pleaseSearchFirst")
                return
            }

            // 从搜索结果中提取案例内容（如果还没有提取）
            if (lastDecryptedCasesText.isNullOrEmpty()) {
                lastDecryptedCasesText = extractCasesTextFromSearchResult(searchResult.searchResultJson)
            }

            // 切换到聊天面板
            showPanel("chat")

            // 判断是否已有对话内容
            if (chatMessages.isEmpty()) {
                // 初次诊断：自动执行诊断
                startDiagnosis(isAutoCall = true)
            } else {
                // 已有内容：闪烁"执行诊断"按钮提示用户
                flashExecuteDiagnosisButton()
            }

        } catch (t: Throwable) {
            statusText.text = I18nHelper.status("diagnoseError", "error" to (t.message ?: t::class.java.simpleName))
        }
    }

    /**
     * 闪烁"执行诊断"按钮两次
     */
    private fun flashExecuteDiagnosisButton() {
        val handler = android.os.Handler(mainLooper)
        var flashCount = 0
        val maxFlashes = 4 // 闪烁两次 = 4次状态切换

        val flashRunnable = object : Runnable {
            override fun run() {
                if (flashCount < maxFlashes) {
                    // 切换按钮高亮状态
                    btnExecuteDiagnosis.isPressed = (flashCount % 2 == 0)
                    flashCount++
                    handler.postDelayed(this, 200) // 200ms 间隔
                } else {
                    // 恢复正常状态
                    btnExecuteDiagnosis.isPressed = false
                }
            }
        }

        handler.post(flashRunnable)
    }

    /**
     * 从搜索结果中提取案例文本
     */
    private fun extractCasesTextFromSearchResult(searchResultJson: String?): String {
        if (searchResultJson == null) return ""
        
        return try {
            val parsed = JSONObject(searchResultJson)
            val data = parsed.optJSONObject("data") ?: return ""
            val hits = data.optJSONArray("hits") ?: return ""
            
            val sb = StringBuilder()
            for (i in 0 until hits.length()) {
                val hit = hits.optJSONObject(i) ?: continue
                val caseId = hit.optString("id", "?") ?: "?"
                val score = hit.optDouble("score", 0.0)
                
                // 从 hit 中提取案例内容
                // hit 结构包含: id, score, 以及案例的各个字段
                val caseContent = buildCaseContentFromHit(hit)
                sb.append("案例 $caseId (相关度: ${String.format("%.2f", score)}):\n")
                sb.append(caseContent)
                sb.append("\n\n")
            }
            
            sb.toString().trim()
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * 从搜索命中结果构建案例内容
     */
    private fun buildCaseContentFromHit(hit: JSONObject): String {
        val sb = StringBuilder()
        
        // 提取案例的各个字段
        val fields = listOf(
            "call_side" to "呼叫侧",
            "symptom" to "故障现象",
            "root_cause" to "根因分析",
            "diagnosis" to "诊断结论",
            "solution" to "解决方案",
            "notes" to "备注"
        )
        
        for ((field, label) in fields) {
            val value = hit.optString(field, "")
            if (!value.isNullOrEmpty() && value != "null") {
                sb.append("$label: $value\n")
            }
        }
        
        return sb.toString().trim()
    }

    private fun extractCasesText(decryptedCasesJson: String?): String {
        if (decryptedCasesJson == null) return ""
        
        return try {
            val parsed = JSONObject(decryptedCasesJson)
            if (!parsed.optBoolean("ok", false)) return ""
            
            val cases = parsed.optJSONArray("data") ?: return ""
            val sb = StringBuilder()
            
            for (i in 0 until cases.length()) {
                val case = cases.optJSONObject(i)
                val caseId = case?.optString("case_id", "?") ?: "?"
                val plaintext = case?.optString("plaintext", "") ?: ""
                sb.append("案例 $caseId:\n$plaintext\n\n")
            }
            
            sb.toString().trim()
        } catch (e: Exception) {
            ""
        }
    }

    // ============== 聊天功能 ==============

    // 保存系统提示词，用于追问时构建消息
    private var systemPromptForFollowUp: String? = null

    private fun initChat() {
        currentRound = 0
        chatMessages.clear()
        messageAdapter.clearMessages()
        systemPromptForFollowUp = null  // 清空系统提示词
        updateRoundCount()
        btnSend.isEnabled = false  // 初始禁用发送按钮，等诊断完成后启用
        chatInput.setText("")

        // 重置执行诊断按钮
        btnExecuteDiagnosis.isEnabled = true
        btnExecuteDiagnosis.text = I18nHelper.buttons("executeDiagnosis")
        
        // 创建新对话记录
        val queryJson = buildQueryFromInputs().toJson().toString()
        val caseIds = extractCaseIds(lastSearchResult)
        currentConversationId = chatRepository.createConversation(queryJson, caseIds)
    }

    private fun extractCaseIds(result: DiagnoseResult?): List<String> {
        if (result == null || result.searchResultJson == null) return emptyList()
        
        return try {
            val parsed = JSONObject(result.searchResultJson)
            val data = parsed.optJSONObject("data") ?: return emptyList()
            val hits = data.optJSONArray("hits") ?: return emptyList()
            
            val ids = mutableListOf<String>()
            for (i in 0 until hits.length()) {
                val hit = hits.optJSONObject(i)
                val id = hit?.optString("id", "") ?: ""
                if (id.isNotEmpty()) ids.add(id)
            }
            ids
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun startDiagnosis() {
        startDiagnosis(isAutoCall = false)
    }

    /**
     * 获取并过滤呼叫描述文本
     * 过滤规则：
     * 1. '<' 和 '>' - 可能与 prompt 占位符格式冲突
     * 2. 不可见控制字符 (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F)
     */
    private fun getSanitizedCallDescription(): String {
        val raw = callDescriptionInput.text?.toString()?.trim() ?: ""
        if (raw.isEmpty()) return ""
        
        return raw.filter { char ->
            // 过滤 '<' 和 '>'
            char != '<' && char != '>' &&
            // 过滤不可见控制字符（保留 \n \r \t）
            !(char.code in 0x00..0x08 || char.code == 0x0B || char.code == 0x0C || char.code in 0x0E..0x1F)
        }
    }

    private fun startDiagnosis(isAutoCall: Boolean) {
        // 检查是否已有对话（避免重复执行）- 自动调用时跳过此检查
        if (!isAutoCall && chatMessages.isNotEmpty()) {
            Toast.makeText(this, I18nHelper.toast("diagnosisExists"), Toast.LENGTH_SHORT).show()
            return
        }

        // 检查案例知识是否已加载
        if (lastDecryptedCasesText.isNullOrEmpty()) {
            Toast.makeText(this, I18nHelper.toast("kbNotLoaded"), Toast.LENGTH_SHORT).show()
            return
        }
        
        // 检查使用次数限制（仅对内置服务）
        val isUsingOwnKey = !isUsingTrialKey()
        if (!isUsingOwnKey) {
            if (!usageTracker.canUseTrialService()) {
                Toast.makeText(this, I18nHelper.usage("trialExhausted"), Toast.LENGTH_LONG).show()
                return
            }
        }

        // 禁用执行诊断按钮，防止重复点击
        btnExecuteDiagnosis.isEnabled = false
        btnExecuteDiagnosis.text = I18nHelper.buttons("diagnosing")

        // 构建完整提示词
        val queryJson = buildQueryFromInputs().toJson().toString()
        val casesText = lastDecryptedCasesText ?: ""
        val callDescription = getSanitizedCallDescription()
        val fullPrompt = chatManager.buildPrompt(queryJson, casesText, callDescription, I18nHelper.getEffectiveLocaleCode())

        // 保存系统提示词，用于后续追问
        systemPromptForFollowUp = fullPrompt

        // 初始诊断：把整个 prompt 作为单条 user 消息发送（与桌面版 llm_analyze_stream 一致）
        chatMessages.add(ChatMessage(role = "user", content = fullPrompt))
        
        // 增加使用次数（仅对内置服务）
        if (!isUsingOwnKey) {
            usageTracker.incrementCount()
            updateUsageCountText()
        }

        // 发送初始请求
        sendLlmRequest(isInitialDiagnosis = true)
    }

    private fun sendChatMessage() {
        val userMessage = chatInput.text?.toString()?.trim() ?: ""
        if (userMessage.isEmpty()) return

        // 检查轮数限制
        if (currentRound >= maxRounds) {
            Toast.makeText(this, I18nHelper.toast("roundLimitReached").replace("{max}", maxRounds.toString()), Toast.LENGTH_SHORT).show()
            return
        }

        // 添加用户消息
        chatMessages.add(ChatMessage(role = "user", content = userMessage))
        messageAdapter.addMessage(DisplayMessage(role = "user", content = userMessage))
        
        // 保存到数据库
        chatRepository.addMessage(currentConversationId, "user", userMessage)
        
        // 清空输入框
        chatInput.setText("")
        
        // 更新轮数
        currentRound++
        updateRoundCount()

        // 发送 LLM 请求（追问模式）
        sendLlmRequest(isInitialDiagnosis = false)
    }

    private fun sendLlmRequest(isInitialDiagnosis: Boolean) {
        btnSend.isEnabled = false
        
        val config = chatManager.getConfig()
        
        // 构建发送给 LLM 的消息
        val messagesToSend = if (isInitialDiagnosis) {
            // 初始诊断：直接发送 chatMessages（包含完整 prompt 作为 user 消息）
            chatMessages.toList()
        } else {
            // 追问模式：构建 system + user/assistant 序列
            buildFollowUpMessages()
        }
        
        // 用于累积流式响应内容
        val accumulatedContent = StringBuilder()
        var assistantMessageIndex = -1
        
        // 先添加一个空的助手消息占位符，用于流式更新
        runOnUiThread {
            messageAdapter.addMessage(DisplayMessage(role = "assistant", content = ""))
            assistantMessageIndex = messageAdapter.itemCount - 1
        }
        
        chatManager.chatStream(
            config = config,
            messages = messagesToSend,
            streamCallback = object : LlmStreamCallback {
                override fun onChunk(chunk: String) {
                    runOnUiThread {
                        // 累积内容
                        accumulatedContent.append(chunk)
                        
                        // 流式期间直接显示原始文本，不解析 section，避免闪烁和重复显示
                        if (assistantMessageIndex >= 0) {
                            messageAdapter.updateMessage(assistantMessageIndex, DisplayMessage(role = "assistant", content = accumulatedContent.toString()))
                            chatRecyclerView.scrollToPosition(assistantMessageIndex)
                        }
                    }
                }
            },
            callback = object : LlmCallback {
                override fun onSuccess(content: String) {
                    runOnUiThread {
                        // 添加助手消息到历史（使用累积的完整内容）
                        val fullContent = accumulatedContent.toString()
                        chatMessages.add(ChatMessage(role = "assistant", content = fullContent))
                        
                        // 保存到数据库
                        chatRepository.addMessage(currentConversationId, "assistant", fullContent)
                        
                        // 流式结束后解析完整内容并更新显示
                        if (assistantMessageIndex >= 0) {
                            val displayMessage = DisplayMessage.fromLlmResponse("assistant", fullContent)
                            messageAdapter.updateMessage(assistantMessageIndex, displayMessage)
                        }
                        
                        // 滚动到底部
                        chatRecyclerView.scrollToPosition(messageAdapter.itemCount - 1)
                        
                        // 恢复发送按钮
                        btnSend.isEnabled = currentRound < maxRounds
                        
                        // 更新执行诊断按钮状态
                        if (isInitialDiagnosis) {
                            btnExecuteDiagnosis.text = I18nHelper.buttons("diagnosisComplete")
                        }
                    }
                }

                override fun onError(error: String) {
                    runOnUiThread {
                        Toast.makeText(this@MainActivity, I18nHelper.errors("llmError", "error" to error), Toast.LENGTH_LONG).show()
                        btnSend.isEnabled = true
                        
                        // 如果有部分内容，保留它
                        if (accumulatedContent.isNotEmpty()) {
                            chatMessages.add(ChatMessage(role = "assistant", content = accumulatedContent.toString()))
                        } else if (assistantMessageIndex >= 0) {
                            // 移除空的占位消息
                            messageAdapter.removeMessage(assistantMessageIndex)
                        }
                        
                        // 恢复执行诊断按钮
                        if (isInitialDiagnosis) {
                            btnExecuteDiagnosis.isEnabled = true
                            btnExecuteDiagnosis.text = I18nHelper.buttons("executeDiagnosis")
                        }
                    }
                }
            }
        )
    }

    /**
     * 构建追问模式的消息序列
     * 格式：system(prompt) + user/assistant 对话历史（不含初始的完整 prompt）
     */
    private fun buildFollowUpMessages(): List<ChatMessage> {
        val result = mutableListOf<ChatMessage>()
        
        // 添加系统消息（完整 prompt）
        systemPromptForFollowUp?.let { prompt ->
            result.add(ChatMessage(role = "system", content = prompt))
        }
        
        // 添加对话历史（跳过第一条 user 消息，因为那是初始的完整 prompt）
        // chatMessages 格式：[user(fullPrompt), assistant(response), user(followUp1), assistant(response1), ...]
        // 需要发送：[system(prompt), user(followUp1), assistant(response1), ...]
        // 但由于 LLM 已经在初始诊断时看到了 prompt 和第一次响应，我们需要保留这个上下文
        // 所以发送：[system(prompt), assistant(firstResponse), user(followUp1), ...]
        
        if (chatMessages.size > 1) {
            // 跳过第一条 user 消息（完整 prompt），从 assistant 响应开始
            for (i in 1 until chatMessages.size) {
                result.add(chatMessages[i])
            }
        }
        
        return result
    }

    private fun endChat() {
        // 更新对话标题
        if (currentConversationId > 0 && messageAdapter.itemCount > 0) {
            val firstMessage = messageAdapter.getMessages().firstOrNull()?.content ?: ""
            val title = firstMessage.take(50) + if (firstMessage.length > 50) "..." else ""
            chatRepository.updateTitle(currentConversationId, title)
        }
        
        // 重置状态
        currentConversationId = -1
        currentRound = 0
        chatMessages.clear()
        
        // 返回选项面板
        showPanel("options")
    }

    /**
     * 清除对话：清空界面显示、删除数据库记录、重置诊断状态
     */
    private fun clearChat() {
        // 删除数据库中的对话记录
        if (currentConversationId > 0) {
            chatRepository.deleteConversation(currentConversationId)
        }
        
        // 清空界面和内存状态
        currentConversationId = -1
        currentRound = 0
        chatMessages.clear()
        messageAdapter.clearMessages()
        systemPromptForFollowUp = null
        
        // 重置诊断状态
        updateRoundCount()
        btnSend.isEnabled = false
        chatInput.setText("")
        btnExecuteDiagnosis.isEnabled = true
        btnExecuteDiagnosis.text = I18nHelper.buttons("executeDiagnosis")
        
        Toast.makeText(this, I18nHelper.toast("chatCleared"), Toast.LENGTH_SHORT).show()
    }

    private fun updateRoundCount() {
        roundCountText.text = I18nHelper.chat("roundCount", "current" to currentRound.toString(), "max" to maxRounds.toString())
    }
    
    // ============== 使用次数相关 ==============
    
    /**
     * 检查是否使用内置试用服务
     */
    private fun isUsingTrialKey(): Boolean {
        val config = chatManager.getConfig()
        return config.apiKey == LlmDefaults.TRIAL_KEY_PLACEHOLDER || config.apiKey.isBlank()
    }
    
    /**
     * 更新使用次数显示
     */
    private fun updateUsageCountText() {
        val isUsingOwnKey = !isUsingTrialKey()
        usageCountText.text = usageTracker.getStatusText(isUsingOwnKey)
    }

    // ============== 设置功能 ==============

    private fun loadConfig() {
        val config = chatManager.getConfig()
        endpointInput.setText(config.endpoint)
        modelInput.setText(config.model)
        apiKeyInput.setText(config.apiKey)
        
        // 更新使用次数显示
        updateUsageCountText()
    }

    private fun saveConfig() {
        val config = LlmConfig(
            endpoint = endpointInput.text?.toString()?.trim() ?: LlmDefaults.ENDPOINT,
            model = modelInput.text?.toString()?.trim() ?: LlmDefaults.MODEL,
            apiKey = apiKeyInput.text?.toString()?.trim() ?: LlmDefaults.TRIAL_KEY_PLACEHOLDER
        )
        chatManager.saveConfig(config)
        Toast.makeText(this, I18nHelper.settings("configSaved"), Toast.LENGTH_SHORT).show()
        
        // 更新使用次数显示
        updateUsageCountText()
    }

    private fun validateApi() {
        val config = LlmConfig(
            endpoint = endpointInput.text?.toString()?.trim() ?: LlmDefaults.ENDPOINT,
            model = modelInput.text?.toString()?.trim() ?: LlmDefaults.MODEL,
            apiKey = apiKeyInput.text?.toString()?.trim() ?: ""
        )
        
        validateStatusText.text = I18nHelper.settings("validating")
        
        chatManager.validateConfig(config, object : LlmValidateCallback {
            override fun onSuccess(message: String) {
                runOnUiThread {
                    validateStatusText.text = I18nHelper.settings("validateSuccess")
                }
            }

            override fun onError(error: String) {
                runOnUiThread {
                    validateStatusText.text = I18nHelper.settings("validateFail").replace("{error}", error)
                }
            }
        })
    }

    private fun useTrialService() {
        endpointInput.setText(LlmDefaults.ENDPOINT)
        modelInput.setText(LlmDefaults.MODEL)
        apiKeyInput.setText(LlmDefaults.TRIAL_KEY_PLACEHOLDER)
        Toast.makeText(this, I18nHelper.settings("autoFillSuccess"), Toast.LENGTH_SHORT).show()
        
        // 更新使用次数显示
        updateUsageCountText()
    }

    // ============== 辅助方法 ==============

    private fun buildQueryFromInputs(): CaseQueryInput {
        val callerText = I18nHelper.options("callSideCaller")
        val calleeText = I18nHelper.options("callSideCallee")
        val callSideRaw = callSideSpinner.selectedItem as? String ?: ""
        val callSide = when (callSideRaw) {
            callerText -> "caller"
            calleeText -> "callee"
            else -> null
        }

        val dsmPosition = dsmStateSpinner.selectedItemPosition
        val dsmOptions = if (callSideRaw == calleeText) calleeDsmOptions else callerDsmOptions
        val dsmState = if (dsmPosition in dsmOptions.indices && dsmPosition > 0) {
            dsmOptions[dsmPosition].second
        } else null

        // SIP 重传：精确匹配 i18n 选项文本，避免语言敏感的字符串切分
        val retransRaw = sipRetransSpinner.selectedItem as? String ?: ""
        val sipRetrans = when (retransRaw) {
            I18nHelper.spinners("retransDontCare") -> null
            I18nHelper.spinners("retransUplink") -> "uplink"
            I18nHelper.spinners("retransDownlink") -> "downlink"
            I18nHelper.spinners("retransBoth") -> "both"
            else -> null
        }

        val mediaRaw = mediaTypeSpinner.selectedItem as? String ?: ""
        val mediaType = when {
            mediaRaw.contains("183") -> "183"
            mediaRaw.contains("UPDATE") -> "UPDATE"
            else -> null
        }

        // SIP 半接通
        val halfConnectedRaw = halfConnectedSpinner.selectedItem as? String ?: ""
        val halfConnected = if (halfConnectedRaw == I18nHelper.spinners("halfConnectedYes")) "半接通状态" else null

        val mmRaw = mmEventSpinner.selectedItem as? String ?: ""
        val mmEvent = if (mmRaw.contains(I18nHelper.spinners("mmDontCare").split(":").first())) null else mmRaw

        val ssRaw = supplementaryServiceSpinner.selectedItem as? String ?: ""
        val supplementaryService = when {
            ssRaw.contains(I18nHelper.spinners("ssDontCare").split(":").first()) -> null
            ssRaw == I18nHelper.spinners("ssConf") -> "多方会议"
            ssRaw == I18nHelper.spinners("ssCf") -> "CF"
            ssRaw == I18nHelper.spinners("ssCw") -> "CW"
            ssRaw == I18nHelper.spinners("ssHold") -> "Hold"
            else -> null
        }

        // SIP ACK/CANCEL/BYE 下拉框
        val ackRaw = hasAck200Spinner.selectedItem as? String ?: ""
        val hasAck200 = when {
            ackRaw == I18nHelper.spinners("ackPresent") -> true
            ackRaw == I18nHelper.spinners("ackAbsent") -> false
            else -> null
        }

        val cancelRaw = hasCancelSpinner.selectedItem as? String ?: ""
        val hasCancel = when {
            cancelRaw == I18nHelper.spinners("cancelPresent") -> true
            cancelRaw == I18nHelper.spinners("cancelAbsent") -> false
            else -> null
        }

        val byeRaw = hasByeSpinner.selectedItem as? String ?: ""
        val hasBye = when {
            byeRaw == I18nHelper.spinners("byePresent") -> true
            byeRaw == I18nHelper.spinners("byeAbsent") -> false
            else -> null
        }

        return CaseQueryInput(
            callSide = callSide,
            // 两态复选框: 勾选=有(true), 未勾选=无(false)
            has183 = if (has183Check.isChecked) true else null,
            has180 = if (has180Check.isChecked) true else false,
            has200Invite = if (has200InviteCheck.isChecked) true else false,
            // 三态下拉框: null=不关心, true=出现, false=未出现
            hasAck200 = hasAck200,
            hasCancel = hasCancel,
            hasBye = hasBye,
            sipResponseCode = sipResponseCodeInput.text?.toString()?.trim()?.ifBlank { null },
            sipText = sipTextInput.text?.toString()?.trim()?.ifBlank { null },
            sipProvisionalCode = sipProvisionalCodeInput.text?.toString()?.trim()?.ifBlank { null },
            sipRetrans = sipRetrans,
            mediaType = mediaType,
            halfConnected = halfConnected,
            mmEvent = mmEvent,
            supplementaryService = supplementaryService,
            dsmState = dsmState
        )
    }

    private fun loadOrParseKb(): String? {
        parsedCasesJson?.let { return it }

        return try {
            val encBytes = assets.open("kb/flowshark.cases.kb.enc").use { it.readBytes() }
            val encB64 = android.util.Base64.encodeToString(encBytes, android.util.Base64.NO_WRAP)

            val parseOut = host.decryptAndParseKb(encB64)
            val parsed = JSONObject(parseOut)
            if (!parsed.optBoolean("ok", false)) {
                statusText.text = I18nHelper.status("kbParseFailed", "error" to parseOut.take(500))
                return null
            }

            val casesArr = parsed.optJSONArray("data")
                ?: run {
                    statusText.text = I18nHelper.status("kbNoData")
                    return null
                }
            parsedCasesJson = casesArr.toString()
            parsedCasesJson
        } catch (t: Throwable) {
            statusText.text = I18nHelper.status("kbLoadError", "error" to (t.message ?: t::class.java.simpleName))
            null
        }
    }
}
