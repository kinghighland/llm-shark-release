const tauriGlobal = window.__TAURI__;
const invoke = tauriGlobal?.tauri?.invoke ?? tauriGlobal?.invoke;
const open = tauriGlobal?.dialog?.open;
const save = tauriGlobal?.dialog?.save;
const writeText = tauriGlobal?.clipboard?.writeText;

const earlyUiLogEvent = (event, fields) => {
  if (typeof invoke !== "function") return;
  const name = String(event || "").trim();
  if (!name) return;
  const payload = fields && typeof fields === "object" ? fields : undefined;
  try {
    invoke("ui_log_event", { event: name, fields: payload });
  } catch { }
};

earlyUiLogEvent("ui_script_loaded", { ts: new Date().toISOString() });

const els = {
  sidebarToggle: document.getElementById("sidebarToggle"),
  navSettings: document.getElementById("navSettings"),
  newSession: document.getElementById("newSession"),
  sessionList: document.getElementById("sessionList"),

  btnAbout: document.getElementById("btnAbout"),
  btnTopSettings: document.getElementById("btnTopSettings"),
  btnMobileQr: document.getElementById("btnMobileQr"),
  btnStoreCenter: document.getElementById("btnStoreCenter"),
  btnThemeToggle: document.getElementById("btnThemeToggle"),
  btnLangToggle: document.getElementById("btnLangToggle"),
  langFlag: document.getElementById("langFlag"),
  langLabel: document.getElementById("langLabel"),
  langMenu: document.getElementById("langMenu"),

  btnExportFeature: document.getElementById("btnExportFeature"),
  btnImportLicense: document.getElementById("btnImportLicense"),
  btnBuyPerpetual: document.getElementById("btnBuyPerpetual"),
  btnBuyYearly: document.getElementById("btnBuyYearly"),
  btnSoftwareUpdate: document.getElementById("btnSoftwareUpdate"),
  licenseStatus: document.getElementById("licenseStatus"),
  licenseSection: document.getElementById("licenseSection"),

  viewApp: document.getElementById("viewApp"),
  viewSettings: document.getElementById("viewSettings"),

  endpoint: document.getElementById("endpoint"),
  apiKey: document.getElementById("apiKey"),
  toggleApiKey: document.getElementById("toggleApiKey"),
  model: document.getElementById("model"),
  btnValidateLlm: document.getElementById("btnValidateLlm"),
  sfPromo: document.getElementById("sfPromo"),
  validateStatus: document.getElementById("validateStatus"),
  promptAuto: document.getElementById("promptAuto"),
  promptPath: document.getElementById("promptPath"),
  pickPrompt: document.getElementById("pickPrompt"),
  tsharkPath: document.getElementById("tsharkPath"),
  tsharkHint: document.getElementById("tsharkHint"),
  detectTshark: document.getElementById("detectTshark"),
  pickTshark: document.getElementById("pickTshark"),
  useKb: document.getElementById("useKb"),
  kbUserPath: document.getElementById("kbUserPath"),
  pickKbUser: document.getElementById("pickKbUser"),
  saveCfg: document.getElementById("saveCfg"),
  loadCfg: document.getElementById("loadCfg"),
  cfgHint: document.getElementById("cfgHint"),

  aboutOverlay: document.getElementById("aboutOverlay"),
  aboutClose: document.getElementById("aboutClose"),
  aboutClose2: document.getElementById("aboutClose2"),
  aboutCopyInfo: document.getElementById("aboutCopyInfo"),
  aboutVersion: document.getElementById("aboutVersion"),
  aboutRuntime: document.getElementById("aboutRuntime"),

  qrOverlay: document.getElementById("qrOverlay"),
  qrClose: document.getElementById("qrClose"),
  qrClose2: document.getElementById("qrClose2"),
  btnQrRefresh: document.getElementById("btnQrRefresh"),
  qrSvgWrap: document.getElementById("qrSvgWrap"),
  qrExpires: document.getElementById("qrExpires"),

  storeOverlay: document.getElementById("storeOverlay"),
  storeClose: document.getElementById("storeClose"),
  storeRefresh: document.getElementById("storeRefresh"),
  storeRestore: document.getElementById("storeRestore"),
  storeCompare: document.getElementById("storeCompare"),
  storePlanList: document.getElementById("storePlanList"),
  storeManage: document.getElementById("storeManage"),
  storeOpenPage: document.getElementById("storeOpenPage"),
  storeStatusText: document.getElementById("storeStatusText"),
  storeMessage: document.getElementById("storeMessage"),
  storeYearSavingBadge: document.getElementById("storeYearSavingBadge"),
  storeProMonthPrice: document.getElementById("storeProMonthPrice"),
  storeProYearPrice: document.getElementById("storeProYearPrice"),
  storeProYearSaving: document.getElementById("storeProYearSaving"),

  trialOverlay: document.getElementById("trialOverlay"),
  trialOpenInvite: document.getElementById("trialOpenInvite"),
  trialUseTemp: document.getElementById("trialUseTemp"),
  trialCancel: document.getElementById("trialCancel"),

  pickPcap: document.getElementById("pickPcap"),
  pcapPath: document.getElementById("pcapPath"),
  btnAnalyze: document.getElementById("btnAnalyze"),
  openArtifacts: document.getElementById("openArtifacts"),
  closeArtifacts: document.getElementById("closeArtifacts"),
  artifactsOverlay: document.getElementById("artifactsOverlay"),
  statusBar: document.getElementById("statusBar"),
  summaryBox: document.getElementById("summaryBox"),

  workspace: document.getElementById("workspace"),
  reportMessages: document.getElementById("reportMessages"),
  dockToggle: document.getElementById("dockToggle"),
  dockSplitter: document.getElementById("dockSplitter"),

  chatMessages: document.getElementById("chatMessages"),
  chatInput: document.getElementById("chatInput"),
  chatAction: document.getElementById("chatAction"),
  chatReset: document.getElementById("chatReset"),

  tabMermaid: document.getElementById("tabMermaid"),
  tabTable: document.getElementById("tabTable"),
  tabSummary: document.getElementById("tabSummary"),
  panelMermaid: document.getElementById("panelMermaid"),
  panelTable: document.getElementById("panelTable"),
  panelSummary: document.getElementById("panelSummary"),

  sigTableBody: document.querySelector("#sigTable tbody"),
  mermaid: document.getElementById("mermaid"),
};

const STORAGE = {
  cfg: "llm_cfg",
  ui: "llm_ui_state",
  sessions: "llm_sessions_state_v1",
  lang: "llm_lang",
};

let detectedTsharkPath = "";
const TRIAL_API_KEY_PLACEHOLDER = "__LLMSHARK_TRIAL_KEY__";
let qrRefreshTimer = null;

const I18N = {
  defaultLang: "zh-Hans",
  supported: new Set([
    "zh-Hans",
    "zh-Hant",
    "en-US",
    "fr-FR",
    "de-DE",
    "it-IT",
    "ru-RU",
    "fa-IR",
    "ar-SA",
    "ja-JP",
    "ko-KR",
    "es-ES",
    "pt-BR",
    "pt-PT",
    "nl-NL",
    "pl-PL",
    "tr-TR",
    "ro-RO",
    "hi-IN",
    "id-ID",
    "ms-MY",
    "th-TH",
    "vi-VN",
  ]),
  current: "zh-Hans",
  dict: null,
  fallbackDict: null,
  loaded: new Map(),
};

const LANG_META = {
  "zh-Hans": { name: "简体中文", short: "简", flag: "./assets/flags/China.png" },
  "zh-Hant": { name: "繁體中文", short: "繁", flag: "./assets/flags/Hong-Kong.png" },
  "en-US": { name: "English", short: "EN", flag: "./assets/flags/United-Kingdom.png" },
  "fr-FR": { name: "Français", short: "FR", flag: "./assets/flags/France.png" },
  "de-DE": { name: "Deutsch", short: "DE", flag: "./assets/flags/Germany.png" },
  "it-IT": { name: "Italiano", short: "IT", flag: "./assets/flags/Italy.png" },
  "ru-RU": { name: "Русский", short: "RU", flag: "./assets/flags/Russia.png" },
  "fa-IR": { name: "فارسی", short: "FA", flag: "./assets/flags/Iran.png" },
  "ar-SA": { name: "العربية", short: "AR", flag: "./assets/flags/Saudi-Arabia.png" },
  "ja-JP": { name: "日本語", short: "日", flag: "./assets/flags/Japan.png" },
  "ko-KR": { name: "한국어", short: "한", flag: "./assets/flags/South-Korea.png" },
  "es-ES": { name: "Español", short: "ES", flag: "./assets/flags/Spain.png" },
  "pt-BR": { name: "Português (BR)", short: "PT", flag: "./assets/flags/Brazil.png" },
  "pt-PT": { name: "Português (PT)", short: "PT", flag: "./assets/flags/Portugal.png" },
  "nl-NL": { name: "Nederlands", short: "NL", flag: "./assets/flags/Netherlands.png" },
  "tr-TR": { name: "Türkçe", short: "TR", flag: "./assets/flags/Turkey.png" },
  "hi-IN": { name: "हिन्दी", short: "HI", flag: "./assets/flags/India.png" },
  "id-ID": { name: "Bahasa Indonesia", short: "ID", flag: "./assets/flags/Indonesia.png" },
  "th-TH": { name: "ไทย", short: "TH", flag: "./assets/flags/Thailand.png" },
  "vi-VN": { name: "Tiếng Việt", short: "VI", flag: "./assets/flags/Vietnam.png" },
  "ms-MY": { name: "Bahasa Melayu", short: "MS", flag: "./assets/flags/Malaysia.png" },
  "pl-PL": { name: "Polski", short: "PL", flag: "./assets/flags/Poland.png" },
  "ro-RO": { name: "Română", short: "RO", flag: "./assets/flags/Romania.png" },
};

function getLangMeta(lang) {
  const l = normalizeLang(lang);
  return LANG_META[l] || LANG_META[I18N.defaultLang];
}

function normalizeLang(raw) {
  const s = String(raw || "").trim();
  const lower = s.toLowerCase();
  if (I18N.supported.has(s)) return s;
  if (lower === "en") return "en-US";
  if (lower === "zh") return "zh-Hans";
  if (lower === "zh-cn") return "zh-Hans";
  if (lower === "fr") return "fr-FR";
  if (lower === "de") return "de-DE";
  if (lower === "it") return "it-IT";
  if (lower === "ru") return "ru-RU";
  if (lower === "fa") return "fa-IR";
  if (lower === "ar") return "ar-SA";
  if (lower === "es") return "es-ES";
  if (lower === "pt") return "pt-PT";
  if (lower === "pt-br") return "pt-BR";
  if (lower === "pt-pt") return "pt-PT";
  if (lower === "nl") return "nl-NL";
  if (lower === "sv") return "sv-SE";
  if (lower === "fi") return "fi-FI";
  if (lower === "da") return "da-DK";
  if (lower === "nb" || lower === "no") return "nb-NO";
  if (lower === "pl") return "pl-PL";
  if (lower === "tr") return "tr-TR";
  if (lower === "cs") return "cs-CZ";
  if (lower === "sk") return "sk-SK";
  if (lower === "hu") return "hu-HU";
  if (lower === "ro") return "ro-RO";
  if (lower === "el") return "el-GR";
  if (lower === "he") return "he-IL";
  if (lower === "hi") return "hi-IN";
  if (lower === "id") return "id-ID";
  if (lower === "ms") return "ms-MY";
  if (lower === "th") return "th-TH";
  if (lower === "vi") return "vi-VN";
  if (lower === "uk") return "uk-UA";
  if (lower === "hr") return "hr-HR";
  if (lower === "ca") return "ca-ES";
  if (lower === "zh-hans") return "zh-Hans";
  if (lower === "zh-hant" || lower === "zh-tw") return "zh-Hant";
  if (lower === "ja" || lower === "jp") return "ja-JP";
  if (lower === "ko" || lower === "kr") return "ko-KR";
  return I18N.defaultLang;
}

function getLang() {
  return normalizeLang(localStorage.getItem(STORAGE.lang) || I18N.defaultLang);
}

function getUiLang() {
  return normalizeLang(I18N.current || getLang());
}

function getFallbackLangFor(lang) {
  const l = normalizeLang(lang);
  if (l.startsWith("zh")) return "zh-Hans";
  return "en-US";
}

function isRtlLang(lang) {
  const l = normalizeLang(lang).toLowerCase();
  return l.startsWith("ar") || l.startsWith("fa") || l.startsWith("he");
}

function updateLangToggleButton() {
  const l = getLang();
  const meta = getLangMeta(l);
  if (els.langFlag) els.langFlag.src = meta.flag;
  if (els.langLabel) els.langLabel.textContent = meta.short;
}

function renderLangMenu() {
  const menu = els.langMenu;
  if (!menu) return;
  const cur = getLang();
  const collator = new Intl.Collator(undefined, { sensitivity: "base" });
  const ordered = Array.from(I18N.supported).sort((a, b) => {
    const an = getLangMeta(a).name;
    const bn = getLangMeta(b).name;
    return collator.compare(an, bn);
  });
  menu.innerHTML = "";
  for (const code of ordered) {
    const meta = getLangMeta(code);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "langItem" + (code === cur ? " langItemActive" : "");
    btn.setAttribute("role", "menuitem");
    btn.dataset.lang = code;

    const img = document.createElement("img");
    img.className = "langFlag";
    img.alt = "";
    img.src = meta.flag;

    const name = document.createElement("span");
    name.className = "langItemName";
    name.textContent = meta.name;

    const c = document.createElement("span");
    c.className = "langItemCode";
    c.textContent = code;

    btn.appendChild(img);
    btn.appendChild(name);
    btn.appendChild(c);
    btn.addEventListener("click", () => {
      saveLang(code);
      setLangMenuOpen(false);
    });
    menu.appendChild(btn);
  }
}

let langMenuOpen = false;

function setLangMenuOpen(opened) {
  langMenuOpen = Boolean(opened);
  const menu = els.langMenu;
  if (menu) menu.classList.toggle("langMenuHidden", !langMenuOpen);
  if (els.btnLangToggle) els.btnLangToggle.setAttribute("aria-expanded", langMenuOpen ? "true" : "false");
}

async function loadLocaleDict(lang) {
  const l = normalizeLang(lang);
  const key = `lang:${l}`;
  if (I18N.loaded.has(key)) return I18N.loaded.get(key);

  const p = (async () => {
    const res = await fetch(`./i18n/app/${encodeURIComponent(l)}.json`, { cache: "no-cache" });
    if (!res.ok) return {};
    const data = await res.json();
    return data && typeof data === "object" ? data : {};
  })();

  I18N.loaded.set(key, p);
  return p;
}

async function loadModuleDict(moduleName, lang) {
  const l = normalizeLang(lang);
  const m = String(moduleName || "").trim();
  if (!m) return {};
  const key = `module:${m}:${l}`;
  if (I18N.loaded.has(key)) return I18N.loaded.get(key);

  const p = (async () => {
    const res = await fetch(`./i18n/${encodeURIComponent(m)}/${encodeURIComponent(l)}.json`, { cache: "no-cache" });
    if (!res.ok) return {};
    const data = await res.json();
    return data && typeof data === "object" ? data : {};
  })();

  I18N.loaded.set(key, p);
  return p;
}

function mergeDeep(base, extra) {
  const b = base && typeof base === "object" ? base : {};
  const e = extra && typeof extra === "object" ? extra : {};
  const out = Array.isArray(b) ? b.slice() : { ...b };
  for (const k of Object.keys(e)) {
    const bv = out[k];
    const ev = e[k];
    if (bv && ev && typeof bv === "object" && typeof ev === "object" && !Array.isArray(bv) && !Array.isArray(ev)) {
      out[k] = mergeDeep(bv, ev);
    } else {
      out[k] = ev;
    }
  }
  return out;
}

const I18N_LOAD_TIMEOUT_MS = 4000;

function withTimeout(promise, ms, token) {
  let timer = null;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(token), ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function getByPath(obj, path) {
  const root = obj && typeof obj === "object" ? obj : null;
  if (!root) return undefined;
  const parts = String(path || "").split(".").filter(Boolean);
  let cur = root;
  for (const k of parts) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = cur[k];
  }
  return cur;
}

function formatTemplate(template, vars) {
  const src = String(template ?? "");
  const v = vars && typeof vars === "object" ? vars : {};
  return src.replace(/\{(\w+)\}/g, (_, k) => (k in v ? String(v[k]) : `{${k}}`));
}

function t(key, vars) {
  const k = String(key || "").trim();
  if (!k) return "";

  const fromCurrent = getByPath(I18N.dict, k);
  if (typeof fromCurrent === "string") return formatTemplate(fromCurrent, vars);

  const fromFallback = getByPath(I18N.fallbackDict, k);
  if (typeof fromFallback === "string") return formatTemplate(fromFallback, vars);

  return k;
}

function errToMessage(err) {
  if (!err) return "";
  if (typeof err === "string") return err;
  if (err instanceof Error && typeof err.message === "string") return err.message;
  try {
    return String(err);
  } catch {
    return "";
  }
}

function translateBackendError(msg) {
  const src = String(msg || "");
  if (!src) return src;

  const lang = getLang();
  if (lang.startsWith("zh")) return src;

  const rulesByLang = {
    "en-US": [
      { re: /未找到授权文件/g, to: "License file not found" },
      { re: /未授权：?/g, to: "Not activated: " },
      { re: /temperature 必须在 \[0,2\]/g, to: "temperature must be in [0,2]" },
      { re: /endpoint\/model 不能为空/g, to: "endpoint/model cannot be empty" },
      { re: /LLM 返回为空/g, to: "LLM response is empty" },
      { re: /summary JSON 解析失败/g, to: "Failed to parse summary JSON" },
      { re: /找不到 parser\.exe：/g, to: "parser.exe not found: " },
      { re: /指定的授权文件不存在/g, to: "Specified license file does not exist" },
    ],
  };

  const rules = rulesByLang[lang] || rulesByLang["en-US"] || [];

  let out = src;
  for (const r of rules) out = out.replace(r.re, r.to);
  return out;
}

function formatErrorForUi(err) {
  const msg = errToMessage(err);
  return translateBackendError(msg);
}

function applyI18nToDom(root) {
  const host = root && root.querySelectorAll ? root : document;
  const nodes = host.querySelectorAll("[data-i18n],[data-i18n-title],[data-i18n-placeholder],[data-i18n-aria-label]");
  for (const el of nodes) {
    const key = el.dataset.i18n;
    if (key) el.textContent = t(key);

    const titleKey = el.dataset.i18nTitle;
    if (titleKey) el.title = t(titleKey);

    const phKey = el.dataset.i18nPlaceholder;
    if (phKey) el.placeholder = t(phKey);

    const ariaKey = el.dataset.i18nAriaLabel;
    if (ariaKey) el.setAttribute("aria-label", t(ariaKey));
  }
}

function isZhUiLang() {
  const raw = String(I18N.current || document.documentElement.lang || localStorage.getItem(STORAGE.lang) || "")
    .trim()
    .toLowerCase();
  return raw.startsWith("zh");
}

function isSimplifiedZhLang(lang) {
  const l = normalizeLang(lang || I18N.current || getLang());
  return l === "zh-Hans";
}

function isZhLang(lang) {
  const l = normalizeLang(lang || I18N.current || getLang());
  return l === "zh-Hans" || l === "zh-Hant";
}

let licenseStatusCache = null;
let storeEntitlementActive = false;
let usageAuthStateCache = null;

function setStoreEntitlementActive(entitlement) {
  storeEntitlementActive = Boolean(entitlement && entitlement.type);
  updateLicenseSectionVisibility();
}

function updateLicenseSectionVisibility(lang) {
  if (!els.licenseSection) return;
  const mode = getStoreMode();
  const allowLocalLicense = mode !== "native";
  const show = allowLocalLicense && Boolean(licenseStatusCache && licenseStatusCache.ok) && !storeEntitlementActive;
  els.licenseSection.classList.toggle("viewHidden", !show);
}

async function refreshStoreEntitlementForLicense() {
  const mode = getStoreMode();
  if (mode !== "native" || typeof invoke !== "function") {
    setStoreEntitlementActive(null);
    return;
  }
  try {
    const ent = await storeBridgePost("get_entitlement_status");
    const entitlement = ent && ent.ok ? ent.entitlement || null : null;
    setStoreEntitlementActive(entitlement);
  } catch {
    setStoreEntitlementActive(null);
  }
}

function fillSiliconFlowDefaults() {
  if (els.endpoint) {
    els.endpoint.value = "https://api.siliconflow.cn";
    els.endpoint.title = els.endpoint.value;
  }
  if (els.model) {
    els.model.value = "Deepseek-ai/DeepSeek-V4-Flash";
    els.model.title = els.model.value;
  }
}

function isUserCfgValidated() {
  try {
    return localStorage.getItem("llm_user_cfg_valid") === "1";
  } catch {
    return false;
  }
}

function isUserConfigComplete() {
  const ep = String(els.endpoint?.value || "").trim();
  const md = String(els.model?.value || "").trim();
  const ak = String(els.apiKey?.value || "").trim();
  return Boolean(ep && md && ak && ak !== TRIAL_API_KEY_PLACEHOLDER);
}

function isModelConfigComplete() {
  const ep = String(els.endpoint?.value || "").trim();
  const md = String(els.model?.value || "").trim();
  return Boolean(ep && md);
}

function promptMissingModelConfig() {
  if (isModelConfigComplete()) return false;
  setView("settings");
  const title = t("settings.modelConfigTitle");
  const hint = t("settings.cfgNoSaved");
  const fallback = `${t("settings.endpoint")} / ${t("settings.model")} / ${t("settings.apiKey")}`;
  const msg = hint && hint !== "settings.cfgNoSaved" ? `${title}\n${hint}` : `${title}\n${fallback}`;
  if (typeof window?.alert === "function") window.alert(msg);
  return true;
}

function setTrialOverlayOpen(open) {
  if (!els.trialOverlay) return;
  els.trialOverlay.classList.toggle("overlayHidden", !open);
  document.body.classList.toggle("noScroll", open);
}

function openTrialOverlay() {
  if (!els.trialOverlay) return;
  if (els.trialUseTemp) els.trialUseTemp.disabled = false;
  setTrialOverlayOpen(true);
}

function updateSiliconFlowPromo() {
  const host = els.sfPromo;
  if (!host) return;
  host.innerHTML = "";

  if (!isZhUiLang()) return;

  const url = "https://cloud.siliconflow.cn/i/S45uICVN";

  const title = document.createElement("div");
  title.className = "sfPromoTitle";
  title.textContent = "硅基流动大模型服务";

  const row = document.createElement("div");
  row.className = "sfPromoRow";

  const desc = document.createElement("span");
  desc.className = "sfPromoTop";
  desc.textContent = "🎁 新用户手机注册即得2000万Token";

  const link = document.createElement("a");
  link.className = "sfPromoLink";
  link.href = url;
  link.textContent = "邀请链接";
  link.addEventListener("click", async (e) => {
    e.preventDefault();
    try {
      await openPathInShell(url);
    } catch {
      try {
        window.open(url, "_blank", "noopener,noreferrer");
      } catch { }
    }
  });

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "iconBtnSm";
  btn.textContent = "自动填写参数";
  btn.addEventListener("click", () => fillSiliconFlowDefaults());

  const trialBtn = document.createElement("button");
  trialBtn.type = "button";
  trialBtn.className = "iconBtnSm sfTrialBtn";
  trialBtn.textContent = "使用内置服务";
  trialBtn.addEventListener("click", () => openTrialOverlay());

  const note = document.createElement("span");
  note.className = "sfPromoNote";
  note.textContent = "自动填写 → 邀请链接 获取 API Key → 填入后点 验证";

  // 调整顺序：说明 + 链接  + 自动填写按钮 + 说明note + 空隙 + 试用按钮 固定靠右
  row.appendChild(desc);
  row.appendChild(link);
  row.appendChild(btn);
  row.appendChild(note);

  const spacer = document.createElement("div");
  spacer.style.flex = "1";
  row.appendChild(spacer);

  row.appendChild(trialBtn);

  host.appendChild(title);
  host.appendChild(row);
}


async function applyLang(lang) {
  const l = normalizeLang(lang);
  I18N.current = l;
  document.documentElement.lang = l;
  document.documentElement.dir = isRtlLang(l) ? "rtl" : "ltr";

  const timeoutToken = "__i18n_timeout__";
  const fallbackLang = getFallbackLangFor(l);
  try {
    const res = await withTimeout(
      Promise.all([
        loadLocaleDict(l),
        loadModuleDict("store", l),
        loadLocaleDict(fallbackLang),
        loadModuleDict("store", fallbackLang),
      ]),
      I18N_LOAD_TIMEOUT_MS,
      timeoutToken
    );
    if (res === timeoutToken) {
      I18N.dict = I18N.dict || I18N.fallbackDict || {};
      I18N.fallbackDict = I18N.fallbackDict || {};
    } else {
      const [cur, curStore, fallback, fallbackStore] = res;
      I18N.dict = mergeDeep(cur, curStore);
      I18N.fallbackDict = mergeDeep(fallback, fallbackStore);
    }
  } catch {
    I18N.dict = I18N.dict || I18N.fallbackDict || {};
    I18N.fallbackDict = I18N.fallbackDict || {};
  }

  applyI18nToDom(document);
  updateStoreComparePricing();
  updateLangToggleButton();
  updateChatActionButton();
  renderLangMenu();
  updateSiliconFlowPromo();
  updateLicenseSectionVisibility(l);

  if (!hasTauriApi) {
    if (els.summaryBox) els.summaryBox.textContent = t("errors.noTauriApiSummary");
    if (els.statusBar) els.statusBar.textContent = t("errors.noTauriApiStatus");
  } else {
    if (isZhLang(l)) {
      refreshLicenseStatus().catch(() => { });
      refreshStoreEntitlementForLicense().catch(() => { });
    }
  }

  renderSessionList();
  syncPcapUiFromSession(getActiveSession());
}

function saveLang(lang) {
  const l = normalizeLang(lang);
  localStorage.setItem(STORAGE.lang, l);
  applyLang(l).catch(() => { });
}

const MAX_SESSIONS = 20;

let sessions = [];
let activeSessionId = null;

let currentReport = null;
let chatMessages = [];
let reportEndIdx = 0;
let buildingReport = false;
let streamRunning = false;

let mermaidInited = false;
let mermaidPanZoom = null;

let currentSigRows = null;
let currentSigOffset = 0;
let sigPagerMsgIdx = null;
const SIG_PAGE_SIZE = 40;

function getSigPagerIdxFromMessages() {
  let last = null;
  for (let i = 0; i < chatMessages.length; i++) {
    const m = chatMessages[i];
    const acts = Array.isArray(m?.actions) ? m.actions : [];
    if (acts.some((a) => a && a.type === "sig_next_page")) last = i;
  }
  return last;
}

function syncSigPagerStateFromMessages() {
  sigPagerMsgIdx = getSigPagerIdxFromMessages();

  if (sigPagerMsgIdx == null) return;
  const src = String(chatMessages[sigPagerMsgIdx]?.content || "");
  const patterns = [
    /第\s*(\d+)\s*-\s*(\d+)\s*条\s*\/\s*共\s*(\d+)\s*条/g,
    /\bItems?\s*(\d+)\s*-\s*(\d+)\s*\/\s*Total\s*(\d+)\b/gi,
  ];
  let maxEnd = 0;
  for (const re of patterns) {
    for (; ;) {
      const m = re.exec(src);
      if (!m) break;
      const end = Number(m[2] || 0);
      if (Number.isFinite(end) && end > maxEnd) maxEnd = end;
    }
  }
  if (maxEnd > 0) currentSigOffset = maxEnd;
}

async function ensureSigRowsLoaded() {
  if (Array.isArray(currentSigRows) && currentSigRows.length) return true;
  const s = getActiveSession();
  const sigJsonPath = s?.report?.outputs?.signaling_json;
  if (!sigJsonPath) return false;
  if (typeof invoke !== "function") return false;

  try {
    const sig = await invoke("read_json_file", { path: sigJsonPath });
    if (Array.isArray(sig) && sig.length) {
      currentSigRows = sig;
      if (!Number.isFinite(Number(currentSigOffset)) || currentSigOffset <= 0) {
        currentSigOffset = Math.min(sig.length, 40);
      }
      return true;
    }
  } catch { }

  return false;
}

function getTheme() {
  const raw = localStorage.getItem("llm_theme") || "dark";
  return raw === "light" ? "light" : "dark";
}

const MERMAID_LOCAL_SRC = "./vendor/mermaid.min.js";
const MERMAID_CDN_SRC = "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js";
const SVG_PAN_ZOOM_LOCAL_SRC = "./vendor/svg-pan-zoom.min.js";
const SVG_PAN_ZOOM_CDN_SRC = "https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/dist/svg-pan-zoom.min.js";
const EXT_SCRIPT_TIMEOUT_MS = 5000;
let mermaidLoadPromise = null;
let svgPanZoomLoadPromise = null;

function loadExternalScriptOnce(src, globalKey) {
  if (globalKey && globalThis[globalKey]) return Promise.resolve(true);
  const existing = document.querySelector(`script[src="${src}"]`);
  if (existing) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        resolve(ok);
      };
      const done = () => finish(Boolean(globalKey ? globalThis[globalKey] : true));
      existing.addEventListener("load", done, { once: true });
      existing.addEventListener("error", () => finish(false), { once: true });
      setTimeout(() => finish(Boolean(globalKey ? globalThis[globalKey] : false)), EXT_SCRIPT_TIMEOUT_MS);
    });
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      resolve(ok);
    };
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    const done = () => finish(Boolean(globalKey ? globalThis[globalKey] : true));
    script.addEventListener("load", done, { once: true });
    script.addEventListener("error", () => finish(false), { once: true });
    setTimeout(() => finish(Boolean(globalKey ? globalThis[globalKey] : false)), EXT_SCRIPT_TIMEOUT_MS);
    document.head.appendChild(script);
  });
}

async function loadExternalScriptFirst(sources, globalKey) {
  const list = Array.isArray(sources) ? sources.filter(Boolean) : [];
  for (const src of list) {
    const ok = await loadExternalScriptOnce(src, globalKey);
    if (ok) return true;
  }
  return false;
}

function tryInitMermaid(theme) {
  const m = globalThis.mermaid;
  if (m && typeof m.initialize === "function") {
    try {
      m.initialize({
        startOnLoad: false,
        theme: theme === "light" ? "default" : "dark",
        suppressErrorRendering: true,
      });
      mermaidInited = true;
    } catch { }
  }
}

function scheduleMermaidAssetsLoad(theme) {
  if (!mermaidLoadPromise) {
    mermaidLoadPromise = loadExternalScriptFirst([
      MERMAID_LOCAL_SRC,
      MERMAID_CDN_SRC,
    ], "mermaid").then((ok) => {
      if (ok) {
        tryInitMermaid(theme || getTheme());
        if (currentReport?.mermaid_text) {
          renderMermaid(currentReport.mermaid_text).catch(() => { });
        }
      }
      return ok;
    });
  }
  if (!svgPanZoomLoadPromise) {
    svgPanZoomLoadPromise = loadExternalScriptFirst([
      SVG_PAN_ZOOM_LOCAL_SRC,
      SVG_PAN_ZOOM_CDN_SRC,
    ], "svgPanZoom");
  }
  return mermaidLoadPromise;
}

function applyTheme(theme) {
  const t = theme === "light" ? "light" : "dark";
  document.body.classList.toggle("themeLight", t === "light");

  scheduleMermaidAssetsLoad(t);
  tryInitMermaid(t);

  if (currentReport?.mermaid_text) {
    renderMermaid(currentReport.mermaid_text).catch(() => { });
  }
}

function loadTheme() {
  applyTheme(getTheme());
}

function saveTheme(theme) {
  const t = theme === "light" ? "light" : "dark";
  localStorage.setItem("llm_theme", t);
  applyTheme(t);
}

function flashText(el, text, ms) {
  if (!el) return;
  const s = String(text ?? "");
  el.textContent = s;
  const delay = Number.isFinite(Number(ms)) ? Number(ms) : 1400;
  if (delay <= 0) return;
  setTimeout(() => {
    if (el.textContent === s) el.textContent = "";
  }, delay);
}

async function detectTsharkPath() {
  if (typeof invoke !== "function") return "";
  try {
    const found = await invoke("detect_tshark");
    return typeof found === "string" ? found.trim() : "";
  } catch {
    return "";
  }
}

function normalizeTsharkDisplayPath(p) {
  let s = String(p || "").trim();
  if (!s) return "";
  if (s.startsWith("\\\\?\\UNC\\")) {
    s = "\\\\" + s.slice("\\\\?\\UNC\\".length);
  } else if (s.startsWith("\\\\?\\")) {
    s = s.slice("\\\\?\\".length);
  }
  return s.trim();
}

async function ensureTsharkDetected() {
  const fromUi = String(els.tsharkPath?.value || "").trim();
  if (fromUi) return;
  const found = normalizeTsharkDisplayPath(await detectTsharkPath());
  if (!found) return;
  detectedTsharkPath = found;
  if (els.tsharkPath) {
    els.tsharkPath.value = found;
    els.tsharkPath.title = found;
  }
}

function getCfgFromInputs() {
  return {
    endpoint: els.endpoint.value.trim(),
    api_key: els.apiKey.value.trim(),
    model: els.model.value.trim(),
    temperature: 0.2,
    stream: true,
    prompt_auto: Boolean(els.promptAuto?.checked ?? true),
    prompt_path: String(els.promptPath?.value || "").trim(),
    tshark_path: String(els.tsharkPath?.value || "").trim(),
    use_kb: Boolean(els.useKb?.checked ?? true),
    kb_user_path: String(els.kbUserPath?.value || "").trim(),
    ui_lang: getLang(),
  };
}

function loadCfg() {
  const raw = localStorage.getItem("llm_cfg");
  if (!raw) {
    flashText(els.cfgHint, t("settings.cfgNoSaved"), 1200);
    return;
  }
  try {
    const v = JSON.parse(raw);
    els.endpoint.value = v.endpoint || "";
    els.apiKey.value = v.api_key || "";
    els.model.value = v.model || "";
    if (els.tsharkPath) {
      els.tsharkPath.value = String(v.tshark_path || v.tshark || "");
      els.tsharkPath.title = els.tsharkPath.value;
    }
    if (els.promptAuto) els.promptAuto.checked = Boolean(v.prompt_auto ?? true);
    if (els.promptPath) {
      els.promptPath.value = String(v.prompt_path || "");
      els.promptPath.title = els.promptPath.value;
    }
    if (els.useKb) els.useKb.checked = Boolean(v.use_kb ?? true);
    if (els.kbUserPath) {
      els.kbUserPath.value = String(v.kb_user_path || "");
      els.kbUserPath.title = els.kbUserPath.value;
    }
    if (els.validateHint) els.validateHint.textContent = "";
    flashText(els.cfgHint, t("settings.cfgLoaded"), 1200);
  } catch {
    flashText(els.cfgHint, t("settings.cfgParseFail"), 1200);
  }
}

function saveCfg() {
  const cfg = getCfgFromInputs();
  localStorage.setItem("llm_cfg", JSON.stringify(cfg));
  flashText(els.cfgHint, t("settings.cfgSaved"), 1200);
}

function getCfg() {
  const raw = localStorage.getItem("llm_cfg") || "{}";
  const v = JSON.parse(raw);
  return {
    endpoint: v.endpoint || "",
    api_key: v.api_key || "",
    model: v.model || "",
    temperature: 0.2,
    stream: true,
    prompt_auto: Boolean(v.prompt_auto ?? true),
    prompt_path: String(v.prompt_path || "").trim(),
    tshark_path: String(v.tshark_path || v.tshark || "").trim(),
    use_kb: Boolean(v.use_kb ?? true),
    kb_user_path: String(v.kb_user_path || "").trim(),
    ui_lang: getLang(),
  };
}

function setBusy(b) {
  els.pickPcap.disabled = b;
  els.btnAnalyze.disabled = b;
}

function escapeMdCell(v) {
  const s = String(v ?? "");
  return s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
}

function rowsToMarkdownTable(rows, limit) {
  const arr = Array.isArray(rows) ? rows : [];
  const n = Math.min(arr.length, limit);
  const head = t("sig.markdownTableHeader");
  const lines = [head];
  for (let i = 0; i < n; i++) {
    const r = arr[i] || {};
    lines.push(
      `| ${escapeMdCell(r.frame)} | ${escapeMdCell(r.timestamp)} | ${escapeMdCell(r.protocol)} | ${escapeMdCell(r.message)} | ${escapeMdCell(r.cause)} | ${escapeMdCell(r.src)} | ${escapeMdCell(r.dst)} |`
    );
  }
  if (arr.length > n) {
    lines.push(`\n${t("sig.onlyFirstN", { n, total: arr.length })}`);
  }
  return lines.join("\n");
}

function rowsToMarkdownTablePage(rows, start, count) {
  const arr = Array.isArray(rows) ? rows : [];
  const total = arr.length;
  const s = Math.max(0, Number(start) || 0);
  const e = Math.min(total, s + Math.max(1, Number(count) || 1));
  const page = arr.slice(s, e);
  const table = rowsToMarkdownTable(page, page.length);
  return `${t("sig.pageHeader", { start: s + 1, end: e, total })}\n\n${table}`;
}

function renderChatActionsForNode(node, msg) {
  if (!node) return;

  const old = node.querySelector(".chatActions");
  if (old) old.remove();

  const actions = Array.isArray(msg?.actions) ? msg.actions : [];
  if (!actions.length) return;

  const bar = document.createElement("div");
  bar.className = "chatActions";

  for (const a of actions) {
    if (!a || typeof a.label !== "string" || !a.label.trim() || typeof a.type !== "string") continue;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = a.label;
    btn.addEventListener("click", async () => {
      try {
        if (a.type === "sig_next_page") {
          await appendNextSigPage();
        } else if (a.type === "open_path") {
          await openPathInShell(a.path);
        } else if (a.type === "copy_text") {
          await copyWithUiFeedback(
            a.text,
            () => appendChatMessage({ role: "assistant", content: t("common.copied"), meta: true }),
            (e) => appendChatMessage({ role: "assistant", content: formatErrorForUi(e), meta: true })
          );
        } else if (a.type === "open_dir") {
          await openPathInShell(dirnameOfPath(a.path));
        }
      } catch (e) {
        appendChatMessage({ role: "assistant", content: formatErrorForUi(e), meta: true });
      }
    });
    bar.appendChild(btn);
  }

  if (!bar.childNodes.length) return;

  node.appendChild(bar);
}

async function copyTextToClipboard(text) {
  const s = String(text ?? "");
  if (!s) return;

  // 优先使用 Tauri clipboard API
  if (typeof writeText === "function") {
    try {
      await writeText(s);
      return;
    } catch (e) {
      console.error("Tauri clipboard failed:", e);
    }
  }

  // 备用方案：使用浏览器 clipboard API
  if (navigator?.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(s);
      return;
    } catch (e) {
      console.error("Navigator clipboard failed:", e);
    }
  }

  // 最后的备用方案：使用 textarea + execCommand
  try {
    const ta = document.createElement("textarea");
    ta.value = s;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();

    // 尝试使用现代 API
    try {
      ta.setSelectionRange(0, s.length);
    } catch (e) {
      // 忽略旧浏览器的错误
    }

    const success = document.execCommand("copy");
    document.body.removeChild(ta);

    if (!success) {
      throw new Error("execCommand copy returned false");
    }
  } catch (e) {
    console.error("Fallback copy (execCommand) failed:", e);
    throw new Error("无法复制到剪贴板 / Failed to copy to clipboard");
  }
}

async function copyWithUiFeedback(text, onSuccess, onError) {
  try {
    await copyTextToClipboard(text);
    if (typeof onSuccess === "function") onSuccess();
    return true;
  } catch (e) {
    if (typeof onError === "function") onError(e);
    return false;
  }
}

async function openPathInShell(path) {
  const p = String(path ?? "").trim();
  if (!p) throw new Error(t("errors.pathEmpty"));
  const openFn = tauriGlobal?.shell?.open;
  if (typeof openFn !== "function") throw new Error(t("errors.noShellOpen"));
  await openFn(p);
}

function dirnameOfPath(p) {
  const s = String(p ?? "");
  const i = Math.max(s.lastIndexOf("\\"), s.lastIndexOf("/"));
  return i >= 0 ? s.slice(0, i) : "";
}

function basenameOfPath(p) {
  const s = String(p ?? "");
  const i = Math.max(s.lastIndexOf("\\"), s.lastIndexOf("/"));
  return (i >= 0 ? s.slice(i + 1) : s).trim();
}

async function appendNextSigPage() {
  await ensureSigRowsLoaded();

  if (!Array.isArray(currentSigRows) || !currentSigRows.length) {
    appendChatMessage({ role: "assistant", content: t("sig.noData"), meta: true });
    return;
  }

  syncSigPagerStateFromMessages();

  if (currentSigOffset >= currentSigRows.length) {
    appendChatMessage({ role: "assistant", content: t("sig.allShown"), meta: true });
    return;
  }

  if (sigPagerMsgIdx == null) {
    sigPagerMsgIdx = appendChatMessage({
      role: "assistant",
      content: t("sig.fullHint", { count: currentSigRows.length }),
      meta: false,
      localOnly: true,
      actions: [{ type: "sig_next_page", label: t("sig.nextPage", { pageSize: SIG_PAGE_SIZE }) }],
    });
  }

  const start = Math.max(0, Number(currentSigOffset) || 0);
  const text = rowsToMarkdownTablePage(currentSigRows, start, SIG_PAGE_SIZE);

  const prev = String(chatMessages[sigPagerMsgIdx]?.content || "");
  const appendTitle = t("sig.appendTableTitle");
  const next = prev ? `${prev}\n\n${appendTitle}\n\n${text}` : `${appendTitle}\n\n${text}`;
  updateChatMessage(sigPagerMsgIdx, next);

  currentSigOffset = Math.min(currentSigRows.length, start + SIG_PAGE_SIZE);
  setChatStateDirty();
}

function safeParseJson(raw, fallback) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

async function logUiEvent(name, fields) {
  if (typeof invoke !== "function") return;
  const event = String(name || "").trim();
  if (!event) return;
  const payload = fields && typeof fields === "object" ? fields : undefined;
  try {
    await invoke("ui_log_event", { event, fields: payload });
  } catch { }
}

function fmtBool(v) {
  if (v === true) return t("common.yes");
  if (v === false) return t("common.no");
  return "?";
}

function fmtDurationMs(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return "?";
  const s = Math.round(n / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  if (h > 0) return `${h}h${m}m${ss}s`;
  if (m > 0) return `${m}m${ss}s`;
  return `${ss}s`;
}

function fmtLocalStartNoMs(raw) {
  const s = String(raw || "").trim();
  if (!s) return "?";
  const m = s.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
  if (m && m[1]) return m[1];
  const dot = s.indexOf(".");
  if (dot >= 0) return s.slice(0, dot).trim();
  return s;
}

function last4Digits(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  const digits = s.replace(/\D+/g, "");
  if (!digits) return "";
  return digits.length <= 4 ? digits : digits.slice(-4);
}

function extractPhoneNumber(raw) {
  const s = String(raw ?? "");
  if (!s) return null;

  const tel = s.match(/\btel:([^;>\s]+)/i);
  if (tel && tel[1]) {
    const digits = String(tel[1]).replace(/\D+/g, "");
    return digits || null;
  }

  const sip = s.match(/\bsip:([^@;>\s]+)/i);
  if (sip && sip[1]) {
    const v = String(sip[1]).trim();
    if (v.startsWith("+")) {
      const digits = v.replace(/[^\d+]+/g, "");
      return digits || null;
    }
    const digits = v.replace(/\D+/g, "");
    return digits || null;
  }

  const e164 = s.match(/\+\d{5,15}/);
  if (e164) return e164[0];

  const nums = s.match(/\b\d{7,15}\b/g);
  if (nums && nums.length) return nums[0];

  return null;
}

function isEffectiveKbHit(hit) {
  if (!hit || typeof hit !== "object") return false;

  const hasText = (v) => typeof v === "string" && v.trim().length > 0;
  const hasLines = (v) => Array.isArray(v) && v.some((x) => hasText(String(x ?? "")));

  return hasText(hit.diagnosis) || hasText(hit.root_cause) || hasLines(hit.call_process);
}

function setStatusBar(summary, report) {
  if (!els.statusBar) return;

  const labels = {
    number: t("statusBar.labels.number"),
    time: t("statusBar.labels.time"),
    duration: t("statusBar.labels.duration"),
    ringing: t("statusBar.labels.ringing"),
    offhook: t("statusBar.labels.offhook"),
    answered: t("statusBar.labels.answered"),
    cancel: t("statusBar.labels.cancel"),
    dropped: t("statusBar.labels.dropped"),
    cases: t("statusBar.labels.cases"),
  };

  const aRaw = summary?.sip?.from ?? report?.analysis?.call_parties?.from ?? "";
  const bRaw = summary?.sip?.to ?? report?.analysis?.call_parties?.to ?? "";

  const a = last4Digits(extractPhoneNumber(aRaw) || "");
  const b = last4Digits(extractPhoneNumber(bRaw) || "");

  const start = fmtLocalStartNoMs(summary?.time_range?.start_local);
  const dur = fmtDurationMs(summary?.time_range?.duration_ms);

  const has180 = summary?.sip?.has_180 === true;
  const offhook = summary?.sip?.has_200_invite === true;
  const has200 = summary?.sip?.has_ack_200 === true;
  const hasCancel = summary?.sip?.has_cancel === true;
  const dropped = Boolean(summary?.sip?.bye_has_error_code) && Boolean(has200);

  const callType = String(report?.analysis?.call_flow_type ?? "unknown").replace(/_/g, " ");
  const kbHits = Array.isArray(report?.kb?.hits) ? report.kb.hits : [];
  const kbCount = kbHits.filter((hit) => isEffectiveKbHit(hit)).length;

  const pieces = [];

  const numberPart = a && b ? `${a}→${b}` : a ? a : b ? b : "";
  if (numberPart) pieces.push(`${labels.number}: ${numberPart}`);
  pieces.push(`${labels.time}: ${start}`);
  pieces.push(`${labels.duration}: ${dur}`);
  pieces.push(callType);

  const statusTexts = [
    { label: labels.ringing, ok: has180, cls: has180 ? "statusOk" : "statusOff" },
    { label: labels.offhook, ok: offhook, cls: offhook ? "statusOk" : "statusOff" },
    { label: labels.answered, ok: has200, cls: has200 ? "statusOk" : "statusOff" },
    { label: labels.cancel, ok: hasCancel, cls: hasCancel ? "statusBad" : "statusOff" },
    { label: labels.dropped, ok: dropped, cls: dropped ? "statusBad" : "statusOff" },
  ];

  const statusPlain = statusTexts.map((x) => `${x.label} ${x.ok ? "✓" : "×"}`).join(" ");
  pieces.push(statusPlain);
  pieces.push(`${labels.cases}:${kbCount}`);

  const fullText = pieces.join(" | ");

  els.statusBar.title = fullText;
  els.statusBar.innerHTML = "";

  const frag = document.createDocumentFragment();

  const appendSep = () => {
    frag.appendChild(document.createTextNode(" | "));
  };

  const appendText = (txt) => {
    frag.appendChild(document.createTextNode(String(txt || "")));
  };

  const appendStatusSpan = (label, ok, cls) => {
    const span = document.createElement("span");
    span.className = `statusSeg ${cls}`;
    span.textContent = `${label} ${ok ? "✓" : "×"}`;
    frag.appendChild(span);
  };

  let first = true;

  const addPiece = (fn) => {
    if (!first) appendSep();
    first = false;
    fn();
  };

  if (numberPart) {
    addPiece(() => appendText(`${labels.number}: ${numberPart}`));
  }

  addPiece(() => appendText(`${labels.time}: ${start}`));
  addPiece(() => appendText(`${labels.duration}: ${dur}`));
  addPiece(() => appendText(callType));

  addPiece(() => {
    appendStatusSpan(labels.ringing, has180, has180 ? "statusOk" : "statusOff");
    frag.appendChild(document.createTextNode(" "));
    appendStatusSpan(labels.offhook, offhook, offhook ? "statusOk" : "statusOff");
    frag.appendChild(document.createTextNode(" "));
    appendStatusSpan(labels.answered, has200, has200 ? "statusOk" : "statusOff");
    frag.appendChild(document.createTextNode(" "));
    appendStatusSpan(labels.cancel, hasCancel, hasCancel ? "statusBad" : "statusOff");
    frag.appendChild(document.createTextNode(" "));
    appendStatusSpan(labels.dropped, dropped, dropped ? "statusBad" : "statusOff");
  });

  addPiece(() => appendText(`${labels.cases}:${kbCount}`));

  els.statusBar.appendChild(frag);
}

function syncPcapUiFromSession(s) {
  if (!els.pcapPath || !els.btnAnalyze || !els.statusBar) return;

  const rep = normalizeSessionReport(s?.report);
  const pcap = getSessionPcapPath(s, rep);
  const sum = rep?.summary || null;
  els.pcapPath.value = pcap;
  els.pcapPath.title = pcap;
  els.btnAnalyze.disabled = !pcap;

  if (s && pcap && !String(s.pcapPath || "").trim()) {
    s.pcapPath = pcap;
    saveSessionsState();
  }

  if (sum || rep) {
    setStatusBar(sum, rep);
  } else {
    els.statusBar.textContent = pcap ? t("app.pickedFileHint") : t("app.notLoaded");
  }
}

function normalizeSessionReport(rep) {
  if (!rep) return null;
  if (typeof rep === "string") {
    const parsed = safeParseJson(rep, null);
    return parsed && typeof parsed === "object" ? parsed : null;
  }
  if (typeof rep === "object") return rep;
  return null;
}

function getSessionPcapPath(s, rep) {
  const sum = rep?.summary || null;
  return String(
    s?.pcapPath ||
    s?.pcap_path ||
    s?.pcapFile ||
    s?.pcap ||
    sum?.pcap_file ||
    sum?.pcap_path ||
    sum?.pcapPath ||
    sum?.pcapFile ||
    rep?.pcap_file ||
    rep?.pcap_path ||
    rep?.pcapPath ||
    rep?.pcapFile ||
    rep?.pcap ||
    ""
  ).trim();
}

function normalizeSessionRecord(s) {
  if (!s || typeof s !== "object") return null;
  const next = { ...s };
  if (!next.id && typeof next.sessionId === "string") next.id = next.sessionId;
  if (!next.title) next.title = String(t("sessions.unnamed") || "").trim() || "Session";
  if (!Array.isArray(next.messages)) {
    const fallbackMsgs = next.chatMessages || next.msgs || next.history;
    if (Array.isArray(fallbackMsgs)) next.messages = fallbackMsgs;
    else if (typeof next.messages === "string") {
      const parsed = safeParseJson(next.messages, null);
      next.messages = Array.isArray(parsed) ? parsed : [];
    } else {
      next.messages = [];
    }
  }
  if (!next.report && (next.reportJson || next.report_json || next.reportData)) {
    next.report = next.reportJson || next.report_json || next.reportData;
  }
  const rep = normalizeSessionReport(next.report);
  if (rep) next.report = rep;
  const pcap = getSessionPcapPath(next, rep);
  if (pcap && !String(next.pcapPath || "").trim()) next.pcapPath = pcap;
  return next;
}

function parseMaybeJson(raw) {
  let v = raw;
  for (let i = 0; i < 2; i++) {
    if (typeof v !== "string") break;
    const parsed = safeParseJson(v, v);
    if (parsed === v) break;
    v = parsed;
  }
  return v;
}

function looksLikeSession(val) {
  if (!val || typeof val !== "object") return false;
  return Boolean(
    val.id ||
    val.sessionId ||
    val.title ||
    val.messages ||
    val.report ||
    val.pcapPath ||
    val.createdAt ||
    val.updatedAt
  );
}

function extractSessionsFromObject(obj) {
  if (!obj || typeof obj !== "object") return null;
  const pickArray = (v) => (Array.isArray(v) ? v : null);
  let list =
    pickArray(obj.sessions) ||
    pickArray(obj.items) ||
    pickArray(obj.list) ||
    pickArray(obj.records) ||
    pickArray(obj.data) ||
    null;
  if (list) return list;

  const mapToList = (entries) =>
    entries
      .map(([key, val]) => {
        const v = val && typeof val === "object" ? { ...val } : null;
        if (!v) return null;
        if (!v.id && !v.sessionId) v.id = key;
        return v;
      })
      .filter((v) => v && typeof v === "object");

  if (obj.sessions && typeof obj.sessions === "object") {
    const entries = Object.entries(obj.sessions);
    if (entries.length) {
      const mapped = mapToList(entries);
      if (mapped.length) return mapped;
    }
  }

  const entries = Object.entries(obj);
  if (entries.length && entries.some(([, v]) => looksLikeSession(v))) {
    const mapped = mapToList(entries);
    if (mapped.length) return mapped;
  }
  return null;
}

function extractSessions(value) {
  if (!value) return null;
  if (Array.isArray(value)) return value;
  if (typeof value === "string") {
    const parsed = parseMaybeJson(value);
    if (parsed === value) return null;
    return extractSessions(parsed);
  }
  if (typeof value === "object") return extractSessionsFromObject(value);
  return null;
}

function normalizeSessionsPayload(raw) {
  const st = raw && typeof raw === "object" ? raw : parseMaybeJson(raw);
  if (!st || typeof st === "string") return null;
  if (Array.isArray(st)) return { sessions: st, activeSessionId: null };
  const root = st && typeof st === "object" ? st : {};
  const payload = root.data && typeof root.data === "object" ? root.data : root;

  const list =
    extractSessions(payload.sessions) ||
    extractSessions(payload.items) ||
    extractSessions(payload.list) ||
    extractSessions(payload.records) ||
    extractSessions(payload.data) ||
    extractSessions(payload) ||
    null;

  const active =
    payload.activeSessionId ||
    payload.activeId ||
    payload.active ||
    payload.current ||
    payload.selectedSessionId ||
    payload.currentSessionId ||
    root.activeSessionId ||
    root.activeId ||
    root.current ||
    null;
  return {
    sessions: Array.isArray(list) ? list : [],
    activeSessionId: typeof active === "string" ? active : null,
  };
}

function readSessionsState(key) {
  const raw = localStorage.getItem(key);
  const norm = normalizeSessionsPayload(raw);
  return norm || { sessions: [], activeSessionId: null };
}

function saveUiState(extra) {
  const st = safeParseJson(localStorage.getItem(STORAGE.ui) || "{}", {});
  const next = {
    ...st,
    view: els.viewSettings.classList.contains("viewHidden") ? "app" : "settings",
    ...safeParseJson(JSON.stringify(extra || {}), {}),
  };
  localStorage.setItem(STORAGE.ui, JSON.stringify(next));
}

function setDockWidth(val) {
  if (!els.workspace) return;
  const v = String(val || "").trim();
  if (!v) return;
  els.workspace.style.setProperty("--dockWidth", v);
}

function loadUiState() {
  const st = safeParseJson(localStorage.getItem(STORAGE.ui) || "{}", {});
  if (st.sidebarCollapsed === true) document.body.classList.add("sidebarCollapsed");
  if (st.dockCollapsed === true) document.body.classList.add("dockCollapsed");
  if (st.dockWidth) setDockWidth(st.dockWidth);
  setView(st.view === "settings" ? "settings" : "app");
  renderSessionList();
}

function saveSessionsState() {
  const payload = { sessions, activeSessionId };
  localStorage.setItem(STORAGE.sessions, JSON.stringify(payload));
}

function loadSessionsState() {
  let { sessions: list, activeSessionId: active } = readSessionsState(STORAGE.sessions);
  let migrated = false;
  if (!Array.isArray(list) || !list.length) {
    const keys = Object.keys(localStorage || {}).filter((k) => /^llm_sessions_state/i.test(k));
    const legacyKeys = ["llm_sessions_state", "llm_sessions_state_v0"];
    const candidates = [...new Set([...legacyKeys, ...keys])];
    let best = null;
    let bestScore = 0;
    for (const key of candidates) {
      const st = readSessionsState(key);
      const count = Array.isArray(st.sessions) ? st.sessions.length : 0;
      const score = count * 10 + (st.activeSessionId ? 1 : 0);
      if (score > bestScore) {
        bestScore = score;
        best = st;
      }
    }
    if (best && Array.isArray(best.sessions) && best.sessions.length) {
      list = best.sessions;
      active = best.activeSessionId;
      migrated = true;
    }
  }
  sessions = Array.isArray(list) ? list.map(normalizeSessionRecord).filter(Boolean) : [];
  activeSessionId = typeof active === "string" ? active : null;
  if (migrated) saveSessionsState();
}

function nowIso() {
  return new Date().toISOString();
}

function newSessionId() {
  return `s_${Date.now().toString(16)}_${Math.random().toString(16).slice(2)}`;
}

function getActiveSession() {
  return sessions.find((s) => s && s.id === activeSessionId) || null;
}

function persistActiveSession() {
  const s = getActiveSession();
  if (!s) return;
  s.messages = chatMessages;
  s.report = currentReport;
  if (Number.isFinite(Number(reportEndIdx))) s.reportEndIdx = Number(reportEndIdx);
  else delete s.reportEndIdx;
  s.pcapPath = String(els.pcapPath?.value ?? s.pcapPath ?? "").trim();
  s.updatedAt = nowIso();
  saveSessionsState();
  if (!streamRunning) renderSessionList();
}

function isDefaultAnalyzePromptText(txt) {
  const v = String(txt || "").trim();
  if (!v) return false;
  const cur = String(t("analyze.defaultPrompt") || "").trim();
  return Boolean(cur) && v === cur;
}

function deriveReportEndIdxFromMessages(msgs) {
  if (!Array.isArray(msgs) || !msgs.length) return 0;

  let diagIdx = -1;
  for (let i = 0; i < msgs.length; i++) {
    const m = msgs[i];
    if (!m || m.meta || m.localOnly) continue;
    if (m.role === "assistant") {
      diagIdx = i;
      break;
    }
  }
  if (diagIdx < 0) return 0;

  for (let i = diagIdx + 1; i < msgs.length; i++) {
    const m = msgs[i];
    if (!m || m.meta || m.localOnly) continue;
    if (m.role !== "user") continue;
    if (isDefaultAnalyzePromptText(m.content)) continue;
    return i;
  }

  return msgs.length;
}

function ensureAtLeastOneSession() {
  if (!sessions.length) {
    const id = newSessionId();
    sessions = [
      {
        id,
        title: t("sessions.sessionN", { n: 1 }),
        createdAt: nowIso(),
        updatedAt: nowIso(),
        messages: [],
        report: null,
        reportEndIdx: 0,
      },
    ];
    activeSessionId = id;
    saveSessionsState();
  }
  if (!activeSessionId || !sessions.some((s) => s.id === activeSessionId)) {
    activeSessionId = sessions[0]?.id || null;
  }
}

function trimSessions() {
  if (sessions.length <= MAX_SESSIONS) return;
  const keep = sessions.slice().sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")));
  const kept = keep.slice(0, MAX_SESSIONS);
  const keptIds = new Set(kept.map((s) => s.id));
  sessions = sessions.filter((s) => keptIds.has(s.id));
  if (!sessions.some((s) => s.id === activeSessionId)) {
    activeSessionId = sessions[0]?.id || null;
  }
}

function selectSession(id) {
  persistActiveSession();
  const s = sessions.find((x) => x && x.id === id);
  if (!s) return;
  activeSessionId = id;
  chatMessages = Array.isArray(s.messages) ? s.messages : [];
  currentReport = s.report || null;
  const saved = Number(s.reportEndIdx);
  const derived = deriveReportEndIdxFromMessages(chatMessages);
  reportEndIdx = s.report && (!Number.isFinite(saved) || saved <= 0) ? derived : Number.isFinite(saved) ? saved : derived;
  renderChatAll();
  saveSessionsState();
  renderSessionList();
  syncPcapUiFromSession(s);
  setView("app");
}

function setDockCollapsed(next) {
  const v = Boolean(next);
  document.body.classList.toggle("dockCollapsed", v);
  saveUiState({ dockCollapsed: v });
}

function clamp(n, lo, hi) {
  const x = Number(n);
  if (!Number.isFinite(x)) return lo;
  return Math.max(lo, Math.min(hi, x));
}

function setupDockInteractions() {
  els.dockToggle?.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    const next = !document.body.classList.contains("dockCollapsed");
    setDockCollapsed(next);
  });

  const beginDockDrag = (startX) => {
    if (!els.workspace) return;
    if (document.body.classList.contains("dockCollapsed")) return;
    const dock = document.getElementById("dock");
    if (!dock) return;

    const startW = dock.getBoundingClientRect().width;

    const onMove = (ev) => {
      const dx = ev.clientX - startX;
      const wrapW = els.workspace.getBoundingClientRect().width;
      const minW = 260;
      const maxW = Math.max(minW, wrapW - 360);
      const nextW = clamp(startW - dx, minW, maxW);
      setDockWidth(`${Math.round(nextW)}px`);
    };

    const onUp = () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      const v = els.workspace.style.getPropertyValue("--dockWidth");
      if (v) saveUiState({ dockWidth: v.trim() });
    };

    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
  };

  els.dockSplitter?.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    if (document.body.classList.contains("dockCollapsed")) return;
    e.preventDefault();
    try {
      els.dockSplitter.setPointerCapture(e.pointerId);
    } catch { }
    beginDockDrag(e.clientX);
  });
}

function createSession() {
  persistActiveSession();
  const n = sessions.length + 1;
  const id = newSessionId();
  sessions.unshift({
    id,
    title: t("sessions.sessionN", { n }),
    createdAt: nowIso(),
    updatedAt: nowIso(),
    messages: [],
    report: null,
    reportEndIdx: 0,
    pcapPath: "",
  });
  activeSessionId = id;
  trimSessions();
  chatMessages = [];
  currentReport = null;
  renderChatAll();
  saveSessionsState();
  renderSessionList();
  syncPcapUiFromSession(getActiveSession());
  setView("app");
}

function deleteSession(id) {
  persistActiveSession();

  const before = sessions.length;
  sessions = sessions.filter((s) => s && s.id !== id);
  if (sessions.length === before) return;

  // 如果删除的是当前活动会话，需要切换到其他会话
  if (activeSessionId === id) {
    activeSessionId = sessions[0]?.id || null;
  }

  // 如果删除后没有会话了，创建一个新会话
  if (!sessions.length) {
    ensureAtLeastOneSession();
  }

  // 重新加载当前活动会话的数据
  const s = getActiveSession();
  chatMessages = Array.isArray(s?.messages) ? s.messages : [];
  currentReport = s?.report || null;

  // 刷新界面
  renderChatAll();
  syncPcapUiFromSession(s);
  saveSessionsState();
  renderSessionList();
}

let sessionCtxMenu = null;
let sessionCtxMenuForId = null;

function hideSessionCtxMenu() {
  if (!sessionCtxMenu) return;
  sessionCtxMenu.style.display = "none";
  // 注意：不要在 hide 时清空 sessionCtxMenuForId。
  // 某些情况下（例如全局捕获阶段关闭菜单），会导致菜单项 click 读取不到 id，从而“删除不执行”。
}

function ensureSessionCtxMenu() {
  if (sessionCtxMenu) return sessionCtxMenu;
  const el = document.createElement("div");
  el.className = "sessionCtxMenu";
  el.style.display = "none";
  el.dataset.forId = "";

  const getCtxId = () => String(el.dataset.forId || sessionCtxMenuForId || "").trim() || null;

  const btnRename = document.createElement("button");
  btnRename.type = "button";
  btnRename.className = "ctxMenuItem";
  btnRename.textContent = t("sessions.rename");
  btnRename.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();

    const id = getCtxId();
    if (!id) return;

    const s = sessions.find((x) => x && x.id === id);
    if (!s) return;

    const cur = String(s.title || "");
    const next = window.prompt(t("sessions.renamePromptTitle"), cur);
    const nextTitle = String(next ?? "").trim();
    hideSessionCtxMenu();
    if (!nextTitle) return;

    s.title = nextTitle;
    s.updatedAt = nowIso();
    saveSessionsState();
    renderSessionList();
  });

  const btnDel = document.createElement("button");
  btnDel.type = "button";
  btnDel.className = "ctxMenuItem";
  btnDel.textContent = t("sessions.delete");
  btnDel.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();

    const id = getCtxId();
    hideSessionCtxMenu();
    if (!id) return;

    let ok = false;
    try {
      if (typeof tauriGlobal?.dialog?.confirm === "function") {
        ok = await tauriGlobal.dialog.confirm(t("sessions.deleteConfirm"), { title: t("common.confirm") });
      } else {
        ok = window.confirm(t("sessions.deleteConfirm"));
      }
    } catch {
      ok = window.confirm(t("sessions.deleteConfirm"));
    }

    if (!ok) {
      renderSessionList();
      return;
    }

    deleteSession(id);
  });

  el.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
  });

  el.appendChild(btnRename);
  el.appendChild(btnDel);
  document.body.appendChild(el);

  document.addEventListener("click", (e) => {
    try {
      if (!sessionCtxMenu || sessionCtxMenu.style.display === "none") return;
      const t = e?.target;
      if (t && sessionCtxMenu.contains(t)) return;
      hideSessionCtxMenu();
    } catch {
      hideSessionCtxMenu();
    }
  });
  window.addEventListener("blur", () => hideSessionCtxMenu());
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideSessionCtxMenu();
  });

  sessionCtxMenu = el;
  return el;
}

function showSessionCtxMenu(x, y, id) {
  const el = ensureSessionCtxMenu();
  sessionCtxMenuForId = id;
  el.dataset.forId = String(id || "");
  el.style.left = `${Math.max(8, Number(x) || 0)}px`;
  el.style.top = `${Math.max(8, Number(y) || 0)}px`;
  el.style.display = "block";
}

let sessionListOffset = 0;
const SESSION_LIST_STEP = 3;
let sessionListDebugLogged = false;

function getSessionListPageSize(host, collapsed) {
  const h = Math.max(0, Number(host?.clientHeight) || 0);
  const rowH = collapsed ? 46 : 44;
  return Math.max(1, Math.floor(h / rowH));
}

function clampSessionListOffset(offset, pageSize) {
  const max = Math.max(0, sessions.length - Math.max(1, pageSize));
  return Math.min(Math.max(0, Number(offset) || 0), max);
}

function ensureActiveSessionInView(pageSize) {
  const idx = sessions.findIndex((s) => s && s.id === activeSessionId);
  if (idx < 0) return;
  if (idx < sessionListOffset) sessionListOffset = idx;
  if (idx >= sessionListOffset + pageSize) sessionListOffset = idx - pageSize + 1;
  sessionListOffset = clampSessionListOffset(sessionListOffset, pageSize);
}

function shiftSessionList(delta, pageSize) {
  sessionListOffset = clampSessionListOffset(sessionListOffset + (Number(delta) || 0), pageSize);
  renderSessionList();
}

let sessionListWheelBound = false;
function setupSessionListWheel() {
  if (sessionListWheelBound || !els.sessionList) return;
  sessionListWheelBound = true;
  els.sessionList.addEventListener(
    "wheel",
    (e) => {
      const host = els.sessionList;
      if (!host || sessions.length <= 1) return;
      const collapsed = document.body.classList.contains("sidebarCollapsed");
      const pageSize = getSessionListPageSize(host, collapsed);
      const effectiveSize = Math.max(1, pageSize - 2);
      const dy = Number(e?.deltaY) || 0;
      if (!dy) return;
      e.preventDefault();
      shiftSessionList(dy > 0 ? 1 : -1, effectiveSize);
    },
    { passive: false }
  );
}

function renderSessionList() {
  const host = els.sessionList;
  if (!host) return;
  host.innerHTML = "";

  const collapsed = document.body.classList.contains("sidebarCollapsed");
  const pageSize = getSessionListPageSize(host, collapsed);
  const effectiveSize = Math.max(1, pageSize - 2);
  sessionListOffset = clampSessionListOffset(sessionListOffset, effectiveSize);
  ensureActiveSessionInView(effectiveSize);

  const toShort = (title) => {
    const s = String(title ?? "").trim();
    if (!s) return "?";
    const ch = Array.from(s)[0] || "?";
    if (/[A-Za-z]/.test(ch)) return ch.toUpperCase();
    return ch;
  };

  const appendPager = (dir) => {
    const row = document.createElement("div");
    row.className = "sessionItem";

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "sessionPagerBtn";
    btn.textContent = "...";
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();

      const effectiveSize = Math.max(1, pageSize - 2);
      const upRemain = Math.max(0, sessionListOffset);
      const downRemain = Math.max(0, sessions.length - (sessionListOffset + effectiveSize));
      const step = dir === "up" ? Math.min(SESSION_LIST_STEP, upRemain) : Math.min(SESSION_LIST_STEP, downRemain);
      if (step <= 0) return;

      shiftSessionList(dir === "up" ? -step : step, effectiveSize);
    });

    row.appendChild(btn);
    host.appendChild(row);
  };

  let slots = pageSize;
  const showTop = sessionListOffset > 0;
  if (showTop) slots = Math.max(1, slots - 1);

  let end = Math.min(sessions.length, sessionListOffset + slots);
  let showBottom = end < sessions.length;
  if (showBottom) {
    slots = Math.max(1, slots - 1);
    end = Math.min(sessions.length, sessionListOffset + slots);
    showBottom = end < sessions.length;
  }

  if (showTop) appendPager("up");

  for (let i = sessionListOffset; i < end; i++) {
    const s = sessions[i];
    if (!s || !s.id) continue;

    const row = document.createElement("div");
    row.className = "sessionItem";

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "sessionBtn" + (s.id === activeSessionId ? " sessionBtnActive" : "");
    const fullTitle = String(s.title || t("sessions.unnamed"));
    btn.textContent = collapsed ? toShort(fullTitle) : fullTitle;
    btn.title = fullTitle;
    btn.addEventListener("click", () => selectSession(s.id));

    const onCtx = (e) => {
      e.preventDefault();
      e.stopPropagation();
      showSessionCtxMenu(e.clientX, e.clientY, s.id);
    };

    btn.addEventListener("contextmenu", onCtx);
    row.addEventListener("contextmenu", onCtx);

    row.appendChild(btn);
    host.appendChild(row);
  }

  if (showBottom) appendPager("down");
}

function setChatStateDirty() {
  if (streamRunning) return;
  persistActiveSession();
}

function normalizeMermaidCode(code) {
  const raw = String(code ?? "").trim();
  if (!raw) return null;

  const re = /^(sequenceDiagram|flowchart|graph|stateDiagram|stateDiagram-v2|classDiagram|erDiagram|journey|gantt|pie|mindmap|timeline|quadrantChart|sankey-beta)\b/m;
  const m = raw.match(re);
  if (!m || typeof m.index !== "number") return null;

  let sliced = raw.slice(m.index).trim();
  const firstLine = sliced.split(/\r?\n/)[0]?.trim() || "";
  if (!re.test(firstLine)) return null;

  if (sliced.length < 20) return null;

  // IMPORTANT: Do NOT remove this sanitization.
  // We have repeatedly hit Mermaid sequenceDiagram parse errors when SIP headers like
  // "Q.850;cause=102" appear in message text; replacing ';' with space avoids the parser bug/regression.
  if (/^sequenceDiagram\b/.test(firstLine)) sliced = sliced.replace(/;/g, " ");

  return sliced;
}

function ensureMermaidFence(text) {
  const src = String(text ?? "");
  if (!src.trim()) return src;
  if (/```mermaid[\s\S]*?```/i.test(src)) return src;

  const lines = src.split(/\r?\n/);
  const re = /^\s*(sequenceDiagram|flowchart|graph|stateDiagram|stateDiagram-v2|classDiagram|erDiagram|journey|gantt|pie|mindmap|timeline|quadrantChart|sankey-beta)\b/;
  let idx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) {
      idx = i;
      break;
    }
  }
  if (idx < 0) return src;

  const before = lines.slice(0, idx).join("\n").trimEnd();
  const body = lines.slice(idx).join("\n").trimEnd();
  if (!body) return src;

  const fenced = "```mermaid\n" + body + "\n```";
  if (!before) return fenced;
  return before + "\n" + fenced;
}

async function renderMermaidBlocksInto(root) {
  const blocks = root.querySelectorAll("pre code");
  const rootTag = root?.tagName ? String(root.tagName) : "";
  const rootClass = root?.className ? String(root.className) : "";
  if (!blocks.length) {
    logUiEvent("mermaid_scan", { blocks: "0", rootTag, rootClass });
    return;
  }
  logUiEvent("mermaid_scan", { blocks: String(blocks.length), rootTag, rootClass });

  await scheduleMermaidAssetsLoad();
  const m = globalThis.mermaid;
  const pzFactory = globalThis.svgPanZoom;

  if (!mermaidInited && m && typeof m.initialize === "function") {
    try {
      m.initialize({
        startOnLoad: false,
        theme: getTheme() === "light" ? "default" : "dark",
        suppressErrorRendering: true,
      });
      mermaidInited = true;
    } catch { }
  }

  if (!m || typeof m.render !== "function") {
    logUiEvent("mermaid_not_loaded", {
      hasRender: String(Boolean(m && typeof m.render === "function")),
      hasInit: String(Boolean(m && typeof m.initialize === "function")),
    });
    appendChatMessage({ role: "assistant", content: t("mermaid.notLoaded"), meta: true });
    return;
  }

  const errs = [];
  let idx = 0;

  for (const codeEl of blocks) {
    const cur = idx++;
    const pre = codeEl.closest("pre");
    const cls = String(codeEl.className || "");
    const rawText = String(codeEl.textContent ?? "");
    if (!pre) {
      logUiEvent("mermaid_block_skip", { idx: String(cur), reason: "no_pre", cls });
      continue;
    }

    const code = normalizeMermaidCode(rawText);
    if (!code) {
      const head = rawText.trim().split(/\r?\n/)[0] || "";
      logUiEvent("mermaid_block_skip", { idx: String(cur), reason: "normalize_null", cls, head });
      continue;
    }
    logUiEvent("mermaid_block_ok", { idx: String(cur), cls, rawLen: String(rawText.length), normLen: String(code.length) });

    const wrap = document.createElement("div");
    wrap.className = "mermaidWrap";

    const tools = document.createElement("div");
    tools.className = "mermaidTools";

    const btnToggle = document.createElement("button");
    btnToggle.type = "button";
    btnToggle.textContent = t("mermaid.zoomIn");

    const btnFit = document.createElement("button");
    btnFit.type = "button";
    btnFit.textContent = t("mermaid.fit");

    tools.appendChild(btnToggle);
    tools.appendChild(btnFit);

    const holder = document.createElement("div");
    holder.className = "mermaid box";
    holder.textContent = code;

    wrap.appendChild(tools);
    wrap.appendChild(holder);
    pre.replaceWith(wrap);

    const id = `cm_${Math.random().toString(16).slice(2)}`;
    try {
      if (typeof m.parse === "function") {
        const r = m.parse(code);
        if (r && typeof r.then === "function") await r;
      }

      const out = await m.render(id, code);
      const svgText = String(out?.svg || "");
      if (/Syntax error in text/i.test(svgText)) {
        const v = typeof m.version === "string" ? m.version : "";
        const extra = v ? ` (mermaid ${v})` : "";
        throw new Error(t("mermaid.syntaxError", { extra }));
      }

      logUiEvent("mermaid_render_done", { idx: String(cur), svgLen: String(svgText.length) });
      holder.innerHTML = svgText;
      if (typeof out?.bindFunctions === "function") out.bindFunctions(holder);

      const svg = holder.querySelector("svg");
      if (svg) {
        try {
          svg.style.display = "block";
          svg.style.width = "100%";
          svg.style.height = "100%";
          svg.style.maxWidth = "none";
        } catch { }
      }

      let pz = null;
      if (svg && typeof pzFactory === "function") {
        try {
          pz = pzFactory(svg, {
            zoomEnabled: true,
            controlIconsEnabled: false,
            fit: true,
            center: true,
            minZoom: 0.2,
            maxZoom: 20,
            dblClickZoomEnabled: false,
          });
        } catch { }
      }

      const fitAll = () => {
        try {
          pz?.updateBBox?.();
        } catch { }
        try {
          pz?.resize?.();
        } catch { }
        try {
          pz?.fit?.();
        } catch { }
        try {
          pz?.center?.();
        } catch { }
      };

      const fillViewport = () => {
        try {
          try {
            pz?.updateBBox?.();
          } catch { }
          pz?.resize?.();

          const vb = svg?.viewBox?.baseVal;
          const vbw = vb?.width || 0;
          const vbh = vb?.height || 0;
          const cwRaw = holder?.clientWidth || 0;
          const chRaw = holder?.clientHeight || 0;
          const cs = holder ? getComputedStyle(holder) : null;
          const padX = cs ? Number.parseFloat(cs.paddingLeft || "0") + Number.parseFloat(cs.paddingRight || "0") : 0;
          const padY = cs ? Number.parseFloat(cs.paddingTop || "0") + Number.parseFloat(cs.paddingBottom || "0") : 0;
          const cw = Math.max(0, cwRaw - (Number.isFinite(padX) ? padX : 0));
          const ch = Math.max(0, chRaw - (Number.isFinite(padY) ? padY : 0));

          if (!vbw || !vbh || !cw || !ch || typeof pz?.zoom !== "function") {
            fitAll();
            return;
          }

          const zx = cw / vbw;
          const zy = ch / vbh;
          const z = Math.min(zx, zy);
          pz.zoom(z);
          pz.center?.();
        } catch {
          fitAll();
        }
      };

      const fit = () => {
        if (wrap.classList.contains("mermaidWrapMax")) fillViewport();
        else fitAll();
      };

      const scheduleFit = () => {
        try {
          requestAnimationFrame(() => requestAnimationFrame(() => fit()));
        } catch {
          queueMicrotask(() => fit());
        }
      };

      btnFit.addEventListener("click", () => scheduleFit());

      btnToggle.addEventListener("click", () => {
        const max = !wrap.classList.contains("mermaidWrapMax");

        if (max) {
          wrap.dataset.prevMermaidW = holder.style.width || "";
          wrap.dataset.prevMermaidH = holder.style.height || "";
          holder.style.width = "";
          holder.style.height = "";
        } else {
          holder.style.width = wrap.dataset.prevMermaidW || "";
          holder.style.height = wrap.dataset.prevMermaidH || "";
          delete wrap.dataset.prevMermaidW;
          delete wrap.dataset.prevMermaidH;
        }

        wrap.classList.toggle("mermaidWrapMax", max);
        document.body.classList.toggle("noScroll", max);
        btnToggle.textContent = max ? t("mermaid.zoomOut") : t("mermaid.zoomIn");
        scheduleFit();
      });

      if (typeof ResizeObserver === "function") {
        try {
          const ro = new ResizeObserver(() => scheduleFit());
          ro.observe(holder);
          ro.observe(wrap);
        } catch { }
      }

      scheduleFit();
      try {
        if (typeof document?.fonts?.ready?.then === "function") {
          document.fonts.ready.then(() => scheduleFit()).catch(() => { });
        }
      } catch { }
      setTimeout(() => scheduleFit(), 60);
      setTimeout(() => scheduleFit(), 240);
    } catch (e) {
      const msg = e?.message ? String(e.message) : String(e);
      logUiEvent("mermaid_render_error", { idx: String(cur), msg });

      try {
        holder.innerHTML = "";
        const head = document.createElement("div");
        const mv = globalThis.mermaid;
        const v = typeof mv?.version === "string" ? mv.version : "";
        const ver = v ? t("mermaid.versionHint", { v }) : "";
        head.textContent = t("mermaid.renderFailSuppressed", { msg, ver }).trim();

        const preErr = document.createElement("pre");
        preErr.textContent = code;

        holder.appendChild(head);
        holder.appendChild(preErr);
      } catch {
        holder.textContent = t("mermaid.renderFail", { msg, code });
      }

      errs.push(msg);
    }
  }

  if (errs.length) {
    const sig = errs.join("\n").slice(0, 800);
    if (root.dataset.lastMermaidErrSig !== sig) {
      root.dataset.lastMermaidErrSig = sig;
      appendChatMessage({ role: "assistant", content: t("mermaid.renderFailSummary", { count: errs.length, first: errs[0] }), meta: true });
    }
  }
}

const SECTION_DEFAULT_TITLES = {
  thinking: "Thinking Process",
  diagnosis: "Diagnosis Conclusion",
  failure: "Failure Process & Causal Analysis",
  reference: "Reference Cases",
  sequence: "Sequence Diagram",
  signaling: "Signaling Table",
};

const SECTION_KEY_ALIASES = {
  thinking: "thinking",
  formal: "formal",
  diagnosis: "diagnosis",
  conclusion: "diagnosis",
  failure: "failure",
  analysis: "failure",
  reference: "reference",
  references: "reference",
  case: "reference",
  cases: "reference",
  sequence: "sequence",
  diagram: "sequence",
  signaling: "signaling",
  table: "signaling",
};

const RESPONSE_SECTION_RULES = [
  { key: "thinking", kind: "thinking", re: /^(#{1,6}\s*)?(<\s*thinking\s*过程\s*>|thinking process|思考过程)\s*[:：]?\s*$/i },
  { key: "formal", kind: "marker", re: /^(#{1,6}\s*)?(<\s*正式答复\s*>|正式答复|formal answer|final answer)\s*[:：]?\s*$/i },
  { key: "diagnosis", kind: "formal", re: /^(#{1,6}\s*)?(<\s*诊断结论\s*>|诊断结论|diagnosis conclusion)\s*[:：]?\s*$/i },
  { key: "failure", kind: "formal", re: /^(#{1,6}\s*)?(<\s*故障过程与因果关系分析\s*>|故障过程与因果关系分析|failure process description|failure process and causal analysis|failure process)\s*[:：]?\s*$/i },
  { key: "reference", kind: "formal", re: /^(#{1,6}\s*)?(<\s*参考案例\s*>|参考案例|reference cases?|reference case)\s*[:：]?\s*$/i },
  { key: "sequence", kind: "formal", re: /^(#{1,6}\s*)?(<\s*时序图\s*>|时序图|信令时序图|signaling sequence diagram|sequence diagram)\s*[:：]?\s*$/i },
  { key: "signaling", kind: "formal", re: /^(#{1,6}\s*)?(<\s*信令表\s*>|信令表|关键信令表|signaling table|key signaling table)\s*[:：]?\s*$/i },
];

function parseSectionMarkerLine(line) {
  const src = String(line ?? "").trim();
  const m = src.match(/^<\s*(section|sec)\s*:\s*([a-z_]+)\s*(?:\|\s*([^>]+?))?\s*>$/i);
  if (!m) return null;
  const rawKey = String(m[2] || "").toLowerCase();
  const key = SECTION_KEY_ALIASES[rawKey];
  if (!key) return null;
  const title = String(m[3] || "").trim();
  const kind = key === "thinking" ? "thinking" : key === "formal" ? "marker" : "formal";
  return { key, kind, title };
}

function normalizeSectionTitle(line) {
  const src = String(line ?? "").trim();
  if (!src) return "";
  const cut = src.replace(/^#{1,6}\s*/, "").replace(/[：:]\s*$/, "").trim();
  const m = cut.match(/^<\s*([^>]+)\s*>$/);
  return String(m?.[1] || cut).trim();
}

function matchResponseSection(line) {
  const marker = parseSectionMarkerLine(line);
  if (marker) return marker;
  const src = String(line ?? "");
  for (const rule of RESPONSE_SECTION_RULES) {
    if (rule.re.test(src)) {
      return { key: rule.key, kind: rule.kind, title: normalizeSectionTitle(src) };
    }
  }
  return null;
}

function parseStructuredResponse(src) {
  const lines = String(src ?? "").split(/\r?\n/);
  const sections = [];
  let current = null;
  let found = false;
  let formalStarted = false;
  let leading = false;

  for (const line of lines) {
    const hit = matchResponseSection(line);
    if (hit) {
      found = true;
      if (hit.kind === "marker") {
        formalStarted = true;
        current = null;
        continue;
      }
      const title = hit.title || SECTION_DEFAULT_TITLES[hit.key] || "";
      if (current && !current.content.trim() && current.key === hit.key) {
        current.title = title;
        continue;
      }
      current = { key: hit.key, title, content: "" };
      sections.push(current);
      if (hit.kind === "formal") formalStarted = true;
      continue;
    }
    if (!found && line.trim()) {
      leading = true;
      break;
    }
    if (current) current.content += `${line}\n`;
  }

  if (!found || leading || !sections.length) return null;
  const filtered = sections.filter((s, idx) => s.content.trim() || (streamRunning && idx === sections.length - 1));
  if (!filtered.length) return null;
  return { sections: filtered, formalStarted };
}

function getStructuredState(el) {
  const raw = String(el?.dataset?.sectionState || "");
  const parsed = safeParseJson(raw, {});
  const expanded = typeof parsed?.expanded === "object" && parsed.expanded ? parsed.expanded : {};
  const manual = typeof parsed?.manual === "object" && parsed.manual ? parsed.manual : {};
  return { expanded, manual };
}

function setStructuredState(el, state) {
  if (!el) return;
  el.dataset.sectionState = JSON.stringify(state || {});
}

function scheduleMermaidRender(el) {
  if (!el) return;
  const collapsed = Boolean(el.closest(".chatSectionCollapsed"));
  const connected = Boolean(el.isConnected);
  const rootTag = el?.tagName ? String(el.tagName) : "";
  const rootClass = el?.className ? String(el.className) : "";
  if (collapsed) {
    if (!el.dataset.mermaidDeferLogged) {
      el.dataset.mermaidDeferLogged = "1";
      logUiEvent("mermaid_defer", { reason: "collapsed", rootTag, rootClass });
    }
    return;
  }
  const attempt = Number.parseInt(el.dataset.mermaidAttempt || "0", 10) || 0;
  if (!connected) {
    if (attempt < 8) {
      el.dataset.mermaidAttempt = String(attempt + 1);
      logUiEvent("mermaid_defer", { reason: "not_connected", attempt: String(attempt), rootTag, rootClass });
      setTimeout(() => scheduleMermaidRender(el), 50);
      return;
    }
  }
  delete el.dataset.mermaidAttempt;
  delete el.dataset.mermaidDeferLogged;
  queueMicrotask(() => {
    renderMermaidBlocksInto(el).catch(() => { });
  });
}

function renderMarkdownTextInto(el, text) {
  const src = ensureMermaidFence(String(text ?? ""));
  el.classList.add("markdown");
  const hasMarked = typeof marked !== "undefined" && typeof marked.parse === "function";
  const hasPurify = typeof DOMPurify !== "undefined" && typeof DOMPurify.sanitize === "function";
  if (hasMarked && hasPurify) {
    try {
      const html = marked.parse(src, { breaks: true });
      el.innerHTML = DOMPurify.sanitize(html);
    } catch (e) {
      el.textContent = src;
      const msg = e?.message ? String(e.message) : String(e);
      appendChatMessage({ role: "assistant", content: t("markdown.renderFail", { msg }), meta: true });
      return false;
    }

    if (!streamRunning) scheduleMermaidRender(el);
    return true;
  }
  el.textContent = src;
  return false;
}

function renderStructuredResponseInto(el, parsed) {
  const state = getStructuredState(el);
  const activeKey = parsed.sections.length ? parsed.sections[parsed.sections.length - 1].key : "";
  el.innerHTML = "";
  el.classList.remove("markdown");

  const root = document.createElement("div");
  root.className = "chatSections";

  for (const sec of parsed.sections) {
    const section = document.createElement("section");
    section.className = "chatSection";
    section.dataset.key = sec.key;

    let expanded = false;
    if (sec.key === "diagnosis") expanded = true;
    else if (sec.key === "thinking") expanded = !parsed.formalStarted;
    else if (streamRunning) expanded = sec.key === activeKey;
    else expanded = false;

    if (!streamRunning && state.manual?.[sec.key]) {
      expanded = Boolean(state.expanded?.[sec.key]);
    }

    if (!expanded) section.classList.add("chatSectionCollapsed");

    const header = document.createElement("button");
    header.type = "button";
    header.className = "chatSectionToggle";
    header.setAttribute("aria-expanded", expanded ? "true" : "false");

    const caret = document.createElement("span");
    caret.className = "chatSectionCaret";
    caret.textContent = expanded ? "▾" : "▸";

    const title = document.createElement("span");
    title.className = "chatSectionTitle";
    title.textContent = sec.title || "";

    header.appendChild(caret);
    header.appendChild(title);

    const body = document.createElement("div");
    body.className = "chatSectionBody";

    let contentToRender = sec.content;
    if (sec.key === "sequence") {
      const trimmed = String(sec.content || "").trim();
      if (trimmed && !trimmed.startsWith("```")) {
        contentToRender = "```mermaid\n" + sec.content + "\n```";
      }
    }
    renderMarkdownTextInto(body, contentToRender);

    header.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const nextCollapsed = section.classList.toggle("chatSectionCollapsed");
      const nextExpanded = !nextCollapsed;
      header.setAttribute("aria-expanded", nextExpanded ? "true" : "false");
      caret.textContent = nextExpanded ? "▾" : "▸";
      const nextState = getStructuredState(el);
      nextState.manual[sec.key] = true;
      nextState.expanded[sec.key] = nextExpanded;
      setStructuredState(el, nextState);
      if (nextExpanded) {
        setTimeout(() => {
          renderMermaidBlocksInto(body).catch(() => { });
        }, 10);
      }
    });

    section.appendChild(header);
    section.appendChild(body);
    root.appendChild(section);
  }

  el.appendChild(root);
}

function renderMarkdownInto(el, text) {
  const src = String(text ?? "");
  const parsed = parseStructuredResponse(src);
  if (parsed) {
    renderStructuredResponseInto(el, parsed);
    return;
  }
  renderMarkdownTextInto(el, src);
}

function updateChatActionButton() {
  if (!els.chatAction) return;
  const sendText = t("chat.send");
  const stopText = t("chat.stop");
  const isStop = Boolean(streamRunning);
  els.chatAction.textContent = isStop ? stopText : sendText;
  els.chatAction.dataset.mode = isStop ? "stop" : "send";
}

function setChatBusy(b) {
  if (els.chatInput) els.chatInput.disabled = b;
  if (els.btnAnalyze) els.btnAnalyze.disabled = b;
  if (els.chatAction) els.chatAction.disabled = streamRunning ? false : b;
  updateChatActionButton();
}

function scrollDockToBottom() {
  if (!els.chatMessages) return;
  els.chatMessages.scrollTop = els.chatMessages.scrollHeight;
}

function scrollReportToBottom() {
  if (!els.reportMessages) return;
  els.reportMessages.scrollTop = els.reportMessages.scrollHeight;
}

function scrollChatToBottom() {
  scrollDockToBottom();
}

function extractFencedJson(markdown) {
  const src = String(markdown ?? "");
  const m = src.match(/```json\s*([\s\S]*?)```/i);
  const code = m?.[1] ? String(m[1]) : "";
  const v = code.trim();
  return v ? v : null;
}

function isSummaryMarkdown(markdown) {
  const src = String(markdown ?? "");
  const head = src.trim();
  if (!(head.startsWith("摘要：") || head.toLowerCase().startsWith("summary:"))) return false;
  return Boolean(extractFencedJson(src));
}

function shouldUseWideMessage(m) {
  if (!m || m.meta) return false;
  if (m.role !== "assistant") return false;
  const s = String(m.content ?? "");
  return (
    s.includes("信令时序图：") ||
    s.includes("关键信令表：") ||
    s.toLowerCase().includes("signaling sequence diagram:") ||
    s.toLowerCase().includes("key signaling table:") ||
    s.toLowerCase().includes("<section:sequence") ||
    s.toLowerCase().includes("<section:signaling")
  );
}

function splitChatTitleAndBody(raw) {
  const src = String(raw ?? "");
  const m = src.match(
    /^\s*(摘要|Summary|信令时序图|Signaling sequence diagram|关键信令表|Key signaling table|追加信令表|Append signaling table)\s*[:：]\s*(?:\r?\n+)*/i
  );
  if (!m) return { title: "", body: src };
  return { title: m[1] || "", body: src.slice(m[0].length) };
}

function createChatNode(idx, m) {
  const wrap = document.createElement("div");
  wrap.className = "chatMsg";
  wrap.dataset.idx = String(idx);

  if (m.meta) {
    wrap.classList.add("chatMsgMeta");
    const content = document.createElement("div");
    content.className = "chatMsgContent";
    content.textContent = String(m.content ?? "");
    wrap.appendChild(content);
    renderChatActionsForNode(wrap, m);
    return wrap;
  }

  if (m.role === "user") wrap.classList.add("chatMsgUser");
  else wrap.classList.add("chatMsgAssistant");

  if (shouldUseWideMessage(m)) wrap.classList.add("chatMsgWide");

  const raw = String(m.content ?? "");
  const split = m.role === "assistant" ? splitChatTitleAndBody(raw) : { title: "", body: raw };
  const title = split.title;
  const bodyText = split.body;

  const getCopyText = () => {
    const latest = chatMessages?.[idx]?.content;
    if (typeof latest !== "undefined") return String(latest ?? "");
    return raw;
  };

  const btnCopy = document.createElement("button");
  btnCopy.type = "button";
  btnCopy.className = "chatCopyBtn";
  btnCopy.title = t("common.copy");
  btnCopy.setAttribute("aria-label", t("common.copy"));

  const copyIcon = document.createElement("span");
  copyIcon.className = "icon";
  copyIcon.textContent = "⧉";
  btnCopy.appendChild(copyIcon);

  btnCopy.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    await copyWithUiFeedback(
      getCopyText(),
      () => appendChatMessage({ role: "assistant", content: t("common.copied"), meta: true }),
      (err) => appendChatMessage({ role: "assistant", content: formatErrorForUi(err), meta: true })
    );
  });

  const head = document.createElement("div");
  head.className = "chatMsgHead";
  if (!title) head.classList.add("chatMsgHeadNoTitle");

  if (title) {
    const t = document.createElement("div");
    t.className = "chatMsgTitle";
    t.textContent = title;
    head.appendChild(t);
  }
  head.appendChild(btnCopy);

  const content = document.createElement("div");
  content.className = "chatMsgContent";

  const isSummary =
    m.role === "assistant" && (String(title || "").toLowerCase() === "摘要" || String(title || "").toLowerCase() === "summary" || isSummaryMarkdown(raw)) && Boolean(extractFencedJson(raw));

  if (isSummary) {
    const jsonText = extractFencedJson(raw) || "";

    content.classList.add("chatSummary");

    const bubble = document.createElement("button");
    bubble.type = "button";
    bubble.className = "summaryBubble";
    bubble.textContent = t("summary.expand");

    const pre = document.createElement("pre");
    pre.className = "summaryPre";
    pre.textContent = jsonText;

    bubble.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const next = !content.classList.contains("summaryExpanded");
      content.classList.toggle("summaryExpanded", next);
      bubble.textContent = next ? t("summary.collapse") : t("summary.expand");
    });

    content.appendChild(bubble);
    content.appendChild(pre);
  } else if (m.role === "assistant") {
    renderMarkdownInto(content, bodyText);
  } else {
    content.textContent = raw;
  }

  wrap.appendChild(head);
  wrap.appendChild(content);
  renderChatActionsForNode(wrap, m);
  return wrap;
}

function getEffectiveReportEndIdx() {
  if (buildingReport) return chatMessages.length;
  const n = Number(reportEndIdx);
  if (!Number.isFinite(n)) return 0;
  return clamp(Math.floor(n), 0, chatMessages.length);
}

function renderReportAll() {
  if (!els.reportMessages) return;
  els.reportMessages.innerHTML = "";

  const end = getEffectiveReportEndIdx();
  for (let i = 0; i < end; i++) {
    els.reportMessages.appendChild(createChatNode(i, chatMessages[i]));
  }
  scrollReportToBottom();
}

function renderDockAll() {
  if (!els.chatMessages) return;
  els.chatMessages.innerHTML = "";

  const start = getEffectiveReportEndIdx();
  for (let i = start; i < chatMessages.length; i++) {
    els.chatMessages.appendChild(createChatNode(i, chatMessages[i]));
  }
  scrollDockToBottom();
}

function renderChatAll() {
  renderReportAll();
  renderDockAll();
  syncSigPagerStateFromMessages();
}

function appendChatMessage(m) {
  const idx = chatMessages.length;
  chatMessages.push({
    role: m.role,
    content: String(m.content ?? ""),
    meta: Boolean(m.meta ?? false),
    localOnly: Boolean(m.localOnly ?? false),
    actions: Array.isArray(m.actions) ? safeParseJson(JSON.stringify(m.actions), []) : undefined,
  });

  const node = createChatNode(idx, chatMessages[idx]);
  const end = getEffectiveReportEndIdx();
  const inReport = buildingReport || idx < end;
  const host = inReport && els.reportMessages ? els.reportMessages : els.chatMessages;
  host.appendChild(node);

  syncSigPagerStateFromMessages();
  if (inReport) scrollReportToBottom();
  else scrollDockToBottom();

  setChatStateDirty();
  return idx;
}

window.addEventListener(
  "error",
  (e) => {
    try {
      const t = e?.target;
      const tag = t?.tagName ? String(t.tagName).toUpperCase() : "";
      if (tag === "SCRIPT") {
        const src = t?.src ? String(t.src) : "(inline)";
        appendChatMessage({ role: "assistant", content: t("errors.scriptLoadFail", { src }), meta: true });
        return;
      }

      const msg = t("errors.uiRuntimeError", {
        message: e?.message || "unknown",
        file: e?.filename || "?",
        line: e?.lineno || "?",
      });
      appendChatMessage({ role: "assistant", content: msg, meta: true });
    } catch { }
  },
  true
);

window.addEventListener("unhandledrejection", (e) => {
  try {
    const reason = e?.reason?.message ? e.reason.message : String(e?.reason ?? "unknown");
    appendChatMessage({ role: "assistant", content: t("errors.unhandledPromise", { reason }), meta: true });
  } catch { }
});

function updateChatMessage(idx, content) {
  if (!chatMessages[idx]) return;
  chatMessages[idx].content = String(content ?? "");

  const sel = `[data-idx="${idx}"]`;
  const node = els.reportMessages?.querySelector(sel) || els.chatMessages.querySelector(sel);
  if (!node) return;

  if (chatMessages[idx].meta) {
    const contentEl = node.querySelector(".chatMsgContent");
    if (contentEl) contentEl.textContent = chatMessages[idx].content;
    else node.textContent = chatMessages[idx].content;
    renderChatActionsForNode(node, chatMessages[idx]);
    return;
  }

  const contentEl = node.querySelector(".chatMsgContent");
  if (!contentEl) return;

  if (chatMessages[idx].role === "assistant") renderMarkdownInto(contentEl, chatMessages[idx].content);
  else contentEl.textContent = chatMessages[idx].content;

  renderChatActionsForNode(node, chatMessages[idx]);

  const inReport = Boolean(els.reportMessages && els.reportMessages.contains(node));
  if (inReport) scrollReportToBottom();
  else scrollDockToBottom();

  setChatStateDirty();
}

function clearChat() {
  chatMessages = [];
  currentReport = null;
  reportEndIdx = 0;
  buildingReport = false;
  renderChatAll();
  setChatStateDirty();
}

function getActiveTabName() {
  if (els.tabTable.classList.contains("tabBtnActive")) return "table";
  if (els.tabSummary.classList.contains("tabBtnActive")) return "summary";
  return "mermaid";
}

function setTab(name) {
  const tab = name === "table" ? "table" : name === "summary" ? "summary" : "mermaid";

  els.tabMermaid.classList.toggle("tabBtnActive", tab === "mermaid");
  els.tabTable.classList.toggle("tabBtnActive", tab === "table");
  els.tabSummary.classList.toggle("tabBtnActive", tab === "summary");

  els.panelMermaid.classList.toggle("tabPanelActive", tab === "mermaid");
  els.panelTable.classList.toggle("tabPanelActive", tab === "table");
  els.panelSummary.classList.toggle("tabPanelActive", tab === "summary");

  if (tab === "mermaid" && mermaidPanZoom) {
    try {
      mermaidPanZoom.resize();
      mermaidPanZoom.fit();
      mermaidPanZoom.center();
    } catch { }
  }

  saveUiState();
}

function setView(name) {
  const view = name === "settings" ? "settings" : "app";
  els.viewApp.classList.toggle("viewHidden", view !== "app");
  els.viewSettings.classList.toggle("viewHidden", view !== "settings");
  if (els.navSettings) els.navSettings.classList.toggle("navBtnActive", view === "settings");
  saveUiState();
}

function buildChatPayload(excludeTrailingEmptyAssistant) {
  const msgs = chatMessages
    .filter((m) => !m.meta && !m.localOnly)
    .map((m) => ({ role: m.role, content: m.content }));
  if (excludeTrailingEmptyAssistant && msgs.length) {
    const last = msgs[msgs.length - 1];
    if (last.role === "assistant" && !String(last.content || "").trim()) msgs.pop();
  }
  return msgs;
}

function isPlainChatAllowed(authState) {
  const state = String(authState?.state || "").trim();
  return state === "online_active" || state === "offline_full";
}

async function ensureUsageAuthState() {
  if (usageAuthStateCache && typeof usageAuthStateCache === "object") return usageAuthStateCache;
  if (typeof invoke !== "function") return null;
  try {
    const auth = await invoke("usage_auth_state");
    usageAuthStateCache = auth && typeof auth === "object" ? auth : null;
  } catch {
    usageAuthStateCache = null;
  }
  return usageAuthStateCache;
}

async function runChatCompletion(assistantIdx, cfg) {
  if (streamRunning) throw new Error(t("errors.streamRunning"));

  const payload = buildChatPayload(true);
  const hasReport = Boolean(currentReport);

  if (!hasReport) {
    const authState = await ensureUsageAuthState();
    if (!isPlainChatAllowed(authState)) throw new Error(t("chat.noPcapPaidOnly"));
  }

  if (!cfg.stream) {
    const txt = hasReport
      ? await invoke("llm_chat", { cfg, report: currentReport, messages: payload })
      : await invoke("llm_chat_plain", { cfg, messages: payload });
    updateChatMessage(assistantIdx, txt);
    return;
  }

  const eventApi = tauriGlobal?.event;
  if (!eventApi?.listen) throw new Error(t("errors.noEventApi"));

  streamRunning = true;
  updateChatActionButton();
  setChatBusy(true);
  let buf = "";

  const unlistenChunk = await eventApi.listen("llm_stream_chunk", (e) => {
    const delta = e?.payload?.delta ?? "";
    buf += String(delta);
    updateChatMessage(assistantIdx, buf);
  });

  const unlistenDone = await eventApi.listen("llm_stream_done", () => {
    unlistenChunk();
    unlistenDone();
    streamRunning = false;
    updateChatActionButton();
    updateChatMessage(assistantIdx, buf);
    setChatBusy(false);
  });

  try {
    if (hasReport) {
      await invoke("llm_chat_stream", { cfg, report: currentReport, messages: payload });
    } else {
      await invoke("llm_chat_plain_stream", { cfg, messages: payload });
    }
  } catch (e) {
    try {
      unlistenChunk();
      unlistenDone();
    } catch { }
    streamRunning = false;
    updateChatActionButton();
    throw e;
  }
}

function applyLicenseStatus(status) {
  licenseStatusCache = status && typeof status === "object" ? status : null;
  updateLicenseSectionVisibility();
  if (!els.licenseStatus) return;
  if (!licenseStatusCache) {
    els.licenseStatus.textContent = t("license.statusUnknown");
    return;
  }
  if (licenseStatusCache.ok) {
    const name = licenseStatusCache.name || "";
    const exp = licenseStatusCache.expire || "";
    const isTrial = String(licenseStatusCache.kind || "").toLowerCase() === "trial";
    const sep = getLang().startsWith("zh") ? "，" : ", ";
    const trialTag = isTrial ? "试用授权" : "";
    const detail = [name, trialTag, exp ? t("license.detailExpire", { exp }) : ""].filter(Boolean).join(sep);
    els.licenseStatus.textContent = detail ? t("license.statusAuthedWithDetail", { detail }) : t("license.statusAuthed");
  } else {
    const reason = licenseStatusCache.reason || t("common.unknown");
    els.licenseStatus.textContent = t("license.statusUnAuthed", { reason });
  }
}

async function refreshLicenseStatus() {
  if (typeof invoke !== "function") return;
  try {
    const st = await invoke("license_status");
    applyLicenseStatus(st);
  } catch {
    applyLicenseStatus(null);
  }
}

els.saveCfg?.addEventListener("click", saveCfg);
els.loadCfg?.addEventListener("click", loadCfg);

const hasTauriApi = typeof invoke === "function" && typeof open === "function";
if (!hasTauriApi) {
  if (els.summaryBox) {
    els.summaryBox.textContent = t("errors.noTauriApiSummary");
  }
  if (els.statusBar) {
    els.statusBar.textContent = t("errors.noTauriApiStatus");
  }
  if (els.pickPcap) els.pickPcap.disabled = true;
  if (els.btnAnalyze) els.btnAnalyze.disabled = true;
  if (els.openArtifacts) els.openArtifacts.disabled = true;
} else {
  refreshLicenseStatus();
}

els.btnExportFeature?.addEventListener("click", async () => {
  if (typeof invoke !== "function") return;
  try {
    if (typeof save !== "function") throw new Error(t("errors.noDialogSave"));
    const out = await save({
      title: t("license.exportDialogTitle"),
      defaultPath: "llmshark_feature.json",
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (typeof out !== "string" || !out.trim()) return;
    await invoke("license_export_feature", { path: out });
    window.alert?.("机器特征已导出：" + out);
    await refreshLicenseStatus();
  } catch (e) {
    window.alert?.("导出机器特征失败：" + String(e));
  }
});

els.btnImportLicense?.addEventListener("click", async () => {
  if (typeof invoke !== "function") return;
  if (typeof open !== "function") return;
  const picked = await open({
    title: t("dialogs.importLicenseTitle"),
    multiple: false,
    filters: [{ name: "License", extensions: ["json"] }],
  });
  if (typeof picked !== "string" || !picked.trim()) return;
  const st = await invoke("license_import", { path: picked });
  applyLicenseStatus(st);
});

els.btnBuyPerpetual?.addEventListener("click", async () => {
  try {
    await openPathInShell("https://k.youshop10.com/JFXX=EzQ");
  } catch (e) {
    flashText(els.licenseStatus, errToMessage(e) || t("common.unknown"), 2000);
  }
});

els.btnBuyYearly?.addEventListener("click", async () => {
  try {
    await openPathInShell("https://k.youshop10.com/UmHGLPhi");
  } catch (e) {
    flashText(els.licenseStatus, errToMessage(e) || t("common.unknown"), 2000);
  }
});

els.btnSoftwareUpdate?.addEventListener("click", async () => {
  try {
    await openPathInShell("https://github.com/kinghighland/llm-shark-release");
  } catch (e) {
    flashText(els.licenseStatus, errToMessage(e) || t("common.unknown"), 2000);
  }
});

els.pickPcap.addEventListener("click", async () => {
  if (typeof open !== "function") return;
  const picked = await open({
    title: t("dialogs.openPcapTitle"),
    multiple: false,
    filters: [{ name: "PCAP", extensions: ["pcap", "pcapng"] }],
  });
  if (typeof picked === "string") {
    els.pcapPath.value = picked;
    if (els.pcapPath) els.pcapPath.title = picked;
    els.btnAnalyze.disabled = false;
    if (els.openArtifacts) els.openArtifacts.disabled = true;
    if (els.statusBar) els.statusBar.textContent = t("app.pickedFileHint");

    const s = getActiveSession();
    if (s) {
      s.pcapPath = picked;
      s.updatedAt = nowIso();
      saveSessionsState();
      if (!streamRunning) renderSessionList();
    }
  }
});

els.pickKbUser?.addEventListener("click", async () => {
  if (typeof open !== "function") return;
  const picked = await open({
    title: t("dialogs.openKbTitle"),
    multiple: false,
    filters: [{ name: "KB Markdown", extensions: ["md"] }],
  });
  if (typeof picked === "string" && els.kbUserPath) {
    els.kbUserPath.value = picked;
    els.kbUserPath.title = picked;
  }
});

els.pickPrompt?.addEventListener("click", async () => {
  if (typeof open !== "function") return;
  const picked = await open({
    title: t("dialogs.openPromptTitle"),
    multiple: false,
    filters: [{ name: t("dialogs.promptMarkdown"), extensions: ["md"] }],
  });
  if (typeof picked === "string" && els.promptPath) {
    els.promptPath.value = picked;
    els.promptPath.title = picked;
  }
});

els.pickTshark?.addEventListener("click", async () => {
  if (typeof open !== "function") return;
  const picked = await open({
    title: t("dialogs.openTsharkTitle"),
    multiple: false,
    filters: [{ name: "Executable", extensions: ["exe"] }],
  });
  if (typeof picked === "string" && els.tsharkPath) {
    const v = normalizeTsharkDisplayPath(picked);
    detectedTsharkPath = v;
    els.tsharkPath.value = v;
    els.tsharkPath.title = v;
  }
});

els.detectTshark?.addEventListener("click", async () => {
  const found = normalizeTsharkDisplayPath(await detectTsharkPath());
  if (!found) {
    flashText(els.tsharkHint, t("settings.tsharkNotFound"), 2000);
    return;
  }
  detectedTsharkPath = found;
  if (els.tsharkPath) {
    els.tsharkPath.value = found;
    els.tsharkPath.title = found;
  }
  flashText(els.tsharkHint, t("settings.tsharkDetected", { path: found }), 2000);
});

els.toggleApiKey?.addEventListener("click", () => {
  if (!els.apiKey) return;
  const isPwd = String(els.apiKey.type || "").toLowerCase() === "password";
  els.apiKey.type = isPwd ? "text" : "password";
  if (els.toggleApiKey) els.toggleApiKey.textContent = isPwd ? t("settings.hide") : t("settings.show");
});




els.btnAnalyze.addEventListener("click", async () => {
  if (typeof invoke !== "function") return;
  const pcap = els.pcapPath.value.trim();
  if (!pcap) return;

  setBusy(true);
  setChatBusy(true);
  clearChat();
  buildingReport = true;
  reportEndIdx = 0;
  currentSigRows = null;
  currentSigOffset = 0;
  appendChatMessage({ role: "assistant", content: t("analyze.fetchingSummary"), meta: true });
  if (els.openArtifacts) els.openArtifacts.disabled = true;

  try {
    const cfg = getCfg();
    const tsharkFromUi = String(els.tsharkPath?.value || "").trim();
    let tsharkPath = tsharkFromUi || String(cfg.tshark_path || "").trim() || detectedTsharkPath;
    if (!tsharkPath) {
      const found = await detectTsharkPath();
      if (found) {
        detectedTsharkPath = found;
        tsharkPath = found;
        if (els.tsharkPath) {
          els.tsharkPath.value = found;
          els.tsharkPath.title = found;
        }
      }
    }
    if (!tsharkPath) {
      appendChatMessage({ role: "assistant", content: t("settings.tsharkNotFound"), meta: true });
      return;
    }
    const tshark = tsharkPath || null;

    // Don't pass maxSizeKb, let backend determine based on license
    const summary = await invoke("pcap_summary", { pcapPath: pcap, tshark, filter: null, maxSizeKb: null });
    setStatusBar(summary, null);

    const protos = Array.isArray(summary?.protocols) ? summary.protocols.filter(Boolean) : [];
    if (protos.length) {
      appendChatMessage({ role: "assistant", content: t("analyze.detectedProtocols", { protocols: protos.join(", ") }), meta: true });
    }

    const analyzable = Boolean(summary?.analyzable ?? summary?.call?.analyzable_voice_call);
    const tooLarge = Boolean(summary?.too_large);
    // Get actual max_size_kb from backend response
    const maxSizeKb = summary?.max_size_kb || 500;

    if (tooLarge) {
      appendChatMessage({ role: "assistant", content: t("analyze.tooLarge", { size: `${maxSizeKb}KB` }), meta: true });
      return;
    }

    if (!analyzable) {
      const reason = summary?.analyzable_reason ?? summary?.call?.analyzable_reason ?? "unknown";
      appendChatMessage({ role: "assistant", content: t("analyze.notAnalyzable", { reason }), meta: true });
      return;
    }

    appendChatMessage({ role: "assistant", content: t("analyze.summaryOk"), meta: true });

    const kbUserPath = String(cfg.kb_user_path || "").trim();
    const report = await invoke("pcap_analyze", {
      pcapPath: pcap,
      tshark,
      filter: null,
      maxSizeKb: null, // Let backend determine based on license
      kbPath: kbUserPath || null,
      kbEnabled: Boolean(cfg.use_kb),
      uiLang: getUiLang(),
    });
    currentReport = report;

    try {
      const base = String(pcap).split(/[/\\]/).pop() || pcap;
      document.title = t("app.documentTitleWithFile", { file: base });
      localStorage.setItem("llm_last_report", JSON.stringify(report));

      const s = getActiveSession();
      if (s) {
        s.title = base;
        s.updatedAt = nowIso();
        saveSessionsState();
        if (!streamRunning) renderSessionList();
      }
    } catch { }

    setStatusBar(summary, report);

    const sigCsvPath = report?.outputs?.signaling_csv;
    const sigJsonPath = report?.outputs?.signaling_json;
    const sig = sigJsonPath ? await invoke("read_json_file", { path: sigJsonPath }) : [];

    const prompt =
      t("analyze.defaultPrompt");
    appendChatMessage({ role: "user", content: prompt });
    const assistantIdx = appendChatMessage({ role: "assistant", content: "" });

    await runChatCompletion(assistantIdx, cfg);

    if (Array.isArray(sig) && sig.length) {
      currentSigRows = sig;
      currentSigOffset = Math.min(sig.length, 40);

      const keyTitle = t("sig.keyTableTitle");
      appendChatMessage({
        role: "assistant",
        content: `<section:signaling|${keyTitle}>\n\n${rowsToMarkdownTable(sig, 40)}`,
        meta: false,
        localOnly: true,
      });

      sigPagerMsgIdx = appendChatMessage({
        role: "assistant",
        content: t("sig.fullHint", { count: sig.length }),
        meta: false,
        localOnly: true,
        actions: [{ type: "sig_next_page", label: t("sig.nextPage", { pageSize: SIG_PAGE_SIZE }) }],
      });
    }

    reportEndIdx = chatMessages.length;
    buildingReport = false;
    setChatStateDirty();
  } catch (e) {
    appendChatMessage({ role: "assistant", content: formatErrorForUi(e), meta: true });
  } finally {
    if (buildingReport) {
      reportEndIdx = chatMessages.length;
      buildingReport = false;
      renderChatAll();
      setChatStateDirty();
    }
    setBusy(false);
    if (!streamRunning) setChatBusy(false);
  }
});

els.navSettings?.addEventListener("click", () => setView("settings"));
els.btnTopSettings?.addEventListener("click", () => setView("settings"));
els.newSession?.addEventListener("click", () => createSession());
els.sessionList?.addEventListener("click", () => setView("app"));
setupSessionListWheel();
window.addEventListener("resize", () => renderSessionList());

els.sidebarToggle?.addEventListener("click", () => {
  const next = !document.body.classList.contains("sidebarCollapsed");
  document.body.classList.toggle("sidebarCollapsed", next);
  saveUiState({ sidebarCollapsed: next });
  renderSessionList();
});

function setAboutOpen(open) {
  if (!els.aboutOverlay) return;
  els.aboutOverlay.classList.toggle("overlayHidden", !open);
  document.body.classList.toggle("noScroll", open);
}

async function fillAboutInfo() {
  if (!els.aboutVersion || !els.aboutRuntime) return;

  let version = "-";
  let tauriVer = "";
  try {
    if (typeof tauriGlobal?.app?.getVersion === "function") version = (await tauriGlobal.app.getVersion()) || "-";
  } catch { }
  try {
    if (typeof tauriGlobal?.app?.getTauriVersion === "function") tauriVer = (await tauriGlobal.app.getTauriVersion()) || "";
  } catch { }

  els.aboutVersion.textContent = String(version || "-");

  const rt = [];
  if (tauriVer) rt.push(`Tauri ${tauriVer}`);
  rt.push(navigator.userAgent);
  els.aboutRuntime.textContent = rt.join(" / ");
}

els.btnAbout?.addEventListener("click", () => {
  setAboutOpen(true);
  fillAboutInfo().catch(() => { });
});

els.aboutClose?.addEventListener("click", () => setAboutOpen(false));
els.aboutClose2?.addEventListener("click", () => setAboutOpen(false));
els.aboutOverlay?.addEventListener("click", (e) => {
  const t = e?.target;
  if (t && t === els.aboutOverlay) setAboutOpen(false);
});

function setQrOpen(open) {
  if (!els.qrOverlay) return;
  els.qrOverlay.classList.toggle("overlayHidden", !open);
  document.body.classList.toggle("noScroll", open);
  if (!open && qrRefreshTimer) {
    clearTimeout(qrRefreshTimer);
    qrRefreshTimer = null;
  }
}

async function refreshMobileQr() {
  if (!els.qrSvgWrap || !els.qrExpires) return;
  els.qrExpires.textContent = t("qr.loading");
  els.qrSvgWrap.innerHTML = "";
  try {
    const data = await invoke("mobile_auth_qr");
    const svg = String(data?.qr_svg || "").trim();
    if (!svg) throw new Error("EMPTY_QR");
    els.qrSvgWrap.innerHTML = svg;
    const ts = Number(data?.qr_expires_at || 0);
    const dt = Number.isFinite(ts) && ts > 0 ? new Date(ts * 1000) : null;
    const when = dt && !Number.isNaN(dt.getTime()) ? dt.toLocaleString() : "-";
    els.qrExpires.textContent = t("qr.expiresAt", { time: when });
    if (qrRefreshTimer) clearTimeout(qrRefreshTimer);
    qrRefreshTimer = setTimeout(() => {
      if (!els.qrOverlay?.classList.contains("overlayHidden")) refreshMobileQr().catch(() => { });
    }, 5 * 60 * 1000);
  } catch (e) {
    els.qrSvgWrap.textContent = "";
    els.qrExpires.textContent = t("qr.generateFail", { reason: errToMessage(e) || t("common.unknown") });
  }
}

els.btnMobileQr?.addEventListener("click", () => {
  setQrOpen(true);
  refreshMobileQr().catch(() => { });
});
els.btnQrRefresh?.addEventListener("click", () => refreshMobileQr().catch(() => { }));
els.qrClose?.addEventListener("click", () => setQrOpen(false));
els.qrClose2?.addEventListener("click", () => setQrOpen(false));
els.qrOverlay?.addEventListener("click", (e) => {
  const t = e?.target;
  if (t && t === els.qrOverlay) setQrOpen(false);
});

const STORE_PLANS = [
  { id: "pro_month", tier: "Pro" },
  { id: "pro_year", tier: "Pro" },
];

function getStoreMode() {
  const raw = String(window.__LLMSHARK_ENV__?.storeMode || "").trim();
  if (raw) return raw;
  return hasTauriApi ? "native" : "browser";
}

async function storeBridgePost(type, payload) {
  const msg = { type, ...(payload && typeof payload === "object" ? payload : {}) };
  if (typeof invoke !== "function") return { ok: false, errorCode: "NO_BRIDGE" };
  try {
    const out = await invoke("native_bridge_post", { payload: JSON.stringify(msg) });
    return out && typeof out === "object" ? out : { ok: false, errorCode: "INVALID_RESPONSE" };
  } catch (e) {
    return { ok: false, errorCode: errToMessage(e) || "BRIDGE_FAILED" };
  }
}

function formatPrice(amount, currency) {
  const v = Number(amount);
  const c = String(currency || "").trim();
  if (!Number.isFinite(v) || !c) return "";
  try {
    return new Intl.NumberFormat(getUiLang(), { style: "currency", currency: c }).format(v);
  } catch {
    return `${v} ${c}`;
  }
}

function planLabel(planId, title) {
  const key = `store.plan.${planId}`;
  const label = t(key);
  if (label && label !== key) return label;
  const t2 = String(title || "").trim();
  return t2 || planId;
}

function setStoreOpen(open) {
  if (!els.storeOverlay) return;
  els.storeOverlay.classList.toggle("overlayHidden", !open);
  document.body.classList.toggle("noScroll", open);
}

function setStoreMessage(msg, ms) {
  if (!els.storeMessage) return;
  const text = String(msg || "").trim();
  if (!text) {
    els.storeMessage.textContent = "";
    return;
  }
  const delay = Number.isFinite(Number(ms)) ? Number(ms) : 6000;
  if (delay <= 0) {
    els.storeMessage.textContent = text;
    return;
  }
  flashText(els.storeMessage, text, delay);
}


let storePriceMap = {};
let storeYearSavingPercent = 0;

function buildStorePriceMap(products) {
  const out = {};
  for (const p of products || []) {
    const planId = String(p.planId || p.id || "").trim();
    if (!planId) continue;
    const price = Number(p.price);
    if (!Number.isFinite(price)) continue;
    const formattedPrice = String(p.formattedPrice || "").trim();
    out[planId] = { price, currency: p.currency, formattedPrice };
  }
  return out;
}

function computeYearSavingPercent() {
  const month = storePriceMap.pro_month;
  const year = storePriceMap.pro_year;
  if (!month || !year) return 0;
  const monthTotal = Number(month.price) * 12;
  const yearTotal = Number(year.price);
  if (!Number.isFinite(monthTotal) || !Number.isFinite(yearTotal) || monthTotal <= 0) return 0;
  const diff = monthTotal - yearTotal;
  if (diff <= 0) return 0;
  return Math.round((diff / monthTotal) * 100);
}

function formatPlanPriceValue(planId) {
  const item = storePriceMap[planId];
  if (!item) return "";
  if (item.formattedPrice) return item.formattedPrice;
  return formatPrice(item.price, item.currency);
}

function updateStoreComparePricing() {
  const monthText = formatPlanPriceValue("pro_month");
  const yearText = formatPlanPriceValue("pro_year");
  if (els.storeProMonthPrice) {
    els.storeProMonthPrice.textContent = monthText || t("store.priceUnknown");
  }
  if (els.storeProYearPrice) {
    els.storeProYearPrice.textContent = yearText || t("store.priceUnknown");
  }

  const saving = computeYearSavingPercent();
  storeYearSavingPercent = saving;
  const savingText = saving > 0 ? `-${saving}%` : "";

  if (els.storeProYearSaving) {
    if (savingText) {
      els.storeProYearSaving.textContent = savingText;
      els.storeProYearSaving.style.display = "inline-flex";
    } else {
      els.storeProYearSaving.textContent = "";
      els.storeProYearSaving.style.display = "none";
    }
  }

  if (els.storeYearSavingBadge) {
    if (savingText) {
      els.storeYearSavingBadge.textContent = `${t("store.compare.proYear.badge")} · ${savingText}`;
      els.storeYearSavingBadge.style.display = "inline-flex";
    } else {
      els.storeYearSavingBadge.textContent = "";
      els.storeYearSavingBadge.style.display = "none";
    }
  }
}

function setStorePricing(products) {
  storePriceMap = buildStorePriceMap(products);
  updateStoreComparePricing();
}

function formatExpireDate(ts) {
  const sec = Number(ts);
  if (!Number.isFinite(sec) || sec <= 0) return "";
  const d = new Date(sec * 1000);
  if (Number.isNaN(d.getTime())) return "";
  try {
    return new Intl.DateTimeFormat(getUiLang(), { year: "numeric", month: "short", day: "numeric" }).format(d);
  } catch {
    return d.toLocaleDateString();
  }
}

function bindStoreButtons() {
  const buttons = document.querySelectorAll(".storeCardBtn");
  for (const btn of buttons) {
    if (btn.dataset.bound === "1") continue;
    btn.dataset.bound = "1";
    const planId = String(btn.dataset.storePlan || "").trim();
    if (!planId) continue;

    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const r = await storeBridgePost("purchase", { productId: planId });
      if (!r || !r.ok) {
        const reason = r?.errorCode || t("common.unknown");
        const msg = t("store.purchaseFailed", { reason });
        setStoreMessage(msg, 8000);
      }
      await refreshStoreStatus();
      btn.disabled = false;
    });
  }
}

function updateStoreButtons(entitlement, authState) {
  const mode = getStoreMode();
  const entPlan = entitlement && entitlement.type ? String(entitlement.type) : "";
  const state = String(authState?.state || "").trim();
  const offlineFull = state === "offline_full";
  const buttons = document.querySelectorAll(".storeCardBtn");

  for (const btn of buttons) {
    const planId = String(btn.dataset.storePlan || "").trim();

    if (!planId) {
      if (!entPlan) {
        btn.textContent = t("store.planActive");
      } else {
        btn.textContent = t("store.planFree");
      }
      btn.disabled = true;
      btn.classList.remove("primaryBtn");
      btn.classList.add("btnGhost");
      continue;
    }

    if (offlineFull) {
      btn.textContent = t("store.planActive");
      btn.disabled = true;
      continue;
    }

    const active = entPlan === planId;
    if (active) {
      btn.textContent = t("store.planActive");
      btn.disabled = true;
    } else {
      btn.textContent = t("store.planPurchase");
      btn.disabled = mode !== "native";
    }
  }
}

async function refreshStoreStatus() {
  if (!els.storeStatusText) return;
  bindStoreButtons();
  const mode = getStoreMode();
  els.storeStatusText.textContent = t("store.statusLoading");

  if (mode !== "native") {
    els.storeStatusText.textContent = t("store.statusUnavailable");
    setStorePricing([]);
    updateStoreButtons(null, null);
    setStoreEntitlementActive(null);
    usageAuthStateCache = null;
    return;
  }

  const [products, ent, auth] = await Promise.all([
    storeBridgePost("list_products"),
    storeBridgePost("get_entitlement_status"),
    invoke("usage_auth_state").catch(() => null),
  ]);

  const list = products && products.ok && Array.isArray(products.products) ? products.products : [];
  const entitlementRaw = ent && ent.ok ? ent.entitlement || null : null;
  const authState = auth && typeof auth === "object" ? auth : null;
  usageAuthStateCache = authState;

  const state = String(authState?.state || "").trim();
  const entitlement = state === "online_active" ? entitlementRaw : null;

  setStorePricing(list);
  setStoreEntitlementActive(entitlement);

  if (!products?.ok) {
    const reason = products?.errorCode || t("common.unknown");
    const msg = t("store.listFailed", { reason });
    setStoreMessage(msg, 8000);
  }

  if (state === "offline_full") {
    els.storeStatusText.textContent = t("store.statusLicensed");
  } else if (state === "offline_trial") {
    els.storeStatusText.textContent = t("store.statusTrial");
  } else if (entitlement && entitlement.type) {
    const planText = planLabel(entitlement.type);
    const expText = formatExpireDate(entitlement.expireAt);
    els.storeStatusText.textContent = expText
      ? t("store.statusActiveExpire", { plan: planText, date: expText })
      : t("store.statusActive", { plan: planText });
  } else {
    els.storeStatusText.textContent = t("store.statusFree");
  }

  updateStoreButtons(entitlement, authState);
}

els.btnStoreCenter?.addEventListener("click", () => {
  setStoreOpen(true);
  refreshStoreStatus().catch(() => { });
});

els.storeClose?.addEventListener("click", () => setStoreOpen(false));
els.storeOverlay?.addEventListener("click", (e) => {
  const t = e?.target;
  if (t && t === els.storeOverlay) setStoreOpen(false);
});

els.storeRefresh?.addEventListener("click", () => {
  refreshStoreStatus().catch(() => { });
});

els.storeRestore?.addEventListener("click", async () => {
  const r = await storeBridgePost("restore_purchases");
  if (!r || !r.ok) {
    const reason = r?.errorCode || t("common.unknown");
    const msg = t("store.restoreFailed", { reason });
    setStoreMessage(msg, 8000);
  } else {
    setStoreMessage(t("store.restoreOk"), 2000);
  }
  refreshStoreStatus().catch(() => { });
});

els.storeManage?.addEventListener("click", async () => {
  const r = await storeBridgePost("manage_subscriptions");
  if (!r || !r.ok) {
    const reason = r?.errorCode || t("common.unknown");
    const msg = t("store.manageFailed", { reason });
    setStoreMessage(msg, 8000);
  }
});

els.storeOpenPage?.addEventListener("click", async () => {
  const r = await storeBridgePost("open_store_product_page");
  if (!r || !r.ok) {
    const reason = r?.errorCode || t("common.unknown");
    const msg = t("store.openFailed", { reason });
    setStoreMessage(msg, 8000);
  }
});

els.trialOpenInvite?.addEventListener("click", async () => {
  const url = "https://cloud.siliconflow.cn/i/S45uICVN";
  try {
    await openPathInShell(url);
  } catch {
    try {
      window.open(url, "_blank", "noopener,noreferrer");
    } catch { }
  }
});

els.trialUseTemp?.addEventListener("click", async () => {
  if (els.trialUseTemp?.disabled) return;
  const ep = String(els.endpoint?.value || "").trim();
  const md = String(els.model?.value || "").trim();
  const ak = String(els.apiKey?.value || "").trim();
  const hasExisting = Boolean(ep || md || ak);

  if (hasExisting) {
    const msg = "检测到已存在的模型参数。是否覆盖当前 Endpoint/Model/API Key？";
    let confirmed = true;
    try {
      if (typeof tauriGlobal?.dialog?.confirm === "function") {
        confirmed = await tauriGlobal.dialog.confirm(msg, { title: t("common.confirm") });
      } else {
        confirmed = window.confirm(msg);
      }
    } catch {
      confirmed = window.confirm(msg);
    }
    if (!confirmed) return;
  }

  fillSiliconFlowDefaults();
  if (els.apiKey) els.apiKey.value = TRIAL_API_KEY_PLACEHOLDER;
  saveCfg();
  setTrialOverlayOpen(false);
});

els.trialCancel?.addEventListener("click", () => setTrialOverlayOpen(false));
els.trialOverlay?.addEventListener("click", (e) => {
  const t = e?.target;
  if (t && t === els.trialOverlay) setTrialOverlayOpen(false);
});

els.aboutCopyInfo?.addEventListener("click", async () => {
  const v = String(els.aboutVersion?.textContent || "-").trim() || "-";
  const rt = String(els.aboutRuntime?.textContent || "-").trim() || "-";
  const txt = `LLM-Shark\n${t("about.version")}: ${v}\n${t("about.runtime")}: ${rt}`;
  await copyWithUiFeedback(txt, () => flashText(els.cfgHint, t("common.copied"), 1200));
});

els.btnThemeToggle?.addEventListener("click", () => {
  const t = getTheme() === "light" ? "dark" : "light";
  saveTheme(t);
});

els.btnValidateLlm?.addEventListener("click", async () => {
  if (typeof invoke !== "function") return;
  const cfg = getCfgFromInputs();

  if (els.validateStatus) {
    els.validateStatus.classList.remove("validateOk", "validateFail");
    els.validateStatus.textContent = t("settings.validating");
  }

  els.btnValidateLlm.disabled = true;
  try {
    const r = await invoke("llm_validate", { cfg });
    const detail = r && typeof r === "object" ? String(r.detail || "").trim() : "";
    const msg = detail ? t("settings.validateOkWithDetail", { detail }) : t("settings.validateOk");
    if (els.validateStatus) {
      els.validateStatus.classList.add("validateOk");
      els.validateStatus.textContent = msg;
    }
    saveCfg();
    if (String(els.apiKey?.value || "").trim() && String(els.apiKey.value).trim() !== TRIAL_API_KEY_PLACEHOLDER) {
      localStorage.setItem("llm_user_cfg_valid", "1");
      updateSiliconFlowPromo();
    }
  } catch (e) {
    if (els.validateStatus) {
      els.validateStatus.classList.add("validateFail");
      els.validateStatus.textContent = t("settings.validateFail", { reason: formatErrorForUi(e) });
    }
  } finally {
    els.btnValidateLlm.disabled = false;
  }
});

els.btnLangToggle?.addEventListener("click", (e) => {
  e?.stopPropagation?.();
  renderLangMenu();
  setLangMenuOpen(!langMenuOpen);
});

document.addEventListener("click", (e) => {
  if (!langMenuOpen) return;
  const t = e?.target;
  if (t && typeof t.closest === "function" && t.closest(".langPicker")) return;
  setLangMenuOpen(false);
});

document.addEventListener("keydown", (e) => {
  if (e?.key === "Escape") setLangMenuOpen(false);
  if (e?.key === "Escape") setAboutOpen(false);
  if (e?.key === "Escape") setTrialOverlayOpen(false);
});

async function handleChatSend() {
  if (typeof invoke !== "function") return;
  const txt = els.chatInput.value.trim();
  if (!txt) return;

  els.chatInput.value = "";
  appendChatMessage({ role: "user", content: txt });
  const assistantIdx = appendChatMessage({ role: "assistant", content: "" });

  const cfg = getCfg();
  setChatBusy(true);
  try {
    await runChatCompletion(assistantIdx, cfg);
  } catch (e) {
    updateChatMessage(assistantIdx, formatErrorForUi(e));
    setChatBusy(false);
  } finally {
    if (!streamRunning) setChatBusy(false);
  }
}

els.chatAction?.addEventListener("click", async () => {
  if (streamRunning) {
    try {
      await invoke("llm_stream_cancel");
    } catch { }
    return;
  }
  handleChatSend();
});
els.chatInput?.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    handleChatSend();
  }
});

async function runInitStep(name, fn) {
  try {
    await fn();
    return true;
  } catch (err) {
    logUiEvent("init_error", { step: name, err: errToMessage(err) });
    return false;
  }
}

async function init() {
  const startTime = performance.now();
  console.log("[Init] Starting initialization...");
  logUiEvent("init_start", { ts: new Date().toISOString() });
  scheduleMermaidAssetsLoad();

  await runInitStep("apply_lang", () => applyLang(getLang()));
  await runInitStep("load_cfg", () => Promise.resolve(loadCfg()));
  await runInitStep("tshark_detect", () => ensureTsharkDetected().catch(() => { }));
  await runInitStep("load_theme", () => Promise.resolve(loadTheme()));
  await runInitStep("dock_setup", () => Promise.resolve(setupDockInteractions()));
  await runInitStep("sessions_load", () => Promise.resolve(loadSessionsState()));
  await runInitStep("sessions_ensure", () => Promise.resolve(ensureAtLeastOneSession()));
  await runInitStep("sessions_trim", () => Promise.resolve(trimSessions()));
  await runInitStep("prepare_session", () => {
    const active = getActiveSession();
    chatMessages = Array.isArray(active?.messages) ? active.messages : [];
    currentReport = active?.report || null;
    buildingReport = false;
    const saved = Number(active?.reportEndIdx);
    const derived = deriveReportEndIdxFromMessages(chatMessages);
    reportEndIdx = active?.report && (!Number.isFinite(saved) || saved <= 0) ? derived : Number.isFinite(saved) ? saved : derived;
  });
  await runInitStep("render_chat", () => Promise.resolve(renderChatAll()));
  await runInitStep("render_sessions", () => Promise.resolve(renderSessionList()));
  await runInitStep("sync_pcap", () => {
    const active = getActiveSession();
    return Promise.resolve(syncPcapUiFromSession(active));
  });
  await runInitStep("load_ui", () => {
    loadUiState();
    const activeAfterUi = getActiveSession();
    requestAnimationFrame(() => {
      renderSessionList();
      syncPcapUiFromSession(activeAfterUi);
    });
  });
  await runInitStep("check_model_config", () => Promise.resolve(promptMissingModelConfig()));
  await runInitStep("update_chat_action", () => Promise.resolve(updateChatActionButton()));
  await runInitStep("check_license", async () => {
    const raw = localStorage.getItem(STORAGE.cfg);
    let missing = true;
    if (raw && String(raw).trim()) {
      const v = JSON.parse(raw);
      missing = !String(v?.endpoint || "").trim() || !String(v?.model || "").trim();
    }
    if (missing && typeof invoke === "function" && isSimplifiedZhLang()) {
      let st = null;
      try {
        st = await invoke("license_status");
      } catch { }
      const authed = Boolean(st && typeof st === "object" && st.ok);
      if (!authed) setView("settings");
    }
  });

  const totalTime = performance.now() - startTime;
  console.log(`[Init] ✓ Initialization completed in ${totalTime.toFixed(2)}ms (${(totalTime / 1000).toFixed(2)}s)`);
  logUiEvent("init_done", { duration_ms: totalTime.toFixed(2) });
}

init().catch((err) => {
  logUiEvent("init_error", { err: errToMessage(err) });
  console.error("[Init] ✗ Initialization failed:", err);
});
