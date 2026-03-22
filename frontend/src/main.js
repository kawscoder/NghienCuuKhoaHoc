// ======================================================
// CONFIG
// cấu hình chung của frontend
// ======================================================

const API_BASE = "http://127.0.0.1:8000";

let currentResults = [];

// ======================================================
// LANGUAGE SYSTEM
// hệ thống chuyển đổi ngôn ngữ VI / EN
// ======================================================

// ngôn ngữ hiện tại
let currentLang = "vi";


// dictionary dịch
const translations = {

  vi: {

    nav_dataset: "Dữ Liệu",
    nav_history: "Lịch Sử",
    nav_about: "Giới Thiệu",

    tab_text: "📝 Nhập Log",
    tab_upload: "📁 Tải File",
    tab_screenshot: "📸 Dán Ảnh",

    upload_hint: "Kéo & Thả logs vào đây",
    upload_subtitle: "hoặc dán dữ liệu log bên dưới",

    log_placeholder: "Dán logs của bạn vào đây...",

    supported_formats: "💡 Định dạng hỗ trợ: .json, .log, .txt",

    file_drop_title: "Thả file log của bạn vào đây",
    file_drop_subtitle: "Hỗ trợ: .json, .log, .txt (Tối đa 10MB)",

    choose_file: "Chọn File",

    screenshot_title: "Dán ảnh chụp màn hình từ clipboard",
    screenshot_subtitle: "Nhấn Ctrl+V (hoặc Cmd+V) để dán",

    analyze_button: "🚀 Phân Tích Ngay với DefLog",

    results_title: "📊 Kết Quả Phân Tích",
    no_analysis: "Chưa có phân tích. Tải lên hoặc dán logs để bắt đầu.",

  },

  en: {

    nav_dataset: "Dataset",
    nav_history: "History",
    nav_about: "About",

    tab_text: "📝 Text Log",
    tab_upload: "📁 Upload File",
    tab_screenshot: "📸 Paste Screenshot",

    upload_hint: "Drag & Drop logs here",
    upload_subtitle: "or paste log data below",

    log_placeholder: "Paste logs here...",

    supported_formats: "💡 Supported formats: .json, .log, .txt",

    file_drop_title: "Drop your log file here",
    file_drop_subtitle: "Supports: .json, .log, .txt (Max 10MB)",

    choose_file: "Choose File",

    screenshot_title: "Paste screenshot from clipboard",
    screenshot_subtitle: "Press Ctrl+V (or Cmd+V)",

    analyze_button: "🚀 Analyze with DefLog",

    results_title: "📊 Analysis Results",
    no_analysis: "No analysis yet. Upload or paste logs to begin.",

  }

};



// ======================================================
// SWITCH LANGUAGE
// ======================================================

function switchLanguage(lang) {

  currentLang = lang;

  const t = translations[lang];

  // NAV
  document.getElementById("nav-dataset").textContent = t.nav_dataset;
  document.getElementById("nav-history").textContent = t.nav_history;
  document.getElementById("nav-about").textContent = t.nav_about;

  // TABS
  document.getElementById("tab-text-label").textContent = t.tab_text;
  document.getElementById("tab-upload-label").textContent = t.tab_upload;
  document.getElementById("tab-screenshot-label").textContent = t.tab_screenshot;

  // INPUT
  document.getElementById("upload-hint").textContent = t.upload_hint;
  document.getElementById("upload-subtitle").textContent = t.upload_subtitle;

  document.getElementById("logInput").placeholder = t.log_placeholder;

  document.getElementById("supported-formats").textContent =
    t.supported_formats;

  // FILE
  document.getElementById("file-drop-title").textContent =
    t.file_drop_title;

  document.getElementById("file-drop-subtitle").textContent =
    t.file_drop_subtitle;

  document.getElementById("choose-file-btn").textContent =
    t.choose_file;

  // SCREENSHOT
  document.getElementById("screenshot-title").textContent =
    t.screenshot_title;

  document.getElementById("screenshot-subtitle").textContent =
    t.screenshot_subtitle;

  // BUTTON
  document.getElementById("analyze-button-text").textContent =
    t.analyze_button;

  // RESULT
  document.getElementById("results-title").textContent =
    t.results_title;

  document.getElementById("no-analysis-text").textContent =
    t.no_analysis;

  // ICON LANGUAGE
  if (lang === "vi") {

    document.getElementById("langIcon").textContent = "🇻🇳";
    document.getElementById("langText").textContent = "VI";

  } else {

    document.getElementById("langIcon").textContent = "🇺🇸";
    document.getElementById("langText").textContent = "EN";

  }

}



// ======================================================
// LANGUAGE SWITCH BUTTON
// ======================================================

document.getElementById("langSwitcher").addEventListener("click", () => {

  if (currentLang === "vi") {
    switchLanguage("en");
  } else {
    switchLanguage("vi");
  }

});



// ======================================================
// MENU NAVIGATION
// chuyển giữa Main / Dataset / History / About
// ======================================================

// lấy element
const navDataset = document.getElementById("nav-dataset");
const navHistory = document.getElementById("nav-history");
const navAbout = document.getElementById("nav-about");

const datasetPage = document.getElementById("datasetPage");
const historyPage = document.getElementById("historyPage");
const aboutPage = document.getElementById("aboutPage");

const mainContent = document.querySelector("main");



// ======================================================
// ẨN TẤT CẢ PAGE
// ======================================================

function hideAllPages() {

  datasetPage.classList.add("hidden");
  historyPage.classList.add("hidden");
  aboutPage.classList.add("hidden");

  mainContent.classList.add("hidden");

}



// ======================================================
// HIỆN TRANG CHÍNH
// ======================================================

function showMainPage() {

  hideAllPages();

  mainContent.classList.remove("hidden");

}

resultsPlaceholder.classList.add("hidden");
resultsContent.classList.remove("hidden");

const layout = document.getElementById("mainLayout");

layout.classList.remove("grid-cols-2");
layout.classList.add("grid-cols-[320px_1fr]");

// ======================================================
// DATASET PAGE
// ======================================================

function showDataset() {

  hideAllPages();

  datasetPage.classList.remove("hidden");

}


// ======================================================
// ABOUT PAGE
// ======================================================

function showAbout() {

  hideAllPages();

  aboutPage.classList.remove("hidden");

}



// ======================================================
// EVENT MENU
// ======================================================

navDataset.addEventListener("click", showDataset);
navHistory.addEventListener("click", showHistory);
navAbout.addEventListener("click", showAbout);



// ======================================================
// CLICK LOGO → HOME
// ======================================================

document.getElementById("app-title")
  .addEventListener("click", showMainPage);



// ======================================================
// INIT APP
// ======================================================

switchLanguage("vi");


// ======================================================
// TAB SYSTEM
// chuyển giữa 3 chế độ nhập log
// Text / Upload / Screenshot
// ======================================================

// danh sách tab
const tabs = ["text", "upload", "screenshot"];


// gắn event click cho từng tab
tabs.forEach((tab) => {

  const tabBtn = document.getElementById(`tab-${tab}`);

  if (!tabBtn) return;

  tabBtn.addEventListener("click", () => {

    setActiveTab(tab);

  });

});



// ======================================================
// HÀM SET TAB ACTIVE
// ======================================================

function setActiveTab(activeTab) {

  tabs.forEach((tab) => {

    const btn = document.getElementById(`tab-${tab}`);
    const content = document.getElementById(`content-${tab}`);

    if (!btn || !content) return;

    if (tab === activeTab) {

      btn.className =
        "tab-active px-4 py-2 rounded-lg font-medium text-sm transition-all";

      content.classList.remove("hidden");

    } else {

      btn.className =
        "tab-inactive px-4 py-2 rounded-lg font-medium text-sm transition-all";

      content.classList.add("hidden");

    }

  });

}



// ======================================================
// DRAG & DROP LOG
// hỗ trợ kéo file vào vùng input
// ======================================================

const dropZone = document.getElementById("dropZone");
const fileDropZone = document.getElementById("fileDropZone");
const logInput = document.getElementById("logInput");


// gom các zone drag
const dragZones = [dropZone, fileDropZone];

dragZones.forEach((zone) => {

  if (!zone) return;

  // khi kéo file vào
  zone.addEventListener("dragover", (e) => {

    e.preventDefault();

    zone.classList.add("dragover");

  });


  // khi rời vùng
  zone.addEventListener("dragleave", () => {

    zone.classList.remove("dragover");

  });


  // khi thả file
  zone.addEventListener("drop", (e) => {

    e.preventDefault();

    zone.classList.remove("dragover");

    const files = e.dataTransfer.files;

    if (files.length > 0) {

      readFile(files[0]);

    }

  });

});



// ======================================================
// FILE INPUT BUTTON
// nút "Chọn file"
// ======================================================

const fileInput = document.getElementById("fileInput");
const chooseFileBtn = document.getElementById("choose-file-btn");
const fileName = document.getElementById("fileName");


// click nút chọn file
chooseFileBtn.addEventListener("click", () => {

  fileInput.click();

});


// khi file được chọn
fileInput.addEventListener("change", () => {

  const file = fileInput.files[0];

  if (!file) return;

  fileName.textContent =
    `${translations[currentLang].file_selected || "Selected"}: ${file.name}`;

});

// ======================================================
// SCREENSHOT PASTE
// hỗ trợ Ctrl+V dán ảnh log
// ======================================================

let screenshotBlob = null;

document.addEventListener("paste", (e) => {

  const activeTab = document.querySelector(".tab-active");

  if (!activeTab) return;

  // chỉ hoạt động khi tab screenshot
  if (activeTab.id !== "tab-screenshot") return;

  const items = e.clipboardData.items;

  for (let item of items) {

    if (item.type.indexOf("image") !== -1) {

      screenshotBlob = item.getAsFile();

      const url = URL.createObjectURL(screenshotBlob);

      const preview = document.getElementById("screenshotPreview");
      const img = document.getElementById("screenshotImage");

      // reset ảnh cũ
      img.src = "";

      // gán ảnh mới
      img.src = url;

      preview.classList.remove("hidden");

      console.log("Screenshot pasted");

      resultsContent.innerHTML = "";
      resultsPlaceholder.classList.remove("hidden");

    }

  }

});

// ======================================================
// ANALYZE BUTTON CONTROLLER
// ======================================================

analyzeBtn.addEventListener("click", async () => {

  const activeTab = document.querySelector(".tab-active").id;

  const buttonText = analyzeBtn.querySelector("span");
  const t = translations[currentLang];

  analyzeBtn.disabled = true;
  buttonText.textContent = t.analyzing || "Analyzing...";

  try {

    let data;

    // =========================
    // TEXT MODE
    // =========================
    if (activeTab === "tab-text") {

      const logText = logInput.value.trim();

      if (!logText) {
        alert("No log data");
        analyzeBtn.disabled = false;
        buttonText.textContent = t.analyze_button;
        return;
      }

      const formData = new FormData();
      formData.append("log", logText);

      const response = await fetch(`${API_BASE}/analyze/text`, {

        method: "POST",
        body: formData

      });

      data = await response.json();
    }


    // =========================
    // FILE MODE
    // =========================
    if (activeTab === "tab-upload") {

      const file = fileInput.files[0];

      if (!file) {
        alert("No file selected");
        analyzeBtn.disabled = false;
        buttonText.textContent = t.analyze_button;
        return;
      }

      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_BASE}/analyze/file`, {
        method: "POST",
        body: formData
      });

      data = await response.json();
    }


    // =========================
    // IMAGE MODE
    // =========================
    if (activeTab === "tab-screenshot") {

      if (!screenshotBlob) {

        alert("No screenshot pasted");

        analyzeBtn.disabled = false;
        buttonText.textContent = t.analyze_button;
        return;

      }

      const formData = new FormData();
      formData.append("file", screenshotBlob, "screenshot.png");

      const response = await fetch(`${API_BASE}/analyze/image`, {

        method: "POST",
        body: formData

      });

      data = await response.json();

    }

    // =========================
    // DISPLAY RESULT
    // =========================

    let results;

    if (data.results && data.results.length > 0) {

      results = data.results;

    } else {

      results = [data];

    }

    displayResults(results);

    saveHistory(results);

    resultsPlaceholder.classList.add("hidden");
    resultsContent.classList.remove("hidden");


  } catch (err) {

    console.error(err);
    alert("API error");

  }

  analyzeBtn.disabled = false;
  buttonText.textContent = t.analyze_button;

});

// ======================================================
// DISPLAY RESULTS (MULTI LOG)
// ======================================================

// ======================================================
// DISPLAY RESULTS (UPDATED WITH DETAIL BUTTON)
// ======================================================

function displayResults(results) {

  // 🔥 lưu global để dùng cho popup
  currentResults = results;

  let html = `
  <div class="space-y-4">
  `;

  results.forEach((data, index) => {

    const confidence =
      data.confidence ? (data.confidence * 100).toFixed(1) + "%" : "-";

    const incident = data.incident || {};

    const severity = incident.severity || "-";
    const attacker = incident.attacker || "-";

    const playbook = (data.playbook || [])
      .map(p => `
        <li>
          <b>Step ${p.step}:</b> ${p.action} 
          (${p.tool})
        </li>
      `)
      .join("");

    html += `
    <div class="border border-blue-900 rounded-lg p-4 relative">

      <!-- HEADER -->
      <div class="flex justify-between mb-2">
        <span class="font-bold text-blue-400">
          #${index + 1} - ${data.attack_type}
        </span>

        <span class="text-sm font-semibold">
          ${confidence}
        </span>
      </div>

      <!-- INFO -->
      <div class="text-sm mb-2">
        <b>Severity:</b> ${severity} |
        <b>Attacker:</b> ${attacker}
      </div>

      <!-- SUMMARY -->
      <div class="text-sm mb-2">
        ${data.summary || ""}
      </div>

      <!-- PLAYBOOK -->
      <div class="text-sm mb-2">
        <b>Playbook:</b>
        <ul class="list-disc ml-5">
          ${playbook}
        </ul>
      </div>

      <!-- IMPACT -->
      <div class="text-xs opacity-70 mb-6">
        ${data.explanation?.impact || ""}
      </div>

      <!-- 🔥 BUTTON DETAIL -->
      <button onclick="showDetail(${index})"
        class="absolute bottom-3 right-3 text-xs bg-blue-600 hover:bg-blue-500 px-3 py-1 rounded transition">
        🔍 Chi tiết
      </button>

    </div>
    `;
  });

  html += `</div>`;

  resultsContent.innerHTML = html;
}

function showDetail(index) {

  const data = currentResults[index];
  if (!data || !data.debug) return;

  const d = data.debug;

  function block(title, obj) {
    return `
      <div class="border border-blue-900 rounded p-3">
        <div class="text-blue-400 font-bold mb-1">${title}</div>
        <pre class="text-xs text-gray-300 whitespace-pre-wrap">
${JSON.stringify(obj, null, 2)}
        </pre>
      </div>
    `;
  }

  const html = `

    ${block("📥 Raw Log", d.raw_log)}

    ${block("🧩 Parser", d.parser)}

    ${block("🔄 Normalizer", d.normalizer)}

    ${block("🌊 Flow", d.flow)}

    ${block("📊 Features", d.features)}

    ${block("🧠 Behavior", d.behavior)}

    ${block("🤖 ML Detection", d.ml)}

    ${block("🧬 MITRE Mapping", d.mitre)}

    ${block("🧾 LLM Analysis", d.llm)}

    ${block("📈 Confidence", d.confidence)}

    ${block("🔗 Correlation (Incident)", d.incident)}

  `;

  document.getElementById("detailContent").innerHTML = html;

  document.getElementById("detailModal").classList.remove("hidden");
}

function closeDetail() {
  document.getElementById("detailModal").classList.add("hidden");
}

// ======================================================
// HISTORY PAGE
// ======================================================

function showHistory() {

  hideAllPages();

  historyPage.classList.remove("hidden");

  loadHistory();

}


// ======================================================
// SAVE ANALYSIS HISTORY
// ======================================================

function saveHistory(results) {

  if (!results) return;

  // đảm bảo results luôn là array
  if (!Array.isArray(results)) {
    results = [results];
  }

  let history = JSON.parse(localStorage.getItem("deflog_history")) || [];

  const item = {
    time: new Date().toLocaleString(),
    results: results
  };

  history.unshift(item);

  // giữ tối đa 20 record
  if (history.length > 20) {
    history = history.slice(0, 20);
  }

  localStorage.setItem("deflog_history", JSON.stringify(history));

}


// ======================================================
// LOAD HISTORY
// ======================================================

function loadHistory() {

  const historyList = document.getElementById("historyList");

  if (!historyList) return;

  let history = JSON.parse(localStorage.getItem("deflog_history")) || [];

  if (!Array.isArray(history) || history.length === 0) {

    historyList.innerHTML = `
      <p class="text-sm opacity-70">
      No analysis history
      </p>
    `;

    return;
  }

  let html = `<div class="space-y-3">`;

  history.forEach((item, index) => {

    if (!item) return;

    let results = item.results;

    // fix dữ liệu cũ
    if (!results) {
      results = [];
    }

    if (!Array.isArray(results)) {
      results = [results];
    }

    const count = results.length;

    html += `
    <div class="border border-blue-900 rounded-lg p-4 hover:bg-blue-900/20 cursor-pointer"
         onclick="openHistory(${index})">

      <div class="flex justify-between text-sm">

        <span class="font-semibold">
          Analysis #${index + 1}
        </span>

        <span class="opacity-70">
          ${item.time || "-"}
        </span>

      </div>

      <div class="text-xs mt-2 opacity-70">
        ${count} logs analyzed
      </div>

    </div>
    `;
  });

  html += `</div>`;

  historyList.innerHTML = html;

}


// ======================================================
// OPEN HISTORY ITEM
// ======================================================

function openHistory(index) {

  const history = JSON.parse(localStorage.getItem("deflog_history")) || [];

  const item = history[index];

  if (!item) return;

  let results = item.results;

  if (!results) return;

  if (!Array.isArray(results)) {
    results = [results];
  }

  showMainPage();

  displayResults(results);

}


// ======================================================
// CLEAR HISTORY (OPTIONAL)
// ======================================================

function clearHistory() {

  localStorage.removeItem("deflog_history");

  loadHistory();

}