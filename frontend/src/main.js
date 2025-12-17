// ============ Ngôn ngữ ============

let currentLang = "vi"; // mặc định

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
    log_placeholder:
      "Dán logs của bạn vào đây...\nVí dụ:\n[2025-01-15 14:23:45] WARNING: Kết nối đáng ngờ từ 192.168.1.100\n[2025-01-15 14:23:46] ALERT: Phát hiện nhiều lần đăng nhập thất bại",
    supported_formats:
      "💡 Định dạng hỗ trợ: .json, .log, .txt, Suricata IDS, Zeek",
    file_drop_title: "Thả file log của bạn vào đây",
    file_drop_subtitle: "Hỗ trợ: .json, .log, .txt (Tối đa 10MB)",
    choose_file: "Chọn File",
    file_selected: "📁 Đã chọn:",
    screenshot_title: "Dán ảnh chụp màn hình từ clipboard",
    screenshot_subtitle: "Nhấn Ctrl+V (hoặc Cmd+V) để dán",
    detection_engine: "🔍 Công cụ Phát hiện",
    autodetect: "Tự động phát hiện",
    analyze_button: "🚀 Phân Tích Ngay với LLM",
    analyzing: "🔄 Đang phân tích với AI...",
    results_title: "📊 Kết Quả Phân Tích",
    no_analysis: "Chưa có phân tích. Tải lên hoặc dán logs để bắt đầu.",
    severity_high: "🔴 MỨC ĐỘ CAO",
    high_risk: "Nguy hiểm cao",
    medium_risk: "Trung bình",
    low_risk: "Thấp",
    attack_vector: "🎯 Vector Tấn Công",
    summary: "📋 Tóm Tắt",
    summary_text:
      "Phát hiện tấn công brute-force tiềm ẩn với 15 lần đăng nhập thất bại từ địa chỉ IP đáng ngờ. Mẫu khớp với chữ ký tấn công đã biết.",
    category: "🏷️ Danh Mục",
    suggested_fix: "💡 Đề Xuất Khắc Phục (LLM)",
    suggested_fix_text:
      "1. Chặn địa chỉ IP 192.168.1.100 ngay lập tức<br>2. Triển khai giới hạn tốc độ trên điểm đăng nhập<br>3. Bật xác thực đa yếu tố<br>4. Kiểm tra nhật ký truy cập để phát hiện tài khoản bị xâm nhập",
    export_pdf: "📄 Xuất Báo Cáo PDF",
  },
  en: {
    nav_dataset: "Dataset",
    nav_history: "History",
    nav_about: "About",
    tab_text: "📝 Text Log",
    tab_upload: "📁 Upload File",
    tab_screenshot: "📸 Paste Screenshot",
    upload_hint: "Drag & Drop logs here",
    upload_subtitle: "or paste your log data below",
    log_placeholder:
      "Paste your logs here...\nExample:\n[2025-01-15 14:23:45] WARNING: Suspicious connection from 192.168.1.100\n[2025-01-15 14:23:46] ALERT: Multiple failed login attempts detected",
    supported_formats:
      "💡 Supported formats: .json, .log, .txt, Suricata IDS, Zeek",
    file_drop_title: "Drop your log file here",
    file_drop_subtitle: "Supports: .json, .log, .txt (Max 10MB)",
    choose_file: "Choose File",
    file_selected: "📁 Selected:",
    screenshot_title: "Paste screenshot from clipboard",
    screenshot_subtitle: "Press Ctrl+V (or Cmd+V) to paste",
    detection_engine: "🔍 Detection Engine",
    autodetect: "Auto-detect",
    analyze_button: "🚀 Analyze Now with LLM",
    analyzing: "🔄 Analyzing with AI...",
    results_title: "📊 Analysis Results",
    no_analysis: "No analysis yet. Upload or paste logs to begin.",
    severity_high: "🔴 HIGH SEVERITY",
    high_risk: "High Risk",
    medium_risk: "Medium",
    low_risk: "Low Risk",
    attack_vector: "🎯 Attack Vector",
    summary: "📋 Summary",
    summary_text:
      "Detected potential brute-force attack with 15 failed login attempts from suspicious IP address. Pattern matches known attack signatures.",
    category: "🏷️ Category",
    suggested_fix: "💡 Suggested Fix (LLM Generated)",
    suggested_fix_text:
      "1. Block IP address 192.168.1.100 immediately<br>2. Implement rate limiting on login endpoints<br>3. Enable multi-factor authentication<br>4. Review access logs for compromised accounts",
    export_pdf: "📄 Export PDF Report",
  },
};

function switchLanguage(lang) {
  currentLang = lang;
  const t = translations[lang];

  // nút switch
  document.getElementById("langIcon").textContent =
    lang === "vi" ? "🇻🇳" : "🇺🇸";
  document.getElementById("langText").textContent =
    lang === "vi" ? "VI" : "EN";

  // nav
  document.getElementById("nav-dataset").textContent = t.nav_dataset;
  document.getElementById("nav-history").textContent = t.nav_history;
  document.getElementById("nav-about").textContent = t.nav_about;

  // tabs
  document.getElementById("tab-text-label").textContent = t.tab_text;
  document.getElementById("tab-upload-label").textContent = t.tab_upload;
  document.getElementById("tab-screenshot-label").textContent =
    t.tab_screenshot;

  // input zone
  document.getElementById("upload-hint").textContent = t.upload_hint;
  document.getElementById("upload-subtitle").textContent = t.upload_subtitle;
  document.getElementById("logInput").placeholder = t.log_placeholder;
  document.getElementById("supported-formats").textContent =
    t.supported_formats;

  // file upload
  document.getElementById("file-drop-title").textContent = t.file_drop_title;
  document.getElementById("file-drop-subtitle").textContent =
    t.file_drop_subtitle;
  document.getElementById("choose-file-btn").textContent = t.choose_file;

  // screenshot
  document.getElementById("screenshot-title").textContent =
    t.screenshot_title;
  document.getElementById("screenshot-subtitle").textContent =
    t.screenshot_subtitle;

  // detection
  document.getElementById("detection-engine-label").textContent =
    t.detection_engine;
  document.getElementById("autodetect-label").textContent = t.autodetect;

  // analyze button
  document.getElementById("analyze-button-text").textContent =
    t.analyze_button;

  // results
  document.getElementById("results-title").textContent = t.results_title;
  document.getElementById("no-analysis-text").textContent = t.no_analysis;
  document.getElementById("severityBadge").textContent = t.severity_high;
  document.getElementById("high-risk-label").textContent = t.high_risk;
  document.getElementById("medium-risk-label").textContent = t.medium_risk;
  document.getElementById("low-risk-label").textContent = t.low_risk;
  document.getElementById("attack-vector-label").textContent =
    t.attack_vector;
  document.getElementById("summary-label").textContent = t.summary;
  document.getElementById("summary-text").textContent = t.summary_text;
  document.getElementById("category-label").textContent = t.category;
  document.getElementById("suggested-fix-label").textContent =
    t.suggested_fix;
  document.getElementById("suggested-fix-text").innerHTML =
    t.suggested_fix_text;
  document.getElementById("export-pdf-btn").textContent = t.export_pdf;
}

// config (sau này nếu anh muốn cho chỉnh trên UI thì dùng tiếp)
const defaultConfig = {
  app_title: "DEFLOG",
  tagline: "Intelligent Log Analyzer with LLM",
  upload_hint: "Kéo & Thả logs vào đây",
  analyze_button: "🚀 Phân Tích Ngay với LLM",
  footer_text: "© DEFLOG Research Group – 2025",
  footer_tech: "Built with FastAPI + Qwen2.5 + TailwindCSS",
};

// ============ Tab switching ============

const tabs = ["text", "upload", "screenshot"];

tabs.forEach((tab) => {
  document
    .getElementById(`tab-${tab}`)
    .addEventListener("click", () => setActiveTab(tab));
});

function setActiveTab(active) {
  tabs.forEach((t) => {
    const tabBtn = document.getElementById(`tab-${t}`);
    const content = document.getElementById(`content-${t}`);
    if (t === active) {
      tabBtn.className =
        "tab-active px-4 py-2 rounded-lg font-medium text-sm transition-all";
      content.classList.remove("hidden");
    } else {
      tabBtn.className =
        "tab-inactive px-4 py-2 rounded-lg font-medium text-sm transition-all";
      content.classList.add("hidden");
    }
  });
}

// ============ Drag & Drop + File input ============

const dropZone = document.getElementById("dropZone");
const fileDropZone = document.getElementById("fileDropZone");
const logInput = document.getElementById("logInput");

[dropZone, fileDropZone].forEach((zone) => {
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("dragover");
  });

  zone.addEventListener("dragleave", () => {
    zone.classList.remove("dragover");
  });

  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("dragover");
    const files = e.dataTransfer.files;
    if (files.length > 0) handleFile(files[0]);
  });
});

document.getElementById("fileInput").addEventListener("change", (e) => {
  if (e.target.files.length > 0) handleFile(e.target.files[0]);
});

function handleFile(file) {
  const fileName = document.getElementById("fileName");
  const t = translations[currentLang];

  fileName.textContent = `${t.file_selected} ${file.name} (${(
    file.size / 1024
  ).toFixed(2)} KB)`;
  fileName.style.color = "#3B82F6";

  const reader = new FileReader();
  reader.onload = (e) => {
    logInput.value = e.target.result;
  };
  reader.readAsText(file);
}

// ============ Screenshot paste ============

document.addEventListener("paste", (e) => {
  const activeTab = document.querySelector(".tab-active").id;
  if (activeTab === "tab-screenshot") {
    const items = e.clipboardData.items;
    for (let item of items) {
      if (item.type.indexOf("image") !== -1) {
        const blob = item.getAsFile();
        const url = URL.createObjectURL(blob);
        const preview = document.getElementById("screenshotPreview");
        const img = document.getElementById("screenshotImage");
        img.src = url;
        preview.classList.remove("hidden");
      }
    }
  }
});

// ============ Language switch button ============

document
  .getElementById("langSwitcher")
  .addEventListener("click", () => {
    const newLang = currentLang === "vi" ? "en" : "vi";
    switchLanguage(newLang);
  });

// ============ Analyze button (tạm demo, chưa gọi API) ============

const analyzeBtn = document.getElementById("analyzeBtn");
const resultsPlaceholder = document.getElementById("resultsPlaceholder");
const resultsContent = document.getElementById("resultsContent");

analyzeBtn.addEventListener("click", () => {
  const buttonText = analyzeBtn.querySelector("span");
  const t = translations[currentLang];

  analyzeBtn.disabled = true;
  analyzeBtn.classList.add("analyzing");
  buttonText.textContent = t.analyzing;

  // TODO: sau này thay đoạn setTimeout này = fetch('/api/analyze', { ... })
  setTimeout(() => {
    resultsPlaceholder.classList.add("hidden");
    resultsContent.classList.remove("hidden");
    analyzeBtn.disabled = false;
    analyzeBtn.classList.remove("analyzing");
    buttonText.textContent = t.analyze_button;

    if (window.innerWidth < 1024) {
      resultsContent.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, 1000);
});

// ============ Khởi tạo ban đầu ============

switchLanguage("vi");
