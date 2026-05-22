const sampleCode = `def calculate_total(items):
    total = 0
    for item in items:
        total = total + item["price"]
    return total

print(calculate_total(cart))
`;

const routes = new Set(["/dashboard", "/code-analysis", "/security", "/optimization", "/reports"]);
const qs = (selector) => document.querySelector(selector);
const qsa = (selector) => [...document.querySelectorAll(selector)];

const els = {
  loginScreen: qs("#loginScreen"),
  appShell: qs("#appShell"),
  loginForm: qs("#loginForm"),
  loginUsername: qs("#loginUsername"),
  loginPassword: qs("#loginPassword"),
  loginError: qs("#loginError"),
  logoutBtn: qs("#logoutBtn"),
  userName: qs("#userName"),
  codeInput: qs("#codeInput"),
  samplePreview: qs("#samplePreview"),
  fileInput: qs("#fileInput"),
  runAnalyze: qs("#runAnalyze"),
  runTop: qs("#runTop"),
  sampleBtn: qs("#sampleBtn"),
  useModel: qs("#useModel"),
  liveFile: qs("#liveFile"),
  scoreOrbit: qs("#scoreOrbit"),
  scoreValue: qs("#scoreValue"),
  statusChip: qs("#statusChip"),
  summaryText: qs("#summaryText"),
  lineMetric: qs("#lineMetric"),
  issueMetric: qs("#issueMetric"),
  complexityMetric: qs("#complexityMetric"),
  findingsList: qs("#findingsList"),
  optimizedOutput: qs("#optimizedOutput"),
  optimizationStatus: qs("#optimizationStatus"),
  optimizationSuggestions: qs("#optimizationSuggestions"),
  modelOutput: qs("#modelOutput"),
  modelStatus: qs("#modelStatus"),
  copyOptimized: qs("#copyOptimized"),
  securityScore: qs("#securityScore"),
  securityStatus: qs("#securityStatus"),
  criticalMetric: qs("#criticalMetric"),
  highMetric: qs("#highMetric"),
  securityIssueMetric: qs("#securityIssueMetric"),
  securityFindingsList: qs("#securityFindingsList"),
  reportScore: qs("#reportScore"),
  reportLines: qs("#reportLines"),
  reportIssues: qs("#reportIssues"),
  reportStatus: qs("#reportStatus"),
  reportFindingsList: qs("#reportFindingsList"),
  historyStatus: qs("#historyStatus"),
  historyList: qs("#historyList"),
  exportJson: qs("#exportJson"),
  exportMarkdown: qs("#exportMarkdown"),
  checkOllama: qs("#checkOllama"),
  ollamaStatusText: qs("#ollamaStatusText"),
  clearHistory: qs("#clearHistory"),
};

let currentFilename = "sample.py";
let currentUser = null;
let historyCache = [];
let isAuthenticated = false;
let lastResult = null;
let saveTimer = null;
let severityFilter = "all";

function normalizeRoute(pathname) {
  if (pathname === "/" || pathname === "/index.html" || pathname === "/login") return "/dashboard";
  return routes.has(pathname) ? pathname : "/dashboard";
}

function showLogin(message = "") {
  isAuthenticated = false;
  currentUser = null;
  els.appShell.hidden = true;
  els.loginScreen.hidden = false;
  document.body.classList.remove("authenticated");
  document.body.classList.add("auth-loading");
  els.loginError.textContent = message;
  window.history.replaceState({}, "", "/login");
  setTimeout(() => els.loginUsername.focus(), 0);
}

function showApp(snapshot) {
  isAuthenticated = true;
  currentUser = snapshot.username;
  els.userName.textContent = snapshot.username;
  els.loginScreen.hidden = true;
  els.appShell.hidden = false;
  document.body.classList.remove("auth-loading");
  document.body.classList.add("authenticated");
  applySnapshot(snapshot);
  const targetRoute = routes.has(window.location.pathname) ? window.location.pathname : snapshot.state?.last_route;
  navigateTo(targetRoute || "/dashboard", true);
}

function applySnapshot(snapshot) {
  const state = snapshot.state || {};
  historyCache = snapshot.history || [];
  renderHistory(historyCache);

  if (state.code !== undefined) {
    currentFilename = state.filename || "sample.py";
    els.codeInput.value = state.code || "";
    els.useModel.checked = state.use_model !== false;
    updatePreview();
  } else {
    setSample(false);
  }

  if (state.last_result) {
    renderResult(state.last_result);
  } else {
    renderResult({
      filename: currentFilename,
      score: 54,
      status: "ok",
      summary: "Kod namunasi tahlilga tayyor. Tahlil qilish tugmasini bosing.",
      metrics: { code_lines: els.codeInput.value.split("\n").filter((line) => line.trim()).length, complexity: 1 },
      findings: [],
      suggestions: ["Kod tahlil qilingandan keyin tavsiyalar shu yerda saqlanadi."],
      optimized_code: "",
      model_status: "Kutilmoqda",
    });
    lastResult = null;
  }
}

function renderPage(pathname = window.location.pathname) {
  const route = normalizeRoute(pathname);
  qsa("[data-page]").forEach((page) => {
    page.classList.toggle("active", page.dataset.page === route);
  });
  qsa(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.route === route);
  });
  document.body.dataset.route = route.slice(1);
  window.scrollTo({ top: 0, behavior: "auto" });
}

function navigateTo(pathname, replace = false) {
  if (!isAuthenticated) {
    showLogin();
    return;
  }
  const route = normalizeRoute(pathname);
  if (window.location.pathname !== route) {
    const method = replace ? "replaceState" : "pushState";
    window.history[method]({}, "", route);
  }
  renderPage(route);
  queueSaveWork();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const data = await response.json();
  if (response.status === 401) {
    showLogin(data.error || "Sessiya tugagan. Qayta login qiling.");
    throw new Error(data.error || "Avval login qiling.");
  }
  if (!response.ok) {
    throw new Error(data.error || "So'rov bajarilmadi.");
  }
  return data;
}

async function initAuth() {
  try {
    const response = await fetch("/api/me", { credentials: "same-origin" });
    const data = await response.json();
    if (data.authenticated) {
      showApp(data);
    } else {
      showLogin();
    }
  } catch {
    showLogin("Server bilan aloqa bo'lmadi.");
  }
}

async function login(username, password) {
  els.loginError.textContent = "";
  const data = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  showApp(data);
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
  } finally {
    lastResult = null;
    historyCache = [];
    showLogin();
  }
}

function setSample(shouldSave = true) {
  currentFilename = "sample.py";
  els.codeInput.value = sampleCode;
  updatePreview();
  if (shouldSave) queueSaveWork();
}

function updatePreview() {
  const code = els.codeInput.value;
  els.samplePreview.textContent = (code || sampleCode).slice(0, 520).trim() || "Kod bo'sh";
  els.liveFile.textContent = `Python ${currentFilename}`;
}

function setLoading(isLoading) {
  qsa("[data-run-analysis], #runAnalyze, #runTop").forEach((button) => {
    button.disabled = isLoading;
  });
  [els.statusChip, els.reportStatus, els.optimizationStatus].forEach((chip) => {
    if (chip) chip.textContent = isLoading ? "Tahlil ketmoqda" : "Tahlil tugadi";
  });
  document.body.classList.toggle("is-loading", isLoading);
}

async function analyze() {
  if (!isAuthenticated) {
    showLogin();
    return;
  }
  const code = els.codeInput.value;
  setLoading(true);
  try {
    const data = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({
        code,
        filename: currentFilename,
        use_model: els.useModel.checked,
      }),
    });
    renderResult(data);
    await loadHistory();
  } catch (error) {
    renderError(error);
  } finally {
    setLoading(false);
  }
}

function queueSaveWork() {
  if (!isAuthenticated) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveWork, 450);
}

async function saveWork() {
  if (!isAuthenticated) return;
  try {
    await api("/api/save-work", {
      method: "POST",
      body: JSON.stringify({
        code: els.codeInput.value,
        filename: currentFilename,
        use_model: els.useModel.checked,
        last_route: normalizeRoute(window.location.pathname),
        last_result: lastResult,
      }),
    });
  } catch {
    // Login expiry is handled by api(); silent save failures should not interrupt typing.
  }
}

async function loadHistory() {
  const data = await api("/api/history");
  historyCache = data.history || [];
  renderHistory(historyCache);
}

async function checkOllamaStatus() {
  els.ollamaStatusText.textContent = "Ollama tekshirilmoqda...";
  try {
    const data = await api("/api/ollama/status");
    const modelText = data.models?.length ? `Modellar: ${data.models.join(", ")}` : "Model topilmadi.";
    els.ollamaStatusText.textContent = `${data.message} Tanlangan model: ${data.selected_model}. ${modelText}`;
    els.modelStatus.textContent = data.model_ready ? "Model tayyor" : data.ok ? "Model yuklanmagan" : "Ollama yo'q";
  } catch (error) {
    els.ollamaStatusText.textContent = error.message;
  }
}

async function deleteHistoryItem(id) {
  if (!window.confirm("Bu tarix yozuvini o'chirasizmi?")) return;
  const data = await api("/api/history/delete", {
    method: "POST",
    body: JSON.stringify({ id }),
  });
  historyCache = data.history || [];
  renderHistory(historyCache);
}

async function clearHistory() {
  if (!window.confirm("Barcha saqlangan ishlarni tozalaysizmi?")) return;
  const data = await api("/api/history/clear", { method: "POST", body: "{}" });
  historyCache = data.history || [];
  renderHistory(historyCache);
}

function renderResult(data) {
  lastResult = data;
  const findings = data.findings || [];
  const score = Number(data.score || 0);
  const securityFindings = findings.filter((finding) => finding.category === "Xavfsizlik");
  const optimizationFindings = findings.filter((finding) =>
    ["Optimallashtirish", "Murakkablik", "Takrorlanish", "Dizayn"].includes(finding.category),
  );
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const highCount = findings.filter((finding) => finding.severity === "high").length;

  els.scoreOrbit.style.setProperty("--score", String(score));
  els.scoreValue.textContent = score;
  els.summaryText.textContent = data.summary || "Xulosa mavjud emas.";
  els.statusChip.textContent = statusLabel(data.status);
  els.lineMetric.textContent = data.metrics?.code_lines ?? 0;
  els.issueMetric.textContent = findings.length;
  els.complexityMetric.textContent = data.metrics?.complexity ?? 0;
  renderFindings(els.findingsList, findings, "Muammo topilmadi", "Kod sifati yaxshi. Testlar va type hintlar bilan yanada mustahkamlash mumkin.");

  els.securityScore.textContent = Math.max(0, score - criticalCount * 8 - highCount * 3);
  els.securityStatus.textContent = securityFindings.length
    ? "Xavfsizlik bo'yicha tuzatish talab qilinadi."
    : "Xavfsizlik bo'yicha alohida muammo topilmadi.";
  els.criticalMetric.textContent = criticalCount;
  els.highMetric.textContent = highCount;
  els.securityIssueMetric.textContent = `${securityFindings.length} muammo`;
  renderFindings(
    els.securityFindingsList,
    securityFindings,
    "Xavfsizlik muammosi topilmadi",
    "Hardcoded secret, SQL injection yoki xavfli chaqiruvlar aniqlanmadi.",
  );

  els.optimizationStatus.textContent = optimizationFindings.length ? "Tavsiyalar bor" : "Toza";
  els.optimizedOutput.textContent =
    data.optimized_code || "Avtomatik o'zgartirish topilmadi. Tavsiyalar ro'yxati bo'yicha qo'lda yaxshilash mumkin.";
  renderSuggestions(data.suggestions || []);

  els.reportScore.textContent = score;
  els.reportLines.textContent = data.metrics?.code_lines ?? 0;
  els.reportIssues.textContent = findings.length;
  els.reportStatus.textContent = statusLabel(data.status);
  els.modelStatus.textContent = data.model_status || "Kutilmoqda";
  els.modelOutput.textContent = data.model_summary || fallbackModelText(data);
  renderFindings(els.reportFindingsList, findings, "Muammo topilmadi", "Hisobot uchun topilma yo'q.");
}

function renderSuggestions(suggestions) {
  els.optimizationSuggestions.innerHTML = "";
  if (!suggestions.length) {
    const empty = document.createElement("article");
    empty.className = "suggestion-item";
    empty.innerHTML = "<strong>Tavsiya yo'q</strong>Kod umumiy ko'rinishda yaxshi.";
    els.optimizationSuggestions.appendChild(empty);
    return;
  }
  suggestions.forEach((suggestion, index) => {
    const item = document.createElement("article");
    item.className = "suggestion-item";
    item.innerHTML = `<strong>${index + 1}. Tavsiya</strong>${escapeHtml(suggestion)}`;
    els.optimizationSuggestions.appendChild(item);
  });
}

function renderHistory(history) {
  els.historyStatus.textContent = `${history.length} yozuv`;
  els.historyList.innerHTML = "";
  if (!history.length) {
    const item = document.createElement("article");
    item.className = "history-item";
    item.innerHTML = `<div><strong>Hali ish saqlanmagan</strong><span>Tahlil qilganingizdan keyin yozuvlar shu yerda ko'rinadi.</span></div>`;
    els.historyList.appendChild(item);
    return;
  }
  history.forEach((entry) => {
    const item = document.createElement("article");
    item.className = "history-item";
    item.innerHTML = `
      <div>
        <strong>${escapeHtml(entry.filename || "main.py")} · ${Number(entry.score || 0)}/100</strong>
        <span>${escapeHtml(formatDate(entry.created_at))} · ${Number(entry.issue_count || 0)} muammo</span>
        <span>${escapeHtml(entry.summary || "")}</span>
      </div>
      <div class="history-actions">
        <button class="ghost-button compact" type="button" data-history-id="${escapeHtml(entry.id)}">Ochish</button>
        <button class="ghost-button compact" type="button" data-delete-history-id="${escapeHtml(entry.id)}">O'chirish</button>
      </div>
    `;
    els.historyList.appendChild(item);
  });
}

function openHistoryItem(id) {
  const entry = historyCache.find((item) => item.id === id);
  if (!entry) return;
  currentFilename = entry.filename || "main.py";
  els.codeInput.value = entry.code || "";
  updatePreview();
  if (entry.result) renderResult(entry.result);
  navigateTo("/code-analysis");
  queueSaveWork();
}

function exportReport(format) {
  if (!lastResult) {
    window.alert("Avval kodni tahlil qiling.");
    return;
  }
  const baseName = (currentFilename || "report").replace(/[^a-z0-9_.-]+/gi, "_");
  if (format === "json") {
    downloadText(`${baseName}.neyron-report.json`, JSON.stringify(lastResult, null, 2), "application/json");
    return;
  }
  const findings = lastResult.findings || [];
  const lines = [
    `# NeyronCode Hisobot`,
    ``,
    `Fayl: ${lastResult.filename || currentFilename}`,
    `Ball: ${lastResult.score}/100`,
    `Holat: ${statusLabel(lastResult.status)}`,
    ``,
    `## Xulosa`,
    lastResult.summary || "Xulosa yo'q.",
    ``,
    `## Topilmalar`,
    findings.length ? "" : "Muammo topilmadi.",
  ];
  findings.forEach((finding, index) => {
    lines.push(
      `${index + 1}. ${finding.title}`,
      `   - Daraja: ${finding.severity}`,
      `   - Kategoriya: ${finding.category}`,
      `   - Qator: ${finding.line || "umumiy"}`,
      `   - Izoh: ${finding.detail}`,
      `   - Yechim: ${finding.fix}`,
      ``,
    );
  });
  lines.push(`## AI Tavsiya`, lastResult.model_summary || fallbackModelText(lastResult));
  downloadText(`${baseName}.neyron-report.md`, lines.join("\n"), "text/markdown");
}

function downloadText(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function fallbackModelText(data) {
  const suggestions = data.suggestions || [];
  if (!suggestions.length) {
    return "Qoidaviy analiz asosida katta muammo topilmadi.";
  }
  return suggestions.map((item, index) => `${index + 1}. ${item}`).join("\n");
}

function renderFindings(container, findings, emptyTitle, emptyText) {
  container.innerHTML = "";
  const visibleFindings =
    severityFilter === "all" ? findings || [] : (findings || []).filter((finding) => finding.severity === severityFilter);
  if (!visibleFindings || visibleFindings.length === 0) {
    container.appendChild(emptyFinding(emptyTitle, emptyText));
    return;
  }
  visibleFindings.forEach((finding) => {
    container.appendChild(findingNode(finding));
  });
}

function findingNode(finding) {
  const item = document.createElement("article");
  item.className = "finding-item";
  const line = finding.line ? `Qator ${finding.line}` : "Umumiy";
  item.innerHTML = `
    <div class="finding-head">
      <strong>${escapeHtml(finding.title)}</strong>
      <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
    </div>
    <p>${escapeHtml(finding.category)} · ${escapeHtml(line)}</p>
    <p>${escapeHtml(finding.detail)}</p>
    <p><strong>Yechim:</strong> ${escapeHtml(finding.fix)}</p>
  `;
  return item;
}

function emptyFinding(title, text) {
  const item = document.createElement("article");
  item.className = "finding-item";
  item.innerHTML = `
    <div class="finding-head">
      <strong>${escapeHtml(title)}</strong>
      <span class="severity low">good</span>
    </div>
    <p>${escapeHtml(text)}</p>
  `;
  return item;
}

function renderError(error) {
  const fallback = {
    status: "error",
    score: 0,
    summary: error.message,
    findings: [],
    suggestions: [],
    metrics: { code_lines: 0, complexity: 0 },
    model_status: "Xato",
  };
  renderResult(fallback);
}

function statusLabel(status) {
  const labels = {
    ok: "Tahlil tugadi",
    empty: "Kod yo'q",
    syntax_error: "Sintaksis xato",
    error: "Server xatosi",
  };
  return labels[status] || "Tahlil tugadi";
}

function formatDate(value) {
  if (!value) return "Sana yo'q";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("uz-UZ", { dateStyle: "short", timeStyle: "short" });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

els.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await login(els.loginUsername.value.trim(), els.loginPassword.value);
    els.loginPassword.value = "";
  } catch (error) {
    els.loginError.textContent = error.message;
  }
});

els.logoutBtn.addEventListener("click", logout);
els.exportJson.addEventListener("click", () => exportReport("json"));
els.exportMarkdown.addEventListener("click", () => exportReport("markdown"));
els.checkOllama.addEventListener("click", checkOllamaStatus);
els.clearHistory.addEventListener("click", clearHistory);

document.addEventListener("click", (event) => {
  const filterButton = event.target.closest("[data-severity-filter]");
  if (filterButton) {
    severityFilter = filterButton.dataset.severityFilter;
    qsa("[data-severity-filter]").forEach((button) => {
      button.classList.toggle("active", button.dataset.severityFilter === severityFilter);
    });
    if (lastResult) renderResult(lastResult);
    return;
  }

  const historyButton = event.target.closest("[data-history-id]");
  if (historyButton) {
    openHistoryItem(historyButton.dataset.historyId);
    return;
  }

  const deleteHistoryButton = event.target.closest("[data-delete-history-id]");
  if (deleteHistoryButton) {
    deleteHistoryItem(deleteHistoryButton.dataset.deleteHistoryId);
    return;
  }

  const link = event.target.closest("a[data-link]");
  if (!link) return;
  const url = new URL(link.href, window.location.origin);
  if (url.origin !== window.location.origin) return;
  event.preventDefault();
  navigateTo(url.pathname);
});

qsa("[data-run-analysis]").forEach((button) => {
  button.addEventListener("click", analyze);
});

els.runAnalyze.addEventListener("click", analyze);
els.runTop.addEventListener("click", () => {
  navigateTo("/code-analysis");
  analyze();
});
els.sampleBtn.addEventListener("click", () => {
  setSample();
  analyze();
});
els.codeInput.addEventListener("input", () => {
  lastResult = null;
  updatePreview();
  queueSaveWork();
});
els.useModel.addEventListener("change", queueSaveWork);

els.fileInput.addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  currentFilename = file.name;
  els.codeInput.value = await file.text();
  updatePreview();
  navigateTo("/code-analysis");
  analyze();
});

els.copyOptimized.addEventListener("click", async () => {
  const text = els.optimizedOutput.textContent || "";
  try {
    await navigator.clipboard.writeText(text);
    els.copyOptimized.textContent = "Nusxalandi";
    setTimeout(() => {
      els.copyOptimized.textContent = "Nusxa olish";
    }, 1200);
  } catch {
    els.copyOptimized.textContent = "Clipboard yo'q";
  }
});

window.addEventListener("popstate", () => {
  if (isAuthenticated) {
    renderPage(window.location.pathname);
    queueSaveWork();
  } else {
    showLogin();
  }
});

initAuth();
