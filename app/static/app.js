// ── Config ──────────────────────────────────────────────────────
const API = window.location.origin;

// ── State ────────────────────────────────────────────────────────
let currentMode = "url";   // "url" | "dep"
let scanStartTime = null;
let elapsedInterval = null;
let lastReport = "";

// ── Helpers ──────────────────────────────────────────────────────
function $(sel) { return document.querySelector(sel); }

async function api(path, opts = {}) {
  const resp = await fetch(`${API}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }));
    throw new Error(err.detail || resp.statusText);
  }
  return resp.json();
}

function renderMd(text) {
  return marked.parse(text || "", { breaks: true });
}

function toast(msg, isError = false) {
  const el = document.createElement("div");
  el.className = `fixed bottom-4 right-4 z-50 px-4 py-3 rounded-lg text-sm font-medium fade-in shadow-lg ${
    isError ? "bg-red-700/90 text-white" : "bg-green-700/90 text-white"
  }`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function fmtElapsed(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const ss = String(s % 60).padStart(2, "0");
  return m > 0 ? `${m}m ${ss}s` : `${s}s`;
}


// ── Mode toggle ──────────────────────────────────────────────────
function setMode(mode) {
  currentMode = mode;
  const isUrl = mode === "url";

  $("#input-url").classList.toggle("hidden", !isUrl);
  $("#input-dep").classList.toggle("hidden", isUrl);
  $("#scan-hint").textContent = isUrl
    ? "Full repo scans take 5–15 minutes"
    : "Quick dependency list scan (1–2 minutes)";

  $("#mode-url").classList.toggle("active", isUrl);
  $("#mode-dep").classList.toggle("active", !isUrl);
}


// ── Health ───────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const h = await api("/health");
    const dot = h.status === "ok"
      ? '<span class="inline-block w-2.5 h-2.5 rounded-full bg-green-500 pulse-dot"></span>'
      : '<span class="inline-block w-2.5 h-2.5 rounded-full bg-yellow-500"></span>';
    let label = h.llm_vendor === "google"
      ? `gemini/${h.google?.api_key_set ? "ready" : "no key"}`
      : `ollama/${h.ollama?.reachable ? "ready" : "offline"}`;
    $("#health-badge").innerHTML = `${dot} <span class="text-gray-400 text-xs">${label}</span>`;
  } catch {
    $("#health-badge").innerHTML =
      '<span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500"></span> ' +
      '<span class="text-red-400 text-xs">Disconnected</span>';
  }
}


// ── Scan ─────────────────────────────────────────────────────────
async function runScan() {
  const btn = $("#scan-btn");

  let payload;
  if (currentMode === "url") {
    const url = $("#github-url").value.trim();
    if (!url) { toast("Enter a GitHub URL first", true); return; }
    payload = { github_url: url };
  } else {
    const deps = $("#dep-list").value.trim();
    if (!deps) { toast("Paste a dependency list first", true); return; }
    payload = { input: deps };
  }

  // Show loading
  btn.disabled = true;
  $("#result-card").classList.add("hidden");
  $("#scan-loading").classList.remove("hidden");
  scanStartTime = Date.now();
  elapsedInterval = setInterval(() => {
    $("#elapsed-timer").textContent = `Elapsed: ${fmtElapsed(Date.now() - scanStartTime)}`;
  }, 1000);

  try {
    const data = await api("/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showResult(data.result);
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    clearInterval(elapsedInterval);
    elapsedInterval = null;
    $("#scan-loading").classList.add("hidden");
  }
}


// ── Result rendering ─────────────────────────────────────────────
function showResult(reportText) {
  lastReport = reportText;

  // Parse summary numbers from the report
  const summaryBar = buildSummaryBar(reportText);
  $("#summary-bar").innerHTML = summaryBar;

  $("#report-body").innerHTML = renderMd(reportText);
  $("#result-card").classList.remove("hidden");
  $("#result-card").scrollIntoView({ behavior: "smooth", block: "start" });
}

function buildSummaryBar(text) {
  // Extract stat numbers from the Markdown
  const totalMatch = text.match(/Total Dependencies Checked[:\s]+(\d+)/i);
  const vulnMatch  = text.match(/Vulnerable Count[:\s]+(\d+)/i);
  const safeMatch  = text.match(/Safe Count[:\s]+(\d+)/i);

  const total = totalMatch ? parseInt(totalMatch[1]) : null;
  const vuln  = vulnMatch  ? parseInt(vulnMatch[1])  : null;
  const safe  = safeMatch  ? parseInt(safeMatch[1])  : null;

  // Count CRITICAL/HIGH mentions in table rows
  const critCount  = (text.match(/\| CRITICAL \|/gi) || []).length;
  const highCount  = (text.match(/\| HIGH \|/gi) || []).length;
  const medCount   = (text.match(/\| MEDIUM \|/gi) || []).length;
  const lowCount   = (text.match(/\| LOW \|/gi) || []).length;

  let html = "";

  if (total !== null) {
    html += stat("Deps Scanned", total, "badge-blue");
  }
  if (vuln !== null) {
    html += stat("Vulnerable", vuln, vuln > 0 ? "badge-red" : "badge-green");
  }
  if (safe !== null) {
    html += stat("Safe", safe, "badge-green");
  }
  if (critCount > 0) html += stat("Critical", critCount, "badge-red");
  if (highCount > 0)  html += stat("High",     highCount,  "badge-orange");
  if (medCount > 0)   html += stat("Medium",   medCount,   "badge-yellow");
  if (lowCount > 0)   html += stat("Low",      lowCount,   "badge-blue");

  return html;
}

function stat(label, value, badgeClass) {
  return `<div class="flex items-center gap-2">
    <span class="text-gray-500 text-xs">${label}</span>
    <span class="badge ${badgeClass}">${value}</span>
  </div>`;
}


// ── Copy ─────────────────────────────────────────────────────────
function copyReport() {
  if (!lastReport) return;
  navigator.clipboard.writeText(lastReport)
    .then(() => toast("Report copied to clipboard"))
    .catch(() => toast("Copy failed", true));
}


// ── Keyboard shortcuts ───────────────────────────────────────────
$("#github-url").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runScan();
});

$("#dep-list").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runScan();
});


// ── Init ─────────────────────────────────────────────────────────
checkHealth();
setInterval(checkHealth, 30000);
