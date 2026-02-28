// ── Config ──────────────────────────────────────────────────────
const API = window.location.origin;

// ── State ────────────────────────────────────────────────────────
let currentMode = "url";
let scanStartTime = null;
let elapsedInterval = null;
let stepInterval = null;
let lastReport = "";
let currentDepFilter = "all";
let currentTab = "report";

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
    ? "Full repo scans take 3–8 minutes"
    : "Quick dependency list scan (1–3 minutes)";
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


// ── Loading step animation ────────────────────────────────────────
const STEPS = ["s1", "s2", "s3", "s4", "s5"];
let stepIdx = 0;
const STEP_INTERVAL_MS = 30000; // advance every ~30s

function startStepAnimation() {
  stepIdx = 0;
  setStep(0);
  stepInterval = setInterval(() => {
    stepIdx = Math.min(stepIdx + 1, STEPS.length - 1);
    setStep(stepIdx);
  }, STEP_INTERVAL_MS);
}

function setStep(idx) {
  STEPS.forEach((id, i) => {
    const el = document.getElementById(id);
    if (!el) return;
    const label = el.nextElementSibling;
    if (i < idx) {
      el.className = "step-dot step-done";
      if (label) { label.className = "step-label done"; }
    } else if (i === idx) {
      el.className = "step-dot step-active";
      if (label) { label.className = "step-label active"; }
    } else {
      el.className = "step-dot step-wait";
      if (label) { label.className = "step-label waiting"; }
    }
  });
}

function stopStepAnimation() {
  clearInterval(stepInterval);
  stepInterval = null;
  STEPS.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = "step-dot step-done";
    const label = el.nextElementSibling;
    if (label) { label.className = "step-label done"; }
  });
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

  btn.disabled = true;
  $("#result-card").classList.add("hidden");
  $("#scan-loading").classList.remove("hidden");
  scanStartTime = Date.now();
  elapsedInterval = setInterval(() => {
    $("#elapsed-timer").textContent = `Elapsed: ${fmtElapsed(Date.now() - scanStartTime)}`;
  }, 1000);
  startStepAnimation();

  try {
    const data = await api("/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    stopStepAnimation();
    showResult(data.result);
  } catch (e) {
    stopStepAnimation();
    showError(e.message);
  } finally {
    btn.disabled = false;
    clearInterval(elapsedInterval);
    elapsedInterval = null;
    $("#scan-loading").classList.add("hidden");
  }
}


// ── Error display ────────────────────────────────────────────────
function showError(msg) {
  $("#summary-bar").innerHTML = '<span class="badge badge-red">Scan Failed</span>';
  $("#section-nav").innerHTML = "";
  $("#report-body").innerHTML = `
    <div class="bg-red-900/20 border border-red-500/30 rounded-lg p-5">
      <p class="text-red-400 font-semibold mb-2">Scan Error</p>
      <p class="text-gray-300 text-sm font-mono whitespace-pre-wrap break-all leading-relaxed">${escHtml(msg)}</p>
    </div>`;
  $("#result-card").classList.remove("hidden");
  $("#result-card").scrollIntoView({ behavior: "smooth", block: "start" });
}

function escHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}


// ── Result rendering ─────────────────────────────────────────────
function showResult(reportText) {
  lastReport = reportText;

  $("#summary-bar").innerHTML = buildSummaryBar(reportText);

  const container = $("#report-body");
  container.innerHTML = renderMd(reportText);
  postProcessReport(container);
  buildSectionNav(container);

  // Build dependency tab
  const deps = parseDepsFromReport(reportText);
  const depsBtn = $("#tab-deps");
  depsBtn.textContent = deps.length ? `Dependencies (${deps.length})` : "Dependencies";
  $("#deps-panel").innerHTML = buildDepsPanel(deps);
  currentDepFilter = "all";

  // Always open on Report tab when new result arrives
  switchTab("report");

  $("#result-card").classList.remove("hidden");
  $("#result-card").scrollIntoView({ behavior: "smooth", block: "start" });
}


// ── Post-process rendered HTML ────────────────────────────────────
function postProcessReport(container) {
  // 1. Wrap every table in overflow-x scroll wrapper
  container.querySelectorAll("table").forEach(tbl => {
    if (tbl.parentElement.classList.contains("table-wrap")) return;
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    tbl.parentNode.insertBefore(wrap, tbl);
    wrap.appendChild(tbl);
  });

  // 2. Severity badges in table cells
  const sevMap = {
    "CRITICAL": "sev-critical",
    "HIGH":     "sev-high",
    "MEDIUM":   "sev-medium",
    "LOW":      "sev-low",
    "UNKNOWN":  "sev-unknown",
  };
  container.querySelectorAll("td").forEach(td => {
    const t = td.textContent.trim();
    if (sevMap[t]) {
      td.innerHTML = `<span class="sev-badge ${sevMap[t]}">${t}</span>`;
      return;
    }
    // Also handle inline severity labels like "Severity: HIGH"
    if (/^(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)$/i.test(t)) {
      const cls = sevMap[t.toUpperCase()] || "sev-unknown";
      td.innerHTML = `<span class="sev-badge ${cls}">${t.toUpperCase()}</span>`;
    }
  });

  // 3. "YES" / "NO" safe-to-upgrade badges + VULNERABLE / SAFE status badges
  container.querySelectorAll("td").forEach(td => {
    const t = td.textContent.trim();
    if (t === "YES")        td.innerHTML = `<span class="safe-yes">YES</span>`;
    else if (t === "NO")    td.innerHTML = `<span class="safe-no">NO</span>`;
    else if (t === "VULNERABLE") td.innerHTML = `<span class="sev-badge sev-high">VULNERABLE</span>`;
    else if (t === "SAFE")  td.innerHTML = `<span class="status-safe">SAFE</span>`;
  });

  // 4. Style upgrade arrows: "group:a:v -> group:a:v"
  container.querySelectorAll("td").forEach(td => {
    if (!td.textContent.includes("->")) return;
    // Replace " -> " with styled arrow while preserving the dep coords
    td.innerHTML = td.innerHTML.replace(
      /([^\s<]+:[^\s<]+:[^\s<]+)\s*-&gt;\s*([^\s<]+:[^\s<]+:[^\s<]+)/g,
      '<span class="dep-from">$1</span><span class="upgrade-arrow"> → </span><span class="dep-to">$2</span>'
    );
  });

  // 5. Monospace class on first-column cells that look like dep coordinates
  container.querySelectorAll("table tbody tr").forEach(tr => {
    const td = tr.querySelector("td:first-child");
    if (td && /^[\w][\w.\-]+:[\w][\w.\-]+/.test(td.textContent.trim())) {
      td.classList.add("dep-name");
    }
  });

  // 6. Style "Direct" / "Transitive (dN)" type badges in dep overview table
  container.querySelectorAll("td").forEach(td => {
    const t = td.textContent.trim();
    if (t === "Direct") {
      td.innerHTML = `<span class="type-direct">Direct</span>`;
    } else if (/^Transitive/.test(t)) {
      td.innerHTML = `<span class="type-transitive">${escHtml(t)}</span>`;
    }
  });

  // 8. Hide the internal "Dependency Allowlist: [...]" line
  container.querySelectorAll("p").forEach(p => {
    if (/dependency allowlist\s*:/i.test(p.textContent)) {
      p.style.display = "none";
    }
  });
}


// ── Section navigation ────────────────────────────────────────────
function buildSectionNav(container) {
  const nav = $("#section-nav");
  nav.innerHTML = "";

  const headings = container.querySelectorAll("h2");
  if (headings.length === 0) return;

  headings.forEach((h, i) => {
    // Assign an id for anchor scrolling
    const id = `section-${i}`;
    h.id = id;

    // Strip leading "1. " numbering from heading text
    const label = h.textContent.replace(/^\d+\.\s*/, "").trim();

    const btn = document.createElement("button");
    btn.textContent = label;
    btn.onclick = () => {
      h.scrollIntoView({ behavior: "smooth", block: "start" });
      nav.querySelectorAll("button").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
    };
    nav.appendChild(btn);
  });

  // Highlight active section on scroll
  const observer = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const idx = Array.from(headings).indexOf(entry.target);
          nav.querySelectorAll("button").forEach((b, i) => {
            b.classList.toggle("active", i === idx);
          });
        }
      });
    },
    { rootMargin: "-20% 0px -70% 0px" }
  );
  headings.forEach(h => observer.observe(h));
}


// ── Summary bar ───────────────────────────────────────────────────
function buildSummaryBar(text) {
  const totalMatch = text.match(/Total Dependencies Checked[:\s]+(\d+)/i);
  const vulnMatch  = text.match(/Vulnerable Count[:\s]+(\d+)/i);
  const safeMatch  = text.match(/Safe Count[:\s]+(\d+)/i);

  const total = totalMatch ? parseInt(totalMatch[1]) : null;
  const vuln  = vulnMatch  ? parseInt(vulnMatch[1])  : null;
  const safe  = safeMatch  ? parseInt(safeMatch[1])  : null;

  const critCount = (text.match(/\|\s*CRITICAL\s*\|/gi) || []).length;
  const highCount = (text.match(/\|\s*HIGH\s*\|/gi)     || []).length;
  const medCount  = (text.match(/\|\s*MEDIUM\s*\|/gi)   || []).length;
  const lowCount  = (text.match(/\|\s*LOW\s*\|/gi)      || []).length;

  let html = "";
  if (total !== null) html += stat("Deps Scanned", total, "badge-blue");
  if (vuln  !== null) html += stat("Vulnerable",   vuln,  vuln > 0 ? "badge-red" : "badge-green");
  if (safe  !== null) html += stat("Safe",          safe,  "badge-green");
  if (critCount > 0)  html += stat("Critical", critCount, "badge-red");
  if (highCount > 0)  html += stat("High",     highCount, "badge-orange");
  if (medCount  > 0)  html += stat("Medium",   medCount,  "badge-yellow");
  if (lowCount  > 0)  html += stat("Low",      lowCount,  "badge-blue");

  if (!html) html += '<span class="text-gray-500 text-xs">Scan complete</span>';
  return html;
}

function stat(label, value, badgeClass) {
  return `<div class="flex items-center gap-2">
    <span class="text-gray-500 text-xs">${label}</span>
    <span class="badge ${badgeClass}">${value}</span>
  </div>`;
}


// ── Copy / Download ───────────────────────────────────────────────
function copyReport() {
  if (!lastReport) return;
  navigator.clipboard.writeText(lastReport)
    .then(() => toast("Report copied to clipboard"))
    .catch(() => toast("Copy failed", true));
}

function downloadReport() {
  if (!lastReport) return;
  const blob = new Blob([lastReport], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnerability_report_${new Date().toISOString().slice(0,19).replace(/[T:]/g, "-")}.md`;
  a.click();
  URL.revokeObjectURL(url);
  toast("Report downloaded");
}


// ── Tab switching ────────────────────────────────────────────────
function switchTab(tab) {
  currentTab = tab;
  $("#tab-report").classList.toggle("active", tab === "report");
  $("#tab-deps").classList.toggle("active",   tab === "deps");
  $("#report-panel").classList.toggle("hidden", tab !== "report");
  $("#deps-panel").classList.toggle("hidden",   tab !== "deps");
  // Section nav only makes sense on the report tab
  $("#section-nav").style.visibility = tab === "report" ? "visible" : "hidden";
}


// ── Parse dep table from report markdown ─────────────────────────
function parseDepsFromReport(text) {
  const deps = [];
  let inSection = false;
  let headerSkipped = false;

  for (const raw of text.split("\n")) {
    const line = raw.trim();

    // Enter "All Dependencies" section
    if (/^##\s+\d*\.?\s*All Dependencies/i.test(line)) {
      inSection = true;
      headerSkipped = false;
      continue;
    }
    // Leave on next ## heading
    if (inSection && /^##\s/.test(line)) break;
    if (!inSection || !line.startsWith("|")) continue;
    // Skip separator row
    if (/^\|\s*[-:]+\s*\|/.test(line)) continue;
    // Skip column header row (first non-separator table row)
    if (!headerSkipped) { headerSkipped = true; continue; }

    const cols = line.replace(/^\||\|$/g, "").split("|").map(c => c.trim());
    if (cols.length < 4) continue;

    const dep    = cols[0].replace(/[`*_]/g, "").trim();
    const type   = cols[1] || "DIRECT";
    const scope  = cols[2] || "compile";
    const status = cols[3] || "SAFE";
    const vulns  = cols[4] || "—";

    if (!dep || /^dependency$/i.test(dep)) continue;

    deps.push({ dep, type, scope, status, vulns });
  }
  return deps;
}


// ── Build the deps panel HTML ─────────────────────────────────────
function buildDepsPanel(deps) {
  if (!deps.length) {
    return `<div class="text-center py-14 text-gray-600 text-sm">
      No dependency data in this report.<br/>
      <span class="text-xs text-gray-700 mt-1 inline-block">Run a full GitHub repo scan to see the dependency tree.</span>
    </div>`;
  }

  const directCount    = deps.filter(d => /^DIRECT$/i.test(d.type)).length;
  const transitiveCount = deps.length - directCount;
  const vulnCount      = deps.filter(d => /VULNERABLE/i.test(d.status)).length;
  const safeCount      = deps.length - vulnCount;

  const rows = deps.map(d => {
    const isDirect = /^DIRECT$/i.test(d.type);
    const isVuln   = /VULNERABLE/i.test(d.status);

    const dm = d.type.match(/depth=(\d+)/i);
    const typeBadge = isDirect
      ? `<span class="type-direct">Direct</span>`
      : `<span class="type-transitive">${dm ? `T+${dm[1]}` : "Transitive"}</span>`;

    const statusBadge = isVuln
      ? `<span class="sev-badge sev-high">Vulnerable</span>`
      : `<span class="status-safe">Safe</span>`;

    const vulnHtml = isVuln
      ? `<span style="color:#fca5a5;font-family:'JetBrains Mono',monospace;font-size:.68rem">${escHtml(d.vulns)}</span>`
      : `<span style="color:#374151;font-size:.68rem">—</span>`;

    return `<tr data-dtype="${isDirect ? "direct" : "transitive"}"
                data-dstatus="${isVuln ? "vulnerable" : "safe"}"
                data-dname="${escHtml(d.dep.toLowerCase())}">
      <td class="dep-name">${escHtml(d.dep)}</td>
      <td>${typeBadge}</td>
      <td><span style="color:#4b5563;font-size:.7rem;font-family:'JetBrains Mono',monospace">${escHtml(d.scope)}</span></td>
      <td>${statusBadge}</td>
      <td>${vulnHtml}</td>
    </tr>`;
  }).join("");

  return `
    <div class="space-y-4">
      <!-- Stats -->
      <div class="flex gap-4 flex-wrap">
        ${stat("Total",       deps.length,      "badge-blue")}
        ${stat("Direct",      directCount,      "badge-blue")}
        ${stat("Transitive",  transitiveCount,  "badge-blue")}
        ${vulnCount ? stat("Vulnerable", vulnCount, "badge-red")   : ""}
        ${safeCount ? stat("Safe",       safeCount, "badge-green") : ""}
      </div>

      <!-- Search + filters -->
      <div class="flex gap-2 flex-wrap items-center">
        <input id="dep-search" type="text" placeholder="Search dependencies…"
               class="rounded-lg px-3 py-1.5 text-xs"
               style="width:220px"
               oninput="filterDepsTable()" />
        <div class="flex gap-1 flex-wrap">
          <button class="dep-filter active" data-f="all"         onclick="setDepFilter('all')">All</button>
          <button class="dep-filter"        data-f="direct"      onclick="setDepFilter('direct')">Direct</button>
          <button class="dep-filter"        data-f="transitive"  onclick="setDepFilter('transitive')">Transitive</button>
          <button class="dep-filter"        data-f="vulnerable"  onclick="setDepFilter('vulnerable')">Vulnerable</button>
          <button class="dep-filter"        data-f="safe"        onclick="setDepFilter('safe')">Safe</button>
        </div>
      </div>

      <!-- Table -->
      <div class="table-wrap">
        <table id="deps-table" style="width:100%">
          <thead>
            <tr>
              <th>Dependency</th>
              <th>Type</th>
              <th>Scope</th>
              <th>Status</th>
              <th>Vulnerabilities</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div id="deps-empty" class="hidden text-center py-8 text-gray-600 text-xs">No dependencies match the filter</div>
    </div>`;
}


// ── Dep filter / search ───────────────────────────────────────────
function setDepFilter(filter) {
  currentDepFilter = filter;
  document.querySelectorAll(".dep-filter").forEach(b => {
    b.classList.toggle("active", b.dataset.f === filter);
  });
  filterDepsTable();
}

function filterDepsTable() {
  const search = (document.getElementById("dep-search")?.value || "").toLowerCase().trim();
  const rows = document.querySelectorAll("#deps-table tbody tr");
  let visible = 0;

  rows.forEach(row => {
    const matchFilter =
      currentDepFilter === "all" ||
      (currentDepFilter === "direct"      && row.dataset.dtype   === "direct") ||
      (currentDepFilter === "transitive"  && row.dataset.dtype   === "transitive") ||
      (currentDepFilter === "vulnerable"  && row.dataset.dstatus === "vulnerable") ||
      (currentDepFilter === "safe"        && row.dataset.dstatus === "safe");

    const matchSearch = !search || row.dataset.dname.includes(search);

    const show = matchFilter && matchSearch;
    row.classList.toggle("hidden", !show);
    if (show) visible++;
  });

  const empty = document.getElementById("deps-empty");
  if (empty) empty.classList.toggle("hidden", visible > 0);
}


// ── Keyboard shortcuts ───────────────────────────────────────────
$("#github-url").addEventListener("keydown", e => { if (e.key === "Enter") runScan(); });
$("#dep-list").addEventListener("keydown", e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runScan(); });


// ── History ───────────────────────────────────────────────────────
let historyOpen = false;
let activeHistoryId = null;

function toggleHistory() {
  if (historyOpen) {
    closeHistory();
  } else {
    openHistory();
  }
}

function openHistory() {
  historyOpen = true;
  const sec = $("#history-section");
  sec.classList.remove("hidden");
  sec.scrollIntoView({ behavior: "smooth", block: "start" });
  loadHistory();
}

function closeHistory() {
  historyOpen = false;
  $("#history-section").classList.add("hidden");
}

async function loadHistory() {
  const list = $("#history-list");
  list.innerHTML = '<div class="px-5 py-4 text-xs text-gray-600">Loading…</div>';
  try {
    const items = await api("/history");
    if (!items.length) {
      list.innerHTML = '<div class="px-5 py-6 text-xs text-gray-600 text-center">No scans recorded yet.</div>';
      return;
    }
    list.innerHTML = "";
    items.forEach(item => {
      const row = document.createElement("div");
      row.className = "history-item" + (item.id === activeHistoryId ? " active" : "");
      row.dataset.id = item.id;

      const vulnBadge = item.vuln_count > 0
        ? `<span class="badge badge-red ml-2">${item.vuln_count} vuln</span>`
        : `<span class="badge badge-green ml-2">Clean</span>`;

      const depBadge = item.total_deps
        ? `<span class="badge badge-blue ml-1">${item.total_deps} deps</span>`
        : "";

      const date = item.scanned_at
        ? new Date(item.scanned_at + "Z").toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
        : "";

      const buildBadge = item.build_system
        ? `<span class="text-gray-700 text-xs ml-2">${item.build_system}</span>`
        : "";

      row.innerHTML = `
        <div class="flex-1 min-w-0">
          <div class="flex items-center flex-wrap gap-1">
            <span class="text-gray-300 text-xs font-medium truncate max-w-xs">${escHtml(item.display_name)}</span>
            ${vulnBadge}${depBadge}${buildBadge}
          </div>
          <div class="text-gray-700 text-xs mt-0.5 font-mono">${escHtml(item.scan_key)}</div>
        </div>
        <div class="flex items-center gap-2 ml-3 flex-shrink-0">
          <span class="text-gray-700 text-xs tabular-nums">${date}</span>
          <button onclick="deleteHistoryItem(event, ${item.id})"
                  class="text-gray-700 hover:text-red-400 transition p-0.5 rounded opacity-0 group-hover:opacity-100"
                  title="Delete">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
          </button>
        </div>`;
      row.addEventListener("click", (e) => {
        if (e.target.closest("button")) return;
        loadHistoryItem(item.id);
      });
      list.appendChild(row);
    });

    // Show delete button on hover (CSS group trick not available in plain Tailwind here, use JS)
    list.querySelectorAll(".history-item").forEach(row => {
      const btn = row.querySelector("button");
      row.addEventListener("mouseenter", () => btn && (btn.style.opacity = "1"));
      row.addEventListener("mouseleave", () => btn && (btn.style.opacity = "0"));
    });
  } catch (e) {
    list.innerHTML = `<div class="px-5 py-4 text-xs text-red-400">Failed to load history: ${escHtml(e.message)}</div>`;
  }
}

async function loadHistoryItem(id) {
  activeHistoryId = id;
  // Highlight active row
  $("#history-list").querySelectorAll(".history-item").forEach(r => {
    r.classList.toggle("active", parseInt(r.dataset.id) === id);
  });
  try {
    const item = await api(`/history/${id}`);
    showResult(item.report_md);
  } catch (e) {
    toast("Failed to load report: " + e.message, true);
  }
}

async function deleteHistoryItem(event, id) {
  event.stopPropagation();
  try {
    const res = await fetch(`${API}/history/${id}`, { method: "DELETE" });
    if (!res.ok) throw new Error(`Server error ${res.status}`);
    if (activeHistoryId === id) {
      activeHistoryId = null;
    }
    loadHistory(); // refresh list
    toast("Scan deleted");
  } catch (e) {
    toast("Delete failed: " + e.message, true);
  }
}


// ── Init ─────────────────────────────────────────────────────────
checkHealth();
setInterval(checkHealth, 30000);
