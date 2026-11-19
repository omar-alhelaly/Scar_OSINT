"use strict";

// ---------- ثوابت ----------
const SOURCE_LABELS = {
  crtsh: "crt.sh",
  wayback: "Wayback Machine",
  github: "GitHub",
  virustotal: "VirusTotal",
  securitytrails: "SecurityTrails",
  shodan: "Shodan",
  censys: "Censys",
};
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const POLL_MS = 3000;
const MAX_POLL_ERRORS = 5;

// ---------- عناصر الصفحة ----------
const $ = (id) => document.getElementById(id);
const el = {
  domain: $("domain"),
  scanBtn: $("scanBtn"),
  status: $("statusLine"),
  bar: $("bar"),
  pct: $("pct"),
  sources: $("sources"),
  total: $("statTotal"),
  done: $("statDone"),
  failed: $("statFailed"),
  filter: $("filter"),
  rows: $("rows"),
  empty: $("empty"),
  copyBtn: $("copyBtn"),
  csvBtn: $("csvBtn"),
  jsonBtn: $("jsonBtn"),
  log: $("log"),
};

// ---------- الحالة ----------
const state = {
  scanId: null,
  data: null,
  timer: null,
  errors: 0,
  renderedTotal: -1,
  loggedStatus: {},
};

// ---------- أدوات مساعدة ----------
function log(msg) {
  const t = new Date().toLocaleTimeString();
  el.log.textContent += `[${t}] ${msg}\n`;
  el.log.scrollTop = el.log.scrollHeight;
}

function setStatus(text, kind = "") {
  el.status.textContent = text;
  el.status.className = `status ${kind}`.trim();
}

function setBusy(busy) {
  el.scanBtn.disabled = busy;
  el.scanBtn.textContent = busy ? "SCANNING..." : "START SCAN";
  el.domain.disabled = busy;
}

function setExportEnabled(enabled) {
  el.copyBtn.disabled = !enabled;
  el.csvBtn.disabled = !enabled;
  el.jsonBtn.disabled = !enabled;
}

function cleanDomain(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "");
}

async function api(path, options = {}) {
  const headers = {};
  if (options.body) headers["Content-Type"] = "application/json";
  if (CONFIG.API_TOKEN) headers.Authorization = `Bearer ${CONFIG.API_TOKEN}`;

  const res = await fetch(CONFIG.API_BASE + path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// ---------- الرسم على الصفحة ----------
function renderSources(list) {
  el.sources.replaceChildren();
  const byName = new Map((list || []).map((s) => [s.source, s]));

  for (const key of Object.keys(SOURCE_LABELS)) {
    const s = byName.get(key);
    const status = s ? s.status : "idle";

    const card = document.createElement("div");
    card.className = "source";

    const top = document.createElement("div");
    top.className = "source-top";

    const name = document.createElement("span");
    name.className = "source-name";
    name.textContent = SOURCE_LABELS[key];

    const badge = document.createElement("span");
    badge.className = `badge ${status}`;
    badge.textContent = status.toUpperCase();
    if (s && s.error) badge.title = s.error;

    top.append(name, badge);

    const count = document.createElement("div");
    count.className = "source-count";
    if (s && status === "done") count.textContent = `${s.found} found`;
    else if (s && s.error) count.textContent = s.error;
    else count.textContent = "-";
    if (s && s.error) count.title = s.error;

    card.append(top, count);
    el.sources.append(card);
  }
}

function filteredList() {
  const q = el.filter.value.trim().toLowerCase();
  const list = state.data ? state.data.subdomains : [];
  if (!q) return list;
  return list.filter((r) => r.subdomain.includes(q) || r.sources.some((s) => s.includes(q)));
}

function renderRows() {
  const list = filteredList();
  const frag = document.createDocumentFragment();

  list.forEach((r, i) => {
    const tr = document.createElement("tr");

    const n = document.createElement("td");
    n.className = "n";
    n.textContent = String(i + 1);

    const host = document.createElement("td");
    host.className = "host";
    host.textContent = r.subdomain;

    const src = document.createElement("td");
    for (const s of r.sources) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = SOURCE_LABELS[s] || s;
      src.append(chip);
    }

    tr.append(n, host, src);
    frag.append(tr);
  });

  el.rows.replaceChildren(frag);
  el.empty.hidden = list.length > 0;
}

function logChanges(sources) {
  for (const s of sources) {
    if (state.loggedStatus[s.source] === s.status) continue;
    state.loggedStatus[s.source] = s.status;
    const label = SOURCE_LABELS[s.source] || s.source;
    if (s.status === "done") log(`${label}: ${s.found} subdomains`);
    else if (s.status === "failed") log(`${label}: failed (${s.error})`);
    else if (s.status === "skipped") log(`${label}: skipped (${s.error})`);
  }
}

function render(data) {
  state.data = data;
  const srcs = data.sources;
  const finished = srcs.filter((s) => s.status !== "pending").length;
  const doneCount = srcs.filter((s) => s.status === "done").length;
  const failedCount = srcs.filter((s) => s.status === "failed").length;
  const pct = srcs.length ? Math.round((finished / srcs.length) * 100) : 0;

  el.bar.style.width = `${pct}%`;
  el.pct.textContent = `${pct}%`;
  el.total.textContent = String(data.total);
  el.done.textContent = `${doneCount}/${srcs.length}`;
  el.failed.textContent = String(failedCount);

  if (!el.domain.value) el.domain.value = data.domain;

  if (data.status === "complete") {
    setStatus(`Scan complete: ${data.total} subdomains found for ${data.domain}`, "ok");
  } else {
    setStatus(`Scanning ${data.domain}... ${finished}/${srcs.length} sources finished`, "run");
  }

  renderSources(srcs);
  logChanges(srcs);

  if (state.renderedTotal !== data.total || data.status === "complete") {
    renderRows();
    state.renderedTotal = data.total;
  }
  setExportEnabled(data.total > 0);
}

function resetUi() {
  state.data = null;
  state.renderedTotal = -1;
  state.loggedStatus = {};
  state.errors = 0;
  el.bar.style.width = "0%";
  el.pct.textContent = "0%";
  el.total.textContent = "0";
  el.done.textContent = "0/0";
  el.failed.textContent = "0";
  renderSources(null);
  renderRows();
  setExportEnabled(false);
}

// ---------- المتابعة (polling) ----------
function stopPolling() {
  clearTimeout(state.timer);
  state.timer = null;
}

async function tick() {
  if (!state.scanId) return;
  try {
    const data = await api(`/api/scans/${state.scanId}`);
    state.errors = 0;
    render(data);
    if (data.status === "complete") {
      setBusy(false);
      log(`Scan complete: ${data.total} subdomains`);
      return;
    }
  } catch (err) {
    state.errors += 1;
    log(`Error: ${err.message}`);
    if (err.status === 404 || state.errors >= MAX_POLL_ERRORS) {
      setBusy(false);
      setStatus(`Stopped: ${err.message}`, "err");
      log("Polling stopped.");
      return;
    }
  }
  state.timer = setTimeout(tick, POLL_MS);
}

// ---------- بدء الـ scan ----------
async function startScan() {
  const domain = cleanDomain(el.domain.value);
  if (!domain) {
    setStatus("Enter a valid domain, for example: example.com", "err");
    el.domain.focus();
    return;
  }

  stopPolling();
  resetUi();
  setBusy(true);
  setStatus(`Starting scan for ${domain}...`, "run");
  log(`Starting scan for ${domain}`);

  try {
    const res = await api("/api/scans", { method: "POST", body: JSON.stringify({ domain }) });
    state.scanId = res.scanId;
    history.replaceState(null, "", `#${res.scanId}`);
    log(`Scan created: ${res.scanId}`);
    log(`Active sources: ${res.sources.join(", ") || "none"}`);
    tick();
  } catch (err) {
    log(`Error: ${err.message}`);
    setStatus(`Could not start the scan: ${err.message}`, "err");
    setBusy(false);
  }
}

// ---------- التصدير ----------
function download(filename, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const csvCell = (v) => `"${String(v).replace(/"/g, '""')}"`;
const baseName = () => (state.data ? state.data.domain : "results");

async function copyList() {
  const text = filteredList().map((r) => r.subdomain).join("\n");
  try {
    await navigator.clipboard.writeText(text);
    log(`Copied ${filteredList().length} subdomains to clipboard`);
  } catch {
    log("Copy failed: the browser blocked clipboard access");
  }
}

function exportCsv() {
  const lines = filteredList().map((r) => `${csvCell(r.subdomain)},${csvCell(r.sources.join("|"))}`);
  download(`${baseName()}-subdomains.csv`, ["subdomain,sources", ...lines].join("\n"), "text/csv");
  log("Exported CSV");
}

function exportJson() {
  download(`${baseName()}-subdomains.json`, JSON.stringify(filteredList(), null, 2), "application/json");
  log("Exported JSON");
}

// ---------- ربط الأحداث ----------
el.scanBtn.addEventListener("click", startScan);
el.domain.addEventListener("keydown", (e) => {
  if (e.key === "Enter") startScan();
});
el.filter.addEventListener("input", renderRows);
el.copyBtn.addEventListener("click", copyList);
el.csvBtn.addEventListener("click", exportCsv);
el.jsonBtn.addEventListener("click", exportJson);

// ---------- تشغيل أولي ----------
renderSources(null);
renderRows();
log("HIDDEN OSINT initialized.");
log("Waiting for target domain...");

// لو الرابط فيه #scanId نكمل متابعة الـ scan ده
const hashId = location.hash.slice(1);
if (UUID_RE.test(hashId)) {
  state.scanId = hashId;
  setBusy(true);
  log(`Resuming scan ${hashId}`);
  tick();
}