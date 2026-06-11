/**
 * PhishGuard — Dashboard Script
 * Handles auth, URL analysis, results, and history.
 */

const API_BASE = "http://127.0.0.1:5000";

// ── Auth Guard ──────────────────────────────────────────────
// Redirect to login if no token stored
(function checkAuth() {
  const token = localStorage.getItem("token");
  if (!token) { window.location.href = "login.html"; return; }

  // Show username in header
  const username = localStorage.getItem("username") || "User";
  const el = document.getElementById("user-label");
  if (el) el.textContent = username.toUpperCase();
})();

// ── Helpers ─────────────────────────────────────────────────
function getToken() { return localStorage.getItem("token"); }

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${getToken()}`
  };
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("username");
  window.location.href = "login.html";
}

// ── Clock ────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById("live-clock");
  if (!el) return;
  const n = new Date();
  const p = v => String(v).padStart(2, "0");
  el.textContent = `${p(n.getUTCHours())}:${p(n.getUTCMinutes())}:${p(n.getUTCSeconds())} UTC`;
}
setInterval(updateClock, 1000);
updateClock();

// ── Sample URLs ──────────────────────────────────────────────
function setSample(url) {
  const input = document.getElementById("url-input");
  input.value = url.replace(/^https?:\/\//, "");
  input._full = url;
  input.focus();
}

function getFullURL() {
  const input = document.getElementById("url-input");
  if (input._full && input.value === input._full.replace(/^https?:\/\//, "")) {
    const r = input._full; delete input._full; return r;
  }
  const val = input.value.trim();
  if (!val) return "";
  return /^https?:\/\//i.test(val) ? val : "https://" + val;
}

// ── Analyze ──────────────────────────────────────────────────
async function analyzeURL() {
  const url = getFullURL();
  if (!url) { shakeInput(); return; }

  showLoading(true);
  hideResult();

  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ url })
    });

    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error(`Server error: ${res.status}`);

    const result = await res.json();
    renderResult(result);
    await loadHistory();

  } catch (err) {
    showError(err.message);
  } finally {
    showLoading(false);
  }
}

// ── Render Result ────────────────────────────────────────────
function renderResult(data) {
  const section   = document.getElementById("result-section");
  const badge     = document.getElementById("status-badge");
  const urlEl     = document.getElementById("result-url");
  const scoreEl   = document.getElementById("score-value");
  const scoreBar  = document.getElementById("score-bar");
  const reasonsEl = document.getElementById("reasons-list");
  const tsEl      = document.getElementById("result-timestamp");

  urlEl.textContent = data.url;
  scoreEl.textContent = data.score;

  const maxScore = 11; // updated — 11 checks now
  const pct = Math.min((data.score / maxScore) * 100, 100);

  const colorMap = {
    "Safe":      { badge: "badge-safe",   bar: "#00e676", text: "#00e676" },
    "Suspicious":{ badge: "badge-warn",   bar: "#ffd740", text: "#ffd740" },
    "High Risk": { badge: "badge-danger", bar: "#ff4444", text: "#ff4444" }
  };

  const colors = colorMap[data.status] || colorMap["Suspicious"];
  const emojis = { "Safe": "🟢", "Suspicious": "🟡", "High Risk": "🔴" };

  badge.className = `status-badge ${colors.badge}`;
  badge.textContent = `${emojis[data.status] || "⚪"} ${data.status.toUpperCase()}`;
  scoreEl.style.color = colors.text;
  scoreBar.style.width = `${pct}%`;
  scoreBar.style.background = colors.bar;

  reasonsEl.innerHTML = "";
  if (data.reasons && data.reasons.length > 0) {
    data.reasons.forEach(reason => {
      const item = document.createElement("div");
      item.className = "reason-item";
      item.innerHTML = `
        <span class="reason-dot" style="background:${colors.bar}"></span>
        <span>${reason}</span>`;
      reasonsEl.appendChild(item);
    });
  } else {
    reasonsEl.innerHTML = `<div class="no-threats">✓ No phishing indicators detected</div>`;
  }

  const ts = data.timestamp ? new Date(data.timestamp) : new Date();
  tsEl.textContent = `ANALYZED AT ${ts.toUTCString()}`;

  section.classList.remove("hidden");
  section.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ── Load History ─────────────────────────────────────────────
async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/history?limit=30`, {
      headers: authHeaders()
    });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error();

    const records = await res.json();
    renderHistory(records);
    updateStats(records);

  } catch (err) {
    console.warn("History load failed:", err);
  }
}

function renderHistory(records) {
  const tbody = document.getElementById("history-body");
  tbody.innerHTML = "";

  if (!records || records.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No scans yet — analyze a URL above to begin.</td></tr>`;
    return;
  }

  records.forEach((rec, idx) => {
    const sc = {
      "Safe":      { badge: "badge-safe",   color: "#00e676" },
      "Suspicious":{ badge: "badge-warn",   color: "#ffd740" },
      "High Risk": { badge: "badge-danger", color: "#ff4444" }
    }[rec.status] || { badge: "badge-warn", color: "#ffd740" };

    const ts = rec.timestamp ? new Date(rec.timestamp) : null;
    const p  = v => String(v).padStart(2, "0");
    const timeStr = ts ? `${p(ts.getHours())}:${p(ts.getMinutes())}:${p(ts.getSeconds())}` : "—";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td style="font-family:var(--font-mono);color:var(--text-muted);font-size:.7rem">${String(idx+1).padStart(2,"0")}</td>
      <td class="url-cell" title="${esc(rec.url)}">${esc(rec.url)}</td>
      <td class="score-cell" style="color:${sc.color}">${rec.score}</td>
      <td><span class="badge-sm ${sc.badge}">${rec.status.toUpperCase()}</span></td>
      <td class="time-cell">${timeStr}</td>`;
    tbody.appendChild(row);
  });
}

function updateStats(records) {
  animateCounter("stat-total",      records.length);
  animateCounter("stat-safe",       records.filter(r => r.status === "Safe").length);
  animateCounter("stat-suspicious", records.filter(r => r.status === "Suspicious").length);
  animateCounter("stat-high",       records.filter(r => r.status === "High Risk").length);
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.textContent) || 0;
  if (current === target) return;
  const step = target > current ? 1 : -1;
  let val = current;
  const timer = setInterval(() => {
    val += step;
    el.textContent = val;
    if (val === target) clearInterval(timer);
  }, 30);
}

// ── Clear History ────────────────────────────────────────────
async function clearHistory() {
  if (!confirm("Clear all your scan history?")) return;
  try {
    await fetch(`${API_BASE}/history`, { method: "DELETE", headers: authHeaders() });
    renderHistory([]);
    updateStats([]);
  } catch (err) { alert("Could not clear history."); }
}

// ── UI Helpers ───────────────────────────────────────────────
function showLoading(v) {
  document.getElementById("loading-overlay").classList.toggle("hidden", !v);
}

function hideResult() {
  document.getElementById("result-section").classList.add("hidden");
}

function shakeInput() {
  const wrap = document.querySelector(".input-wrap");
  wrap.style.animation = "shake 0.4s ease";
  wrap.style.borderColor = "var(--danger)";
  setTimeout(() => { wrap.style.animation = ""; wrap.style.borderColor = ""; }, 500);
}

function showError(msg) {
  const section = document.getElementById("result-section");
  section.classList.remove("hidden");
  document.getElementById("status-badge").className = "status-badge badge-danger";
  document.getElementById("status-badge").textContent = "⚠ ERROR";
  document.getElementById("result-url").textContent = "Could not reach the analysis server.";
  document.getElementById("score-value").textContent = "—";
  document.getElementById("score-value").style.color = "var(--danger)";
  document.getElementById("score-bar").style.width = "0%";
  document.getElementById("reasons-list").innerHTML = `
    <div class="reason-item">
      <span class="reason-dot" style="background:var(--danger)"></span>
      <span>${esc(msg)}</span>
    </div>`;
}

function esc(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Init ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("url-input");
  input.addEventListener("keydown", e => { if (e.key === "Enter") analyzeURL(); });
  input.addEventListener("input",   () => { delete input._full; });
  loadHistory();
});

const _style = document.createElement("style");
_style.textContent = `@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-6px)}40%{transform:translateX(6px)}60%{transform:translateX(-4px)}80%{transform:translateX(4px)}}`;
document.head.appendChild(_style);
