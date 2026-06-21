"use strict";

const state = { view: "pseudo", funcKey: null, funcs: [] };

const $ = (sel) => document.querySelector(sel);

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}

async function refresh() {
  const info = await api("/api/info");
  if (info.loaded) {
    $("#meta").textContent =
      `${info.name}  ·  ${info.format}  ·  ${info.arch}  ·  ${info.functions} functions`;
  } else {
    $("#meta").textContent = "no file loaded — use “load file…”";
  }
  state.funcs = await api("/api/functions");
  renderFuncList();
}

function renderFuncList() {
  const filter = ($("#filter").value || "").toLowerCase();
  const ul = $("#funcList");
  ul.innerHTML = "";
  for (const f of state.funcs) {
    if (filter && !f.name.toLowerCase().includes(filter)) continue;
    const li = document.createElement("li");
    if (f.key === state.funcKey) li.classList.add("active");
    li.innerHTML =
      `<span class="fname">${escapeHtml(f.name)}<span class="badge">${f.kind}</span></span>` +
      `<span class="faddr">${f.addr} · ${f.size}b</span>`;
    li.onclick = () => { state.funcKey = f.key; renderFuncList(); renderView(); };
    ul.appendChild(li);
  }
}

function setView(v) {
  state.view = v;
  document.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.view === v));
  renderView();
}

async function renderView() {
  const host = $("#view");
  if (state.view === "strings") {
    const rows = await api("/api/strings");
    host.innerHTML = renderStrings(rows);
    return;
  }
  if (!state.funcKey) {
    host.innerHTML = '<div class="empty">Select a function to begin.</div>';
    return;
  }
  if (state.view === "pseudo") {
    const r = await api(`/api/pseudocode/${state.funcKey}`);
    host.innerHTML = `<pre class="code">${highlight(r.code || "")}</pre>`;
  } else {
    const r = await api(`/api/disasm/${state.funcKey}`);
    host.innerHTML = renderDisasm(r.rows || []);
  }
}

function renderDisasm(rows) {
  let out = '<table class="disasm">';
  for (const row of rows) {
    const parts = row.text.split(/\s+/);
    const mn = escapeHtml(parts[0] || "");
    const rest = escapeHtml(row.text.slice((parts[0] || "").length));
    out += `<tr><td class="addr">${row.addr}</td>` +
           `<td class="raw">${row.bytes || ""}</td>` +
           `<td><span class="mn">${mn}</span>${rest}</td></tr>`;
  }
  return out + "</table>";
}

function renderStrings(rows) {
  let out = '<table class="strs">';
  for (const r of rows) {
    out += `<tr><td class="addr">${r.addr}</td><td class="val">${escapeHtml(r.value)}</td></tr>`;
  }
  return out + "</table>";
}

const KEYWORDS = new Set([
  "function", "local", "if", "else", "while", "for", "return", "break",
  "continue", "goto", "true", "false", "null", "void",
]);

function highlight(code) {
  // tokenise on a per-line basis for comments + strings + words
  return code.split("\n").map((line) => {
    const ci = line.indexOf("//");
    let head = line, tail = "";
    if (ci >= 0) { head = line.slice(0, ci); tail = line.slice(ci); }
    let html = head.replace(/("[^"]*")|(\b\d+\b)|([A-Za-z_]\w*)/g,
      (m, str, num, word) => {
        if (str) return `<span class="tok-str">${escapeHtml(str)}</span>`;
        if (num) return `<span class="tok-num">${m}</span>`;
        if (word) {
          if (KEYWORDS.has(word)) return `<span class="tok-kw">${word}</span>`;
          return word;
        }
        return escapeHtml(m);
      });
    if (tail) html += `<span class="tok-com">${escapeHtml(tail)}</span>`;
    return html;
  }).join("\n");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

// --- wiring ---------------------------------------------------------------
document.querySelectorAll(".tab").forEach((t) =>
  t.addEventListener("click", () => setView(t.dataset.view)));
$("#filter").addEventListener("input", renderFuncList);
$("#fileInput").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  const r = await api("/api/upload", { method: "POST", body: fd });
  if (r.error) { alert("Load failed: " + r.error); return; }
  state.funcKey = null;
  await refresh();
  renderView();
});

refresh();
