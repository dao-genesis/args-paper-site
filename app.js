/* ARGs 论文 · 全内容工作台
   概览: data.json (明文进度总览)
   核心: content.enc (稿件中英/图表/表格, 口令派生密钥 AES-256-GCM, 浏览器内解密)  */
"use strict";

const LS_KEY = "args_gate_pass_v2";   // 记住时存口令(本机浏览器), 用于重新派生解密密钥
const PBKDF2_ITERS = 200000;

let CORE = null;   // 解密后的核心内容
let OVERVIEW = null;
let PASS = null;   // 当前会话内存中的访问口令(仅用于按需解密成果最小包, 不落盘)

/* 从版本串解析数值(如 "v54 (…)" → 54) */
function verNum(s) {
  const m = String(s == null ? "" : s).match(/v(\d+)/i);
  return m ? parseInt(m[1], 10) : null;
}
/* 概览(data.json)记录的权威 ER 稿件版本 */
function overviewErVer() {
  return (OVERVIEW && OVERVIEW.submission && OVERVIEW.submission.er && OVERVIEW.submission.er.version) || "";
}
/* 页内稿件版本标签 = 密文自身版本(即真正展示的内容), 诚实标注, 绝不冒用概览版本 */
function erVer() {
  const m = String((CORE && CORE.version) || "").match(/v\d+/i);
  return m ? m[0] : "稿件快照";
}

/* ---------- 工具 ---------- */
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function b64ToBytes(b64) {
  const bin = atob(b64.trim());
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function toast(msg) {
  const t = document.getElementById("toast");
  if (!t) return;
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._t);
  t._t = setTimeout(() => t.classList.remove("show"), 1600);
}
async function copyText(s) {
  try {
    await navigator.clipboard.writeText(s);
    toast("已复制");
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = s; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand("copy"); toast("已复制"); }
    catch (_) { toast("复制失败, 请手动选择"); }
    ta.remove();
  }
}
function downloadBlob(content, filename, mime) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mime || "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
function dataUriToBlob(uri) {
  const [head, b64] = uri.split(",");
  const mime = (head.match(/data:([^;]+)/) || [, "application/octet-stream"])[1];
  const bytes = b64ToBytes(b64);
  return { blob: new Blob([bytes], { type: mime }), ext: (mime.split("/")[1] || "bin").replace("+xml", "") };
}

/* ---------- 解密 ---------- */
async function deriveKey(pass, salt) {
  const mat = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    mat, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
/* 拉取二进制密文, 带下载进度回调; 走浏览器/CDN 缓存(去掉缓存破坏), 冷启只需一次全量, 之后走 304 秒开 */
async function fetchEncBytes(url, onProgress) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 60000);   // 60s 硬超时, 杜绝永久卡"解密中"
  try {
    const resp = await fetch(url, { signal: ctl.signal });     // cache:default → 可被 CDN/浏览器缓存
    if (!resp.ok) { const e = new Error("http " + resp.status); e.kind = "network"; throw e; }
    const total = +(resp.headers.get("content-length") || 0);
    if (!resp.body || !total) {                                // 无 stream/长度: 直接 arrayBuffer
      return new Uint8Array(await resp.arrayBuffer());
    }
    const reader = resp.body.getReader();
    const chunks = []; let recv = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value); recv += value.length;
      if (onProgress) onProgress(recv / total);
    }
    const out = new Uint8Array(recv); let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
  } catch (e) {
    if (e && e.kind === "network") throw e;
    const ne = new Error("network"); ne.kind = "network"; throw ne;   // 加载失败/超时, 非口令问题
  } finally {
    clearTimeout(timer);
  }
}
/* 用口令解密一个 二进制(salt|iv|ct) 密文文件, 返回明文字节 */
async function decryptEncFile(url, pass, onProgress) {
  const raw = await fetchEncBytes(url, onProgress);
  const salt = raw.slice(0, 16), iv = raw.slice(16, 28), ct = raw.slice(28);
  const key = await deriveKey(pass, salt);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}
async function decryptCore(pass, onProgress) {
  const pt = await decryptEncFile("content.enc", pass, onProgress);   // 口令错→AES-GCM 抛异常
  return JSON.parse(new TextDecoder().decode(pt));
}

/* ---------- 登录门 ---------- */
async function attempt(pass, remember) {
  const err = document.getElementById("gate-err");
  const btn = document.getElementById("gate-btn");
  if (!pass) { err.textContent = "请输入口令"; return; }
  btn.disabled = true; btn.textContent = "加载加密内容…"; err.textContent = "";
  try {
    CORE = await decryptCore(pass, (frac) => {
      btn.textContent = "加载加密内容… " + Math.round(frac * 100) + "%";
    });
    btn.textContent = "解密内容…";
    PASS = pass;
    if (remember) localStorage.setItem(LS_KEY, pass);
    else sessionStorage.setItem(LS_KEY, pass);
    openApp();
  } catch (e) {
    if (e && e.kind === "network") {
      err.textContent = "内容加载失败(网络/CDN 未就绪), 请稍候重试——非口令问题。";
    } else {
      err.textContent = "口令不正确或内容无法解密";
      document.getElementById("gate-input").value = "";
    }
  } finally {
    btn.disabled = false; btn.textContent = "进入";
  }
}
function openApp() {
  document.getElementById("gate").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  bootstrap();
}
document.getElementById("gate-btn").addEventListener("click", () =>
  attempt(document.getElementById("gate-input").value,
          document.getElementById("gate-remember").checked));
document.getElementById("gate-input").addEventListener("keydown", e => {
  if (e.key === "Enter")
    attempt(e.target.value, document.getElementById("gate-remember").checked);
});
document.getElementById("logout").addEventListener("click", () => {
  localStorage.removeItem(LS_KEY); sessionStorage.removeItem(LS_KEY); location.reload();
});
(function autologin() {
  const saved = localStorage.getItem(LS_KEY) || sessionStorage.getItem(LS_KEY);
  if (saved) attempt(saved, !!localStorage.getItem(LS_KEY));
  else document.getElementById("gate-input").focus();
})();

/* ---------- 引导 ---------- */
async function bootstrap() {
  try { OVERVIEW = await (await fetch("data.json")).json(); }
  catch (e) { OVERVIEW = null; }
  buildTabs();
  if (OVERVIEW) renderOverview(OVERVIEW);
  initManuscriptControls();
  renderManuscript();
  renderFigures(CORE);
  renderTables(CORE);
  initTableControls();
  showTab("overview");
}

/* ---------- 标签切换 ---------- */
const TABS = [["overview", "概览"], ["manuscript", "稿件全文"], ["figures", "图表"], ["tables", "表格"]];
function buildTabs() {
  document.getElementById("tabnav").innerHTML = TABS.map(([id, l]) =>
    `<button class="tab" data-tab="${id}">${l}</button>`).join("");
  document.querySelectorAll("#tabnav .tab").forEach(b =>
    b.addEventListener("click", () => showTab(b.dataset.tab)));
}
function showTab(id) {
  TABS.forEach(([t]) => {
    document.getElementById("panel-" + t).classList.toggle("hidden", t !== id);
  });
  document.querySelectorAll("#tabnav .tab").forEach(b =>
    b.classList.toggle("active", b.dataset.tab === id));
  window.scrollTo(0, 0);
  updateProgress();
}

/* ---------- 主题 ---------- */
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  const btn = document.getElementById("theme-btn");
  if (btn) btn.textContent = t === "dark" ? "☾" : "☀";
  localStorage.setItem("args_theme", t);
}
(function initTheme() {
  let t = localStorage.getItem("args_theme");
  if (!t) t = (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
  applyTheme(t);
  const btn = document.getElementById("theme-btn");
  if (btn) btn.addEventListener("click", () =>
    applyTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark"));
})();

/* ---------- 回到顶部 + 阅读进度 ---------- */
function totopToggle() {
  const b = document.getElementById("totop");
  if (b) b.classList.toggle("hidden", window.scrollY < 400);
}
function updateProgress() {
  const panel = document.getElementById("panel-manuscript");
  const bar = document.getElementById("ms-progbar");
  if (!panel || !bar || panel.classList.contains("hidden")) return;
  const art = document.getElementById("manuscript");
  const top = art.offsetTop;
  const h = Math.max(1, art.offsetHeight - window.innerHeight + 200);
  const p = Math.max(0, Math.min(1, (window.scrollY - top + 200) / h));
  bar.style.width = (p * 100).toFixed(1) + "%";
}
/* 滚动时收拢顶栏 — 手机上把大量纵向空间还给正文 (含迟滞防抖动) */
function headerCollapse() {
  const h = document.querySelector(".hero");
  if (!h) return;
  const y = window.scrollY;
  if (!h.classList.contains("collapsed") && y > 34) h.classList.add("collapsed");
  else if (h.classList.contains("collapsed") && y < 8) h.classList.remove("collapsed");
}
window.addEventListener("scroll", () => {
  totopToggle(); updateProgress(); headerCollapse();
}, { passive: true });
document.getElementById("totop").addEventListener("click", () =>
  window.scrollTo({ top: 0, behavior: "smooth" }));

/* ---------- 概览 ---------- */
function statusBadge(status) {
  const m = { pass: ["b-ok", "PASS"], warn: ["b-warn", "WARN"], blocked: ["b-block", "阻塞"] };
  const [cls, label] = m[status] || ["b-idle", status || "—"];
  return `<span class="badge ${cls}">${label}</span>`;
}
function renderCite(d) {
  const c = d.cite;
  const box = document.getElementById("cite");
  if (!c || !box) { if (box) box.remove(); return; }
  const apa = `${c.authors_display} (${c.year}). ${c.title}. ${c.journal}. [${c.note}]`;
  const bib =
`@article{zhou${c.year}desert,
  title   = {${c.title}},
  author  = {${c.authors}},
  journal = {${c.journal}},
  year    = {${c.year}},
  note    = {${c.note}}
}`;
  const ris =
`TY  - JOUR
TI  - ${c.title}
AU  - Zhou, Youkang
AU  - Li, Wenjing
JO  - ${c.journal}
PY  - ${c.year}
N1  - ${c.note}
ER  -`;
  box.innerHTML = `
    <div class="card cite-card">
      <p class="cite-apa">${esc(apa)}</p>
      <p class="cite-aff mono">${esc(c.affiliation)}</p>
      <pre class="cite-bib" id="cite-bib">${esc(bib)}</pre>
      <div class="cite-btns">
        <button class="iconbtn" data-cf="apa">复制引用</button>
        <button class="iconbtn" data-cf="bib">复制 BibTeX</button>
        <button class="iconbtn" data-cf="ris">复制 RIS</button>
        <button class="iconbtn" data-cf="risdl">下载 .ris</button>
        <button class="iconbtn" data-cf="bibdl">下载 .bib</button>
      </div>
    </div>`;
  box.querySelectorAll("[data-cf]").forEach(b => b.addEventListener("click", () => {
    const k = b.dataset.cf;
    if (k === "apa") copyText(apa);
    else if (k === "bib") copyText(bib);
    else if (k === "ris") copyText(ris);
    else if (k === "risdl") { downloadBlob(ris, "ARGs_desert_resistome.ris"); toast("已下载 .ris"); }
    else if (k === "bibdl") { downloadBlob(bib, "ARGs_desert_resistome.bib"); toast("已下载 .bib"); }
  }));
}
function renderOverview(d) {
  const P = d.project;
  document.getElementById("p-title").textContent = P.title;
  document.getElementById("p-track").textContent = P.primary_track + " (主) + " + P.secondary_track;
  document.getElementById("p-phase").textContent = P.phase;
  document.getElementById("foot-gen").textContent =
    `数据生成于 ${d.generated_at} · commit ${d.git_head.hash} · 分支 ${d.branch}`;
  document.getElementById("foot-pr").href = d.pr_url;
  document.getElementById("foot-repo").href = "https://github.com/" + d.repo;

  const validators = d.validators;
  const passN = validators.filter(v => v.status === "pass").length;
  const blockN = d.blanks.filter(b => b.blocking).length;
  const readiness = 92;
  document.getElementById("ring").style.setProperty("--p", readiness + "%");
  document.getElementById("ring-pct").textContent = readiness + "%";

  const kpis = [
    { n: passN + "/" + validators.length, l: "验证器 PASS", cls: "ok" },
    { n: blockN, l: "阻塞人类门 (F3/F4)", cls: blockN ? "block" : "ok" },
    { n: d.modules.length, l: "项目板块", cls: "" },
    { n: d.modules.reduce((a, m) => a + m.files, 0), l: "受管文件", cls: "" },
  ];
  document.getElementById("kpis").innerHTML = kpis.map(k =>
    `<div class="kpi ${k.cls}"><div class="n">${esc(k.n)}</div><div class="l">${esc(k.l)}</div></div>`).join("");

  renderCite(d);

  const S = d.submission;
  const subCard = (title, o) => `
    <div class="card">
      <h3>${esc(title)} ${o.status.includes("ready") ? statusBadge("pass") : statusBadge("")}</h3>
      <p><b>版本</b> ${esc(o.version || "—")}</p>
      ${o.contents ? `<p><b>内容</b> ${esc(o.contents)}</p>` : ""}
      ${o.sha256 ? `<p><b>SHA256</b></p><p class="mono">${esc(o.sha256)}</p>` : ""}
      <p class="mono">${esc(o.package)}</p>
      ${o.download ? `<p><a href="${esc(o.download)}" target="_blank" rel="noopener">下载 ↓</a></p>` : ""}
    </div>`;
  document.getElementById("submission").innerHTML =
    subCard("Environmental Research 投稿包", S.er) + subCard("Scientific Data 姐妹稿", S.scidata);

  document.getElementById("blanks").innerHTML = d.blanks.map(b => {
    const done = /verified|applied|ready|recommended|not_due/.test(b.status);
    const cls = b.blocking ? "blocking" : (done ? "done" : "");
    return `<div class="blank ${cls}">
      <div class="top"><span class="fid">${esc(b.id.toUpperCase())} · ${esc(b.key.replace(/^F\d_/, ""))}</span>
        ${b.blocking ? statusBadge("blocked") : statusBadge("pass")}</div>
      <div class="owner">责任人: ${esc(b.owner)}</div>
      <div class="st">${esc(b.status)}</div>
      <div class="na">${esc(b.next_action)}</div>
    </div>`;
  }).join("");

  document.getElementById("validators").innerHTML = validators.map(v =>
    `<div class="card">
      <h3>${esc(v.name)} ${statusBadge(v.status)}</h3>
      <p>${esc(v.detail)}</p>
      ${v.evidence ? `<p><a href="${esc(v.evidence)}" target="_blank" rel="noopener">查看脚本 →</a></p>` : ""}
    </div>`).join("");

  document.getElementById("repro").innerHTML = d.reproducibility.map(r => {
    const st = r.blocking_submission ? "blocked" : (r.blocking_full_repro ? "warn" : "pass");
    return `<div class="card">
      <h3>${esc(r.key)} ${statusBadge(st)}</h3>
      <p class="mono">${esc(r.status)}</p>
      <p>投稿阻塞: <b>${r.blocking_submission ? "是" : "否"}</b> · 完全复现阻塞: <b>${r.blocking_full_repro ? "是" : "否"}</b></p>
      ${r.next_action ? `<p>${esc(r.next_action)}</p>` : ""}
    </div>`;
  }).join("");

  document.getElementById("rounds").innerHTML = d.rounds.map(r =>
    `<div class="tl">
      <h4>${esc(r.label)}</h4>
      <span class="when">${esc(r.verified_at)}</span>
      <p>${esc(r.purpose)}</p>
      ${r.bottom_line ? `<p class="bl">▸ ${esc(r.bottom_line)}</p>` : ""}
    </div>`).join("");

  document.getElementById("modules").innerHTML = d.modules.map(m =>
    `<a class="mod" href="${esc(m.link)}" target="_blank" rel="noopener">
      <div class="mh"><span class="mt">${esc(m.title)}</span><span class="fc">${m.files} 文件</span></div>
      <div class="md">${esc(m.desc)}</div>
      <div class="dir">${esc(m.dir)}/</div>
    </a>`).join("");

  renderMinpack(d);

  document.getElementById("downloads").innerHTML = d.downloads.map(x =>
    `<div class="dl"><div><div class="nm">${esc(x.name)}</div><div class="pt">${esc(x.path)}</div></div>
      <a href="${esc(x.url)}" target="_blank" rel="noopener">打开 →</a></div>`).join("");
}

/* ---------- 成果最小包 (口令加密 · 客户端解密后一键下载) ---------- */
function fmtSize(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " MB";
  if (bytes >= 1024) return (bytes / 1024).toFixed(0) + " KB";
  return bytes + " B";
}
async function downloadMinpack(mp) {
  const btn = document.getElementById("mp-dl");
  if (!btn) return;
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = "下载中…";
  try {
    if (!PASS) throw new Error("nopass");
    const bytes = await decryptEncFile(mp.enc_file || "minpack.enc", PASS, (frac) => {
      btn.textContent = "下载中… " + Math.round(frac * 100) + "%";
    });
    downloadBlob(new Blob([bytes], { type: "application/zip" }),
      mp.filename || "ARGs_成果最小包.zip", "application/zip");
    toast("已解密并开始下载");
  } catch (e) {
    if (e && e.kind === "network") toast("加载失败(网络/CDN 未就绪), 请稍候重试");
    else if (e && e.message === "nopass") toast("请先用访问口令进入后再下载");
    else toast("解密失败, 请重新用正确口令进入");
  } finally {
    btn.disabled = false; btn.textContent = label;
  }
}
function renderMinpack(d) {
  const box = document.getElementById("minpack");
  const sec = document.getElementById("sec-minpack");
  const mp = d.minpack;
  if (!box) return;
  if (!mp) { box.remove(); if (sec) sec.remove(); return; }
  const rows = (mp.items || []).map(it =>
    `<li><span class="mp-nm">${esc(it.name)}</span>
       <span class="mp-desc">${esc(it.desc || "")}</span>
       <span class="mp-sz">${fmtSize(it.bytes)}</span></li>`).join("");
  box.innerHTML = `
    <div class="card mp-card">
      <p class="mp-lead">快速审阅用最小成果集：核心稿 v54 + 关键图 + 关键表 + 核心数据。
        文件以访问口令 AES-256-GCM 加密，<b>浏览器内本地解密后</b>再下载为 ZIP —— 网址即便公开、无口令者也拿不到全文。</p>
      <ul class="mp-list">${rows}</ul>
      <div class="mp-foot">
        <button id="mp-dl" class="mp-btn">⇩ 一键下载（口令解密）· ${esc(mp.filename || "ZIP")} · ${fmtSize(mp.zip_bytes || 0)}</button>
      </div>
      ${mp.sha256 ? `<p class="mp-sha mono">解密后 ZIP SHA256: ${esc(mp.sha256)}</p>` : ""}
    </div>`;
  const btn = document.getElementById("mp-dl");
  if (btn) btn.addEventListener("click", () => downloadMinpack(mp));
}

/* ================= 稿件全文 (中英对照) ================= */
let MS_LANG = localStorage.getItem("args_ms_lang") || "both";
let MS_FS = parseInt(localStorage.getItem("args_ms_fs") || "2", 10);
let MS_SERIF = localStorage.getItem("args_ms_serif") === "1";
let MS_OBS = null;
let MS_MATCHES = [];
let MS_MATCH_I = -1;

function blocksPlain(blocks) {
  return (blocks || []).map(b =>
    b.t === "table" ? (b.rows || []).map(r => r.join("\t")).join("\n") : b.text
  ).join("\n\n");
}
function pHTML(text) {
  return `<p class="ms-p"><span class="ms-txt">${esc(text)}</span>` +
    `<button class="cp" data-copy="${esc(text)}" title="复制本段">⧉</button></p>`;
}
function blocksHTML(blocks) {
  return (blocks || []).map(b =>
    b.t === "table" ? tableHTML(b.rows[0], b.rows.slice(1)) : pHTML(b.text)).join("");
}
function headHTML(tag, cls, id, text) {
  return `<${tag} id="${id}" class="${cls}"><span class="hd-tx">${esc(text)}</span>` +
    `<button class="anchor" data-anchor="${id}" title="复制本节链接">¶</button></${tag}>`;
}

function applyReadingPrefs() {
  const art = document.getElementById("manuscript");
  art.className = "doc fs-" + MS_FS + (MS_SERIF ? " serif" : "");
  const sb = document.getElementById("ms-serif");
  if (sb) sb.classList.toggle("active", MS_SERIF);
}

function initManuscriptControls() {
  // 语言切换
  document.querySelectorAll("#ms-lang .seg-btn").forEach(b =>
    b.addEventListener("click", () => {
      MS_LANG = b.dataset.lang;
      localStorage.setItem("args_ms_lang", MS_LANG);
      renderManuscript();
    }));
  // 字号
  document.getElementById("ms-finc").addEventListener("click", () => {
    MS_FS = Math.min(4, MS_FS + 1); localStorage.setItem("args_ms_fs", MS_FS); applyReadingPrefs();
  });
  document.getElementById("ms-fdec").addEventListener("click", () => {
    MS_FS = Math.max(0, MS_FS - 1); localStorage.setItem("args_ms_fs", MS_FS); applyReadingPrefs();
  });
  // 衬线
  document.getElementById("ms-serif").addEventListener("click", () => {
    MS_SERIF = !MS_SERIF; localStorage.setItem("args_ms_serif", MS_SERIF ? "1" : "0"); applyReadingPrefs();
  });
  // 打印
  document.getElementById("ms-print").addEventListener("click", () => window.print());
  // 全文复制(按当前语言)
  document.getElementById("ms-copyall").addEventListener("click", () => {
    if (MS_LANG === "zh") copyText(blocksPlain((CORE.manuscript_zh || {}).blocks));
    else if (MS_LANG === "en") copyText(blocksPlain((CORE.manuscript || {}).blocks));
    else copyText(bilingualPlain());
  });
  // 段落复制 / 节复制 / 锚点 (事件委托)
  document.getElementById("manuscript").addEventListener("click", e => {
    const cp = e.target.closest(".cp");
    if (cp) { copyText(cp.dataset.copy); return; }
    const an = e.target.closest(".anchor");
    if (an) {
      const url = location.href.split("#")[0] + "#" + an.dataset.anchor;
      copyText(url); return;
    }
    const sc = e.target.closest(".bi-copy");
    if (sc) {
      const s = CORE.bilingual.sections[+sc.dataset.sec];
      const lang = sc.dataset.lang;
      const title = lang === "zh" ? s.title_zh : s.title_en;
      copyText((title ? title + "\n\n" : "") + blocksPlain(lang === "zh" ? s.zh : s.en));
      return;
    }
  });
  // 查找
  document.getElementById("ms-search").addEventListener("input", applySearch);
  document.getElementById("ms-search").addEventListener("keydown", e => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (MS_MATCHES.length) gotoMatch(MS_MATCH_I + (e.shiftKey ? -1 : 1));
    }
  });
  applyReadingPrefs();
}

/* 清除上次高亮: 移除段落底纹, 并把已包 <mark> 的文本还原 */
function clearSearchMarks() {
  document.querySelectorAll("#manuscript .hl").forEach(el => el.classList.remove("hl"));
  document.querySelectorAll("#manuscript .ms-txt, #manuscript .hd-tx").forEach(sp => {
    if (sp.dataset.orig != null && sp.querySelector(".ms-mk")) sp.textContent = sp.dataset.orig;
  });
}
/* 在纯文本 span 内把匹配子串包成 <mark>, 返回命中次数 */
function markInSpan(sp, q) {
  const orig = sp.dataset.orig != null ? sp.dataset.orig : (sp.dataset.orig = sp.textContent);
  const low = orig.toLowerCase();
  let i = 0, idx, out = "", n = 0;
  while ((idx = low.indexOf(q, i)) !== -1) {
    out += esc(orig.slice(i, idx)) + '<mark class="ms-mk">' + esc(orig.slice(idx, idx + q.length)) + "</mark>";
    i = idx + q.length; n++;
  }
  if (n) { out += esc(orig.slice(i)); sp.innerHTML = out; }
  return n;
}
function gotoMatch(i) {
  if (!MS_MATCHES.length) return;
  if (MS_MATCH_I >= 0 && MS_MATCHES[MS_MATCH_I]) MS_MATCHES[MS_MATCH_I].classList.remove("cur");
  MS_MATCH_I = (i % MS_MATCHES.length + MS_MATCHES.length) % MS_MATCHES.length;
  const el = MS_MATCHES[MS_MATCH_I];
  el.classList.add("cur");
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  const cnt = document.getElementById("ms-count");
  if (cnt) cnt.textContent = `${MS_MATCH_I + 1}/${MS_MATCHES.length}`;
}
function applySearch() {
  const q = document.getElementById("ms-search").value.trim().toLowerCase();
  const cnt = document.getElementById("ms-count");
  clearSearchMarks();
  MS_MATCHES = []; MS_MATCH_I = -1;
  if (!q) { if (cnt) cnt.textContent = ""; return; }
  document.querySelectorAll("#manuscript .ms-txt, #manuscript .hd-tx").forEach(sp => {
    if (markInSpan(sp, q)) { const blk = sp.closest(".ms-p, .ms-h1, .ms-h2"); if (blk) blk.classList.add("hl"); }
  });
  // 中英对照的节标题只做底纹(其内含锚点按钮, 不改其结构)
  document.querySelectorAll("#manuscript .bi-h-en, #manuscript .bi-h-zh").forEach(el => {
    if (el.textContent.toLowerCase().includes(q)) el.classList.add("hl");
  });
  MS_MATCHES = Array.from(document.querySelectorAll("#manuscript .ms-mk"));
  if (cnt) cnt.textContent = MS_MATCHES.length ? `${MS_MATCHES.length} 处` : "无匹配";
  if (MS_MATCHES.length) gotoMatch(0);
}

function bilingualPlain() {
  const bi = CORE.bilingual;
  if (!bi) return "";
  const out = [];
  if (bi.title_en) out.push(bi.title_en);
  if (bi.title_zh) out.push(bi.title_zh);
  out.push("");
  bi.sections.forEach(s => {
    if (s.title_en || s.title_zh) out.push([s.title_en, s.title_zh].filter(Boolean).join("  |  "));
    if (s.en.length) out.push(blocksPlain(s.en));
    if (s.zh.length) out.push(blocksPlain(s.zh));
    out.push("");
  });
  return out.join("\n\n");
}

function renderManuscript() {
  const core = CORE;
  if (!core) return;
  document.querySelectorAll("#ms-lang .seg-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.lang === MS_LANG));

  const art = document.getElementById("manuscript");
  const toc = document.getElementById("ms-toc");
  const meta = document.getElementById("ms-meta");
  const tocItems = [];
  let html = "";

  if (MS_LANG === "both") {
    const bi = core.bilingual;
    if (!bi) { art.innerHTML = "<p class='ms-p'>无对照数据</p>"; return; }
    html += `<div class="bi-title"><div class="bi-t-en">${esc(bi.title_en)}</div>` +
      `<div class="bi-t-zh">${esc(bi.title_zh)}</div></div>`;
    bi.sections.forEach((s, i) => {
      const id = "ms-sec-" + i;
      if (s.title_en || s.title_zh)
        tocItems.push({ id, lv: s.lv, text: s.title_en || s.title_zh });
      const enBody = s.en.length ? blocksHTML(s.en)
        : `<p class="ms-note">（英文 ${erVer()} 无此节；仅中文工作版补充）</p>`;
      const zhBody = s.zh.length ? blocksHTML(s.zh)
        : `<p class="ms-note">（${esc(bi.zh_version || "中文工作版")} 暂无对应章节）</p>`;
      html += `<section class="bi-sec lv${s.lv}" id="${id}">
        <div class="bi-head">
          <div class="bi-h-en">${s.title_en ? esc(s.title_en) : "&nbsp;"}
            <button class="anchor" data-anchor="${id}" title="复制本节链接">¶</button></div>
          <div class="bi-h-zh">${s.title_zh ? esc(s.title_zh) : "&nbsp;"}</div>
        </div>
        <div class="bi-body">
          <div class="bi-col bi-en"><div class="bi-tools">${s.en.length ? `<button class="bi-copy" data-sec="${i}" data-lang="en">⧉ 复制英文</button>` : ""}</div>${enBody}</div>
          <div class="bi-col bi-zh"><div class="bi-tools">${s.zh.length ? `<button class="bi-copy" data-sec="${i}" data-lang="zh">⧉ 复制中文</button>` : ""}</div>${zhBody}</div>
        </div>
      </section>`;
    });
    meta.textContent = `中英对照 · ${bi.sections.length} 节 · 英文 ${erVer()} ↔ ${bi.zh_version}`;
  } else {
    const src = MS_LANG === "zh" ? core.manuscript_zh : core.manuscript;
    if (!src) { art.innerHTML = "<p class='ms-p'>无数据</p>"; return; }
    src.blocks.forEach((b, i) => {
      if (b.t === "title") { html += `<h1 class="ms-title">${esc(b.text)}</h1>`; return; }
      if (b.t === "h1") {
        const id = "ms-h-" + i; tocItems.push({ id, lv: 1, text: b.text });
        html += headHTML("h2", "ms-h1", id, b.text); return;
      }
      if (b.t === "h2") {
        const id = "ms-h-" + i; tocItems.push({ id, lv: 2, text: b.text });
        html += headHTML("h3", "ms-h2", id, b.text); return;
      }
      if (b.t === "table") { html += tableHTML(b.rows[0], b.rows.slice(1)); return; }
      html += pHTML(b.text);
    });
    meta.textContent = MS_LANG === "zh"
      ? `${core.manuscript_zh.blocks.length} 块 · ${(core.bilingual || {}).zh_version || "中文工作版"}`
      : `英文 ${erVer()} · ${core.manuscript.blocks.length} 块 · 生成于 ${core.generated_at}`;
  }

  const _cn = verNum(core.version), _on = verNum(overviewErVer());
  if (_on != null && _cn !== _on) {
    const cv = _cn != null ? ("v" + _cn) : "版本未标注";
    html = `<p class="ms-note ms-stale">⚠ 页内稿件为已加密快照(${esc(cv)})；权威稿已 v${_on}。` +
      `如需同步页内密文，请用 DASH_PASSCODE 重跑 <code>docs/_build_site.py</code> 重建 content.enc。</p>` + html;
  }

  art.innerHTML = html;
  applyReadingPrefs();
  { const sb = document.getElementById("ms-search"); if (sb && sb.value.trim()) applySearch(); }

  toc.innerHTML = tocItems.map(h =>
    `<a class="toc-${h.lv}" href="#${h.id}" data-id="${h.id}">${esc(h.text)}</a>`).join("");
  toc.querySelectorAll("a").forEach(a =>
    a.addEventListener("click", e => {
      e.preventDefault();
      const el = document.getElementById(a.dataset.id);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
    }));

  // 目录随滚动高亮
  if (MS_OBS) MS_OBS.disconnect();
  const linkMap = {};
  toc.querySelectorAll("a").forEach(a => linkMap[a.dataset.id] = a);
  MS_OBS = new IntersectionObserver(entries => {
    entries.forEach(en => {
      const a = linkMap[en.target.id];
      if (!a) return;
      if (en.isIntersecting) {
        toc.querySelectorAll("a").forEach(x => x.classList.remove("active"));
        a.classList.add("active");
      }
    });
  }, { rootMargin: "-120px 0px -70% 0px" });
  tocItems.forEach(h => { const el = document.getElementById(h.id); if (el) MS_OBS.observe(el); });

  applySearch();
  updateProgress();
}

function tableHTML(headers, rows) {
  return `<div class="tbl-wrap"><table class="tbl">
    <thead><tr>${headers.map(h => `<th>${esc(h)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody>
  </table></div>`;
}

/* ---------- 图表 ---------- */
function figFilename(f) {
  const { ext } = dataUriToBlob(f.img);
  return String(f.id).replace(/[^\w.-]+/g, "_") + "." + ext;
}
function downloadFig(f) {
  const { blob } = dataUriToBlob(f.img);
  downloadBlob(blob, figFilename(f));
  toast("已下载 " + f.id);
}
function renderFigures(core) {
  const figs = core.figures || [];
  const cnt = document.getElementById("fig-count");
  if (cnt) cnt.textContent = figs.length;
  document.getElementById("figures").innerHTML = figs.map((f, i) =>
    `<figure class="fig-card" data-i="${i}">
      <button class="fig-dl" data-dl="${i}" title="下载原图">↓</button>
      <div class="fig-imgwrap"><img loading="lazy" src="${f.img}" alt="${esc(f.id)}" /></div>
      <figcaption><b>${esc(f.id)}</b> — ${esc(f.title)}
        ${f.caption ? `<span class="fig-cap">${esc(f.caption)}</span>` : ""}</figcaption>
    </figure>`).join("");
  document.querySelectorAll(".fig-card").forEach(c =>
    c.addEventListener("click", e => {
      if (e.target.closest(".fig-dl")) { downloadFig(figs[+e.target.closest(".fig-dl").dataset.dl]); return; }
      const f = figs[+c.dataset.i];
      openLightbox(f, `${f.id} — ${f.title}${f.caption ? "  ·  " + f.caption : ""}`);
    }));
}
let LB_FIG = null, LB_CAP = "";
function openLightbox(f, cap) {
  LB_FIG = f; LB_CAP = cap;
  document.getElementById("lb-img").src = f.img;
  document.getElementById("lb-cap").textContent = cap;
  document.getElementById("lightbox").classList.remove("hidden");
}
document.getElementById("lb-close").addEventListener("click", () =>
  document.getElementById("lightbox").classList.add("hidden"));
document.getElementById("lb-dl").addEventListener("click", () => { if (LB_FIG) downloadFig(LB_FIG); });
document.getElementById("lightbox").addEventListener("click", e => {
  if (e.target.id === "lightbox") e.currentTarget.classList.add("hidden");
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape") document.getElementById("lightbox").classList.add("hidden");
});

/* ---------- 表格 ---------- */
let TBL_IDX = 0;
function renderTables(core) {
  const tabs = core.tables || [];
  document.getElementById("tbl-picker").innerHTML = tabs.map((t, i) =>
    `<button class="tbl-btn" data-i="${i}">${esc(t.title)}</button>`).join("");
  document.querySelectorAll(".tbl-btn").forEach(b =>
    b.addEventListener("click", () => { TBL_IDX = +b.dataset.i; drawTable(core); }));
  if (tabs.length) drawTable(core);
}
function drawTable(core) {
  const t = core.tables[TBL_IDX];
  document.querySelectorAll(".tbl-btn").forEach((b, i) =>
    b.classList.toggle("active", i === TBL_IDX));
  const note = t.truncated
    ? `<p class="sec-note">共 ${t.n_rows} 行，页内显示前 ${t.rows.length} 行（下载 CSV 亦为该范围）。</p>` : "";
  document.getElementById("tables").innerHTML =
    `<h3 class="tbl-title">${esc(t.title)} <span class="mono">${esc(t.file)}</span></h3>${note}` +
    tableHTML(t.headers, t.rows);
  const flt = document.getElementById("tbl-filter");
  if (flt) flt.value = "";
}
function csvQuote(v) {
  v = String(v == null ? "" : v);
  return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}
function initTableControls() {
  const flt = document.getElementById("tbl-filter");
  flt.addEventListener("input", () => {
    const q = flt.value.trim().toLowerCase();
    document.querySelectorAll("#tables tbody tr").forEach(tr => {
      tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? "" : "none";
    });
  });
  document.getElementById("tbl-copy").addEventListener("click", () => {
    const t = CORE.tables[TBL_IDX];
    copyText([t.headers.join("\t"), ...t.rows.map(r => r.join("\t"))].join("\n"));
  });
  document.getElementById("tbl-csv").addEventListener("click", () => {
    const t = CORE.tables[TBL_IDX];
    const csv = [t.headers.map(csvQuote).join(","), ...t.rows.map(r => r.map(csvQuote).join(","))].join("\r\n");
    const fn = String(t.file || t.title).replace(/[^\w.-]+/g, "_").replace(/\.csv$/i, "") + ".csv";
    downloadBlob("\ufeff" + csv, fn, "text/csv;charset=utf-8");
    toast("已下载 " + fn);
  });
}
