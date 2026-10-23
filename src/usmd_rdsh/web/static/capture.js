// Capture tab: NNDP, NCP and SP frames as Wireshark shows them - a live packet
// list with display filters, the field tree of the selected frame, and its bytes.
//
// Self-contained so any page can host it:
//   UsmdCapture.mount(element, { token: () => "...", onUnauthorized: () => {},
//                                canWrite: () => true })
//   .activate() / .deactivate() when the tab is shown or hidden.
"use strict";
(function () {
const CSS = `
.cap { display: flex; flex-direction: column; gap: 10px; }
.cap-bar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.cap-filter { flex: 1 1 320px; display: flex; min-width: 0; }
.cap-filter input { flex: 1; min-width: 0; height: 36px; padding: 0 12px; font: 13px var(--mono);
  border: 1px solid var(--line); background: var(--panel); color: var(--text); border-radius: 8px 0 0 8px; }
.cap-filter input:focus { outline: none; border-color: var(--accent); }
.cap-filter button { border-radius: 0 8px 8px 0 !important; margin-left: -1px; }
.cap-filter input.valid { background: var(--ok-soft, #e7f8f0); border-color: var(--ok); }
.cap-filter input.invalid { background: var(--bad-soft, #fdeeee); border-color: var(--bad); }
.cap-chips { display: flex; gap: 4px; flex-wrap: wrap; }
.cap-chips button { font: inherit; font-size: 12px; padding: 3px 9px; border-radius: 99px;
  border: 1px solid var(--line); background: var(--panel); color: var(--text); cursor: pointer; }
.cap-chips button.on { border-color: var(--accent); color: var(--accent); font-weight: 600; }
.cap-live { display: inline-flex; align-items: center; gap: 6px; }
.cap-live i { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); }
.cap-live.on i { background: var(--ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--ok) 25%, transparent);
  animation: cap-pulse 1.6s infinite; }
@keyframes cap-pulse { 50% { box-shadow: 0 0 0 6px transparent; } }
.cap-status { color: var(--muted); font-size: 12.5px; margin-left: auto; white-space: nowrap; }
.cap-error { color: var(--bad); font-family: var(--mono); font-size: 12.5px; min-height: 1.2em; }
.cap-list { height: 44vh; min-height: 220px; overflow: auto; background: var(--panel);
  border: 1px solid var(--line); border-radius: 10px; outline: none; }
.cap-list table { font-family: var(--mono); font-size: 12px; }
.cap-list th { position: sticky; top: 0; background: var(--panel); z-index: 1; }
.cap-list td, .cap-list th { padding: 3px 8px; }
.cap-list td.info { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 0; width: 100%; }
.cap-list tr.p { cursor: default; }
/* Wireshark-like colouring, from the page's theme tokens (light and dark). */
.cap-list tr.NNDP { --row: var(--info-soft, #e8f4fb); } .cap-list tr.NCP { --row: var(--ok-soft, #e7f8f0); }
.cap-list tr.SP { --row: var(--warn-soft, #fff5e6); }
.cap-list tr.p td { background: var(--row); border-bottom: 1px solid var(--line-2, var(--line)); }
.cap-list tr.bad td { background: var(--bad-soft, #fdeeee); color: var(--bad); }
.cap-list tr.retransmission td { background: var(--bg-sub, #eceef2); color: var(--bad); font-style: italic; }
.cap-list tr.ignored td { color: var(--muted); }
.cap-list tr.sel td { background: var(--accent) !important; color: var(--accent-on, #fff) !important; }
.cap-list .dir { width: 1em; text-align: center; }
.cap-panes { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 10px; }
.cap-pane { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  height: 36vh; min-height: 200px; overflow: auto; padding: 8px 10px; font-family: var(--mono); font-size: 12px; }
.cap-tree details > summary { list-style: none; cursor: pointer; }
.cap-tree details > summary::-webkit-details-marker { display: none; }
.cap-tree details > summary::before { content: "▸"; display: inline-block; width: 1.1em; color: var(--muted); }
.cap-tree details[open] > summary::before { content: "▾"; }
.cap-tree .leaf { padding-left: 1.1em; }
.cap-tree .kids { padding-left: 1.1em; }
.cap-tree .line { cursor: pointer; border-radius: 3px; padding: 0 3px; white-space: nowrap; }
.cap-tree .line:hover { background: var(--bg); }
.cap-tree .line.sel { background: var(--accent); color: var(--accent-on, #fff); }
.cap-tree .line .fn { color: var(--muted); font-size: 11px; margin-left: 8px; }
.cap-tree .line.sel .fn { color: inherit; opacity: .75; }
.cap-tree .malformed { color: var(--bad); }
.cap-tabs { display: flex; gap: 4px; margin-bottom: 6px; flex-wrap: wrap; }
.cap-tabs button { font: inherit; font-size: 11.5px; padding: 2px 8px; border: 1px solid var(--line);
  background: var(--panel); color: var(--muted); border-radius: 5px; cursor: pointer; }
.cap-tabs button.on { color: var(--text); border-color: var(--accent); }
.cap-hex { white-space: pre; line-height: 1.5; }
.cap-hex .off { color: var(--muted); } .cap-hex b { font-weight: normal; }
.cap-hex b.hl { background: var(--accent); color: var(--accent-on, #fff); border-radius: 2px; }
.cap-help { font-size: 12.5px; color: var(--muted); background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: 12px 14px; display: grid; gap: 8px; }
.cap-follow { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; color: var(--muted); }
.cap-tree .empty, .cap-hex .empty { padding: 24px 8px; }
.cap-help code { font-family: var(--mono); color: var(--text); }
.cap-fields { max-height: 220px; overflow: auto; columns: 3 260px; font-family: var(--mono); font-size: 12px; }
.cap-fields div { cursor: pointer; padding: 1px 4px; border-radius: 3px; break-inside: avoid; }
.cap-fields div:hover { background: var(--bg); }
.cap-fields span { color: var(--muted); font-family: system-ui, sans-serif; margin-left: 6px; }
@media (max-width: 760px) { .cap-panes { grid-template-columns: 1fr; } .cap-status { margin-left: 0; } }
`;

const QUICK = [
  ["nndp", "NNDP"], ["ncp", "NCP"], ["sp", "SP"],
  ["frame.dir == in", "reçus"], ["frame.dir == out", "émis"],
  ["frame.status != ok", "anomalies"], ["ncp.type == ERROR", "erreurs NCP"],
  ["sp && !sp.keepalive", "SP sans keepalive"],
];
const MAX_ROWS = 5000;

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;" }[c]));
}
function hexBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function mount(root, host) {
  if (!document.getElementById("usmd-capture-css")) {
    const style = document.createElement("style");
    style.id = "usmd-capture-css"; style.textContent = CSS;
    document.head.appendChild(style);
  }
  root.innerHTML = `
  <div class="cap">
    <div class="cap-bar">
      <button class="btn cap-live" data-r="live" title="Suspendre / reprendre la capture en direct"><i></i><span>En direct</span></button>
      <div class="cap-filter">
        <input data-r="filter" list="cap-field-names" spellcheck="false" autocomplete="off"
               placeholder="Filtre d'affichage… ex. ncp.command == GET_STATUS && ip.src == 127.0.0.2">
        <button class="btn primary" data-r="apply">Appliquer</button>
      </div>
      <button class="btn" data-r="reset" title="Effacer le filtre">✕</button>
      <button class="btn" data-r="help" title="Syntaxe et champs">?</button>
    </div>
    <datalist id="cap-field-names"></datalist>
    <div class="cap-bar">
      <div class="cap-chips" data-r="chips"></div>
      <label class="cap-follow"><input type="checkbox" data-r="follow" checked> Défilement auto</label>
      <button class="btn" data-r="clear">Vider le tampon</button>
      <span class="cap-status" data-r="status"></span>
    </div>
    <div class="cap-error" data-r="error"></div>
    <div class="cap-help hidden" data-r="helpbox">
      <p>Syntaxe des filtres d'affichage de Wireshark : <code>==</code> <code>!=</code> <code>&gt;</code>
      <code>&lt;</code> <code>&gt;=</code> <code>&lt;=</code> <code>contains</code> <code>matches</code> (ou <code>~</code>),
      <code>&amp;&amp;</code>/<code>and</code>, <code>||</code>/<code>or</code>, <code>!</code>/<code>not</code>, parenthèses.
      Un champ seul teste sa présence (<code>sp.keepalive</code>), une chaîne seule cherche partout
      (<code>"01JAB"</code>), un réseau se compare avec <code>ip.addr == 127.0.0.0/8</code>, et les valeurs
      nommées s'écrivent en clair (<code>nndp.state == ACTIVE</code>, <code>ncp.command == DECLARE_STATE</code>).
      Entrée applique le filtre. Cliquez un champ pour l'insérer :</p>
      <div class="cap-fields" data-r="fields"></div>
    </div>
    <div class="cap-list" data-r="list" tabindex="0">
      <table><thead><tr><th>No.</th><th class="dir"></th><th>Temps</th><th>Source</th><th>Destination</th>
        <th>Protocole</th><th>Long.</th><th>Info</th></tr></thead><tbody data-r="rows"></tbody></table>
    </div>
    <div class="cap-panes">
      <div class="cap-pane cap-tree" data-r="tree"><div class="empty">Sélectionnez une trame.</div></div>
      <div class="cap-pane"><div class="cap-tabs" data-r="tabs"></div><div class="cap-hex" data-r="hex"></div></div>
    </div>
  </div>`;
  const $ = (name) => root.querySelector(`[data-r="${name}"]`);
  const state = { active: false, live: true, filter: "", last: 0, started: 0, rows: 0,
                  selected: null, detail: null, buffer: 0, abort: null, generation: 0 };

  async function api(method, path, signal) {
    const res = await fetch(path, { method, signal,
      headers: { "Authorization": "Bearer " + host.token() } });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401) { host.onUnauthorized(); throw new Error("401"); }
    if (!res.ok) { const e = new Error(data.message || res.statusText); e.status = res.status; throw e; }
    return data;
  }

  // ---- packet list ----
  function rowHtml(p) {
    const cls = ["p", p.protocol, p.status === "ok" ? "" : (p.status === "dropped" || p.status === "malformed")
      ? "bad" : p.status].join(" ");
    const time = (p.time - state.started).toFixed(6);
    const note = p.status === "ok" ? "" : ` [${p.status}${p.reason ? ": " + p.reason : ""}]`;
    return `<tr class="${cls}" data-n="${p.number}"><td>${p.number}</td>
      <td class="dir" title="${p.direction === "in" ? "reçu" : "émis"}">${p.direction === "in" ? "↓" : "↑"}</td>
      <td title="${esc(new Date(p.time * 1000).toLocaleString())}">${time}</td>
      <td>${esc(p.source)}</td><td>${esc(p.destination)}</td><td>${esc(p.protocol)}</td>
      <td>${p.length}</td><td class="info" title="${esc(p.info + note)}">${esc(p.info + note)}</td></tr>`;
  }
  function append(packets) {
    if (!packets.length) return;
    const list = $("list");
    const atBottom = list.scrollTop + list.clientHeight >= list.scrollHeight - 30;
    $("rows").insertAdjacentHTML("beforeend", packets.map(rowHtml).join(""));
    state.rows += packets.length;
    while (state.rows > MAX_ROWS) { $("rows").firstElementChild.remove(); state.rows--; }
    if ($("follow").checked && (atBottom || state.rows === packets.length)) list.scrollTop = list.scrollHeight;
  }
  function status(r) {
    $("status").textContent = `${state.rows} affichée(s) · ${r.held}/${r.capacity} en tampon` +
      (r.enabled ? ` · ${r.protocols.join(", ") || "aucun protocole"}` : " · capture arrêtée (config system capture)");
  }

  // ---- live loop: long poll for frames numbered above the last one seen ----
  async function loop(generation) {
    while (state.active && generation === state.generation) {
      const ctrl = new AbortController(); state.abort = ctrl;
      const wait = state.live ? 15 : 0;
      const q = `/web/capture?since=${state.last}&wait=${state.last ? wait : 0}&limit=${MAX_ROWS}` +
        (state.filter ? "&filter=" + encodeURIComponent(state.filter) : "");
      try {
        const r = await api("GET", q, ctrl.signal);
        if (generation !== state.generation) return;
        if (!state.started) state.started = r.started;
        $("error").textContent = "";
        append(r.packets); state.last = r.last; status(r);
        if (!state.live) return;
      } catch (e) {
        if (e.name === "AbortError" || e.message === "401" || generation !== state.generation) return;
        $("error").textContent = e.message;
        if (e.status === 422) { $("filter").className = "invalid"; return; }
        await new Promise(res => setTimeout(res, 2000));
      }
    }
  }
  function restart(clearList) {
    state.generation++;
    if (state.abort) state.abort.abort();
    if (clearList) { $("rows").innerHTML = ""; state.rows = 0; state.last = 0; state.started = 0; }
    if (state.active) loop(state.generation);
  }

  // ---- filter ----
  function setFilter(text) {
    $("filter").value = text; state.filter = text.trim();
    $("filter").className = state.filter ? "valid" : "";
    root.querySelectorAll(".cap-chips button").forEach(b => b.classList.toggle("on", b.dataset.f === state.filter));
    restart(true);
  }
  let checkTimer = null;
  $("filter").addEventListener("input", () => {
    clearTimeout(checkTimer);
    const text = $("filter").value.trim();
    if (!text) { $("filter").className = ""; $("error").textContent = ""; return; }
    checkTimer = setTimeout(async () => {   // validity as you type, like the green/red bar
      try {
        await api("GET", `/web/capture?since=${state.last}&limit=1&filter=${encodeURIComponent(text)}`);
        if ($("filter").value.trim() === text) { $("filter").className = "valid"; $("error").textContent = ""; }
      } catch (e) {
        if ($("filter").value.trim() === text && e.status === 422) {
          $("filter").className = "invalid"; $("error").textContent = e.message;
        }
      }
    }, 250);
  });
  $("filter").addEventListener("keydown", e => { if (e.key === "Enter") setFilter($("filter").value); });
  $("apply").onclick = () => setFilter($("filter").value);
  $("reset").onclick = () => setFilter("");
  $("chips").innerHTML = QUICK.map(([f, l]) => `<button data-f="${esc(f)}" title="${esc(f)}">${esc(l)}</button>`).join("");
  $("chips").querySelectorAll("button").forEach(b =>
    b.onclick = () => setFilter(b.classList.contains("on") ? "" : b.dataset.f));
  $("live").onclick = () => {
    state.live = !state.live;
    $("live").classList.toggle("on", state.live);
    $("live").querySelector("span").textContent = state.live ? "En direct" : "En pause";
    restart(false);
  };
  $("live").classList.add("on");
  $("clear").onclick = async () => {
    if (!window.confirm("Vider le tampon de capture du nœud ?")) return;
    try { await api("POST", "/web/capture/clear"); restart(true); showDetail(null); }
    catch (e) { if (e.message !== "401") $("error").textContent = e.message; }
  };
  $("help").onclick = async () => {
    $("helpbox").classList.toggle("hidden");
    if ($("fields").childElementCount) return;
    try {
      const r = await api("GET", "/web/capture/fields");
      $("fields").innerHTML = r.fields.map(f =>
        `<div data-f="${esc(f.name)}">${esc(f.name)}<span>${esc(f.label)}</span></div>`).join("");
      $("fields").querySelectorAll("div").forEach(d => d.onclick = () => {
        const input = $("filter");
        input.value = (input.value.trim() ? input.value.trimEnd() + " && " : "") + d.dataset.f + " ";
        input.focus(); input.dispatchEvent(new Event("input"));
      });
    } catch (e) { if (e.message !== "401") $("error").textContent = e.message; }
  };
  api("GET", "/web/capture/fields").then(r => {
    document.getElementById("cap-field-names").innerHTML =
      r.fields.map(f => `<option value="${esc(f.name)}">${esc(f.label)}</option>`).join("");
  }).catch(() => {});

  // ---- selection, tree and bytes ----
  async function select(tr) {
    if (!tr) return;
    root.querySelectorAll("tr.sel").forEach(r => r.classList.remove("sel"));
    tr.classList.add("sel");
    tr.scrollIntoView({ block: "nearest" });
    state.selected = Number(tr.dataset.n);
    try { showDetail(await api("GET", `/web/capture/${state.selected}`)); }
    catch (e) { if (e.message !== "401") $("tree").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }
  $("rows").addEventListener("click", e => select(e.target.closest("tr")));
  $("list").addEventListener("keydown", e => {
    const current = root.querySelector("tr.sel");
    const next = e.key === "ArrowDown" ? (current ? current.nextElementSibling : $("rows").firstElementChild)
      : e.key === "ArrowUp" ? current?.previousElementSibling : null;
    if (next) { e.preventDefault(); $("follow").checked = false; select(next); }
  });

  function treeHtml(items) {
    return items.map(item => {
      const text = item.v ? `${esc(item.l)}: ${esc(item.v)}` : esc(item.l);
      const span = item.n ? ` data-o="${item.o}" data-len="${item.n}" data-b="${item.b}"` : "";
      const cls = item.f === "malformed" ? " malformed" : "";
      const line = `<span class="line${cls}"${span}>${text}${item.f ? `<span class="fn">${esc(item.f)}</span>` : ""}</span>`;
      if (!item.c.length) return `<div class="leaf">${line}</div>`;
      const open = ["usmd", "frame", "udp"].includes(item.f) ? "" : " open";
      return `<details${open}><summary>${line}</summary><div class="kids">${treeHtml(item.c)}</div></details>`;
    }).join("");
  }
  function showDetail(d) {
    state.detail = d;
    if (!d) { $("tree").innerHTML = '<div class="empty">Sélectionnez une trame.</div>';
              $("tabs").innerHTML = ""; $("hex").innerHTML = ""; return; }
    $("tree").innerHTML = treeHtml(d.tree);
    const shown = d.buffers.map((b, i) => [b, i]).filter(([b]) => b.hex.length);
    state.buffer = shown.length ? shown[0][1] : 0;
    $("tabs").innerHTML = shown.map(([b, i]) =>
      `<button data-i="${i}">${esc(b.name)} (${b.hex.length / 2} o)</button>`).join("");
    $("tabs").querySelectorAll("button").forEach(btn => btn.onclick = () => showBytes(Number(btn.dataset.i)));
    showBytes(state.buffer);
  }
  function showBytes(index, from = -1, size = 0) {
    state.buffer = index;
    $("tabs").querySelectorAll("button").forEach(b => b.classList.toggle("on", Number(b.dataset.i) === index));
    const buffer = state.detail?.buffers[index];
    if (!buffer || !buffer.hex.length) { $("hex").innerHTML = '<span class="off">Aucun octet.</span>'; return; }
    const bytes = hexBytes(buffer.hex), lines = [];
    const hl = (i) => i >= from && i < from + size ? ' class="hl"' : "";
    for (let off = 0; off < bytes.length; off += 16) {
      let hex = "", ascii = "";
      for (let i = off; i < off + 16; i++) {
        if (i < bytes.length) {
          const b = bytes[i];
          hex += `<b${hl(i)}>${b.toString(16).padStart(2, "0")}</b>` + (i % 16 === 7 ? "  " : " ");
          ascii += `<b${hl(i)}>${b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : "."}</b>`;
        } else hex += "   " + (i % 16 === 7 ? " " : "");
      }
      lines.push(`<span class="off">${off.toString(16).padStart(4, "0")}</span>  ${hex} ${ascii}`);
    }
    $("hex").innerHTML = lines.join("\n");
    const first = $("hex").querySelector("b.hl");
    if (first) first.scrollIntoView({ block: "nearest" });
  }
  $("tree").addEventListener("click", e => {
    const line = e.target.closest(".line");
    if (!line) return;
    if (e.target.closest("summary")) e.preventDefault();  // select, do not fold
    root.querySelectorAll(".cap-tree .line.sel").forEach(l => l.classList.remove("sel"));
    line.classList.add("sel");
    if (line.dataset.len) showBytes(Number(line.dataset.b), Number(line.dataset.o), Number(line.dataset.len));
  });
  $("tree").addEventListener("dblclick", e => {
    const details = e.target.closest("details");
    if (details && e.target.closest("summary")) details.open = !details.open;
  });

  return {
    activate() { $("clear").classList.toggle("hidden", !host.canWrite());
                 if (!state.active) { state.active = true; restart(false); } },
    deactivate() { state.active = false; restart(false); },
  };
}

window.UsmdCapture = { mount };
})();
