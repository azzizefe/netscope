// netscope Desktop — Frontend
// Talks to the Rust backend over Tauri IPC (window.__TAURI__).

const PROTOCOL_COLORS = {
  TCP: '#4a9ef5', UDP: '#45d1c5', DNS: '#a78bfa', HTTP: '#34d399',
  TLS: '#6ee7b7', ICMP: '#fbbf24', ARP: '#9ca3af',
};
const protoColor = (p) => PROTOCOL_COLORS[p] || '#f87171';

const STATES = { IDLE: 'Idle', CAPTURING: 'Capturing' };

const state = {
  view: 'packets',
  packets: [],
  filteredPackets: [],
  selectedIndex: -1,
  filterText: '',
  status: STATES.IDLE,
  packetCount: 0,
  flows: new Map(),      // key -> flow aggregate
  blocked: new Set(),    // blocked IP strings
  elevated: false,
  stats: {
    totalPackets: 0, totalBytes: 0, perProtocol: {},
    topTalkersSent: [], topDomains: [],
  },
};

// ---- Tauri IPC ----
async function invoke(cmd, args = {}) {
  if (window.__TAURI__) return window.__TAURI__.core.invoke(cmd, args);
  console.warn(`[mock] invoke ${cmd}`, args);
  return null;
}
async function listen(event, handler) {
  if (window.__TAURI__) return window.__TAURI__.event.listen(event, handler);
  console.warn(`[mock] listen ${event}`);
}

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const els = {};

// ---- Helpers ----
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
}
function endpointLabel(addr, host, port) {
  if (!addr) return '?';
  const name = host || addr;
  const p = port != null ? `:${port}` : '';
  // bracket IPv6 when no host name
  const base = !host && addr.includes(':') ? `[${addr}]` : name;
  return `${base}${p}`;
}

// ---- Interfaces ----
async function loadInterfaces() {
  try {
    const ifaces = await invoke('list_interfaces');
    if (ifaces && ifaces.length) {
      els.interfaceSelect.innerHTML = ifaces
        .map((d) => `<option value="${d.name}">${d.description || d.name}</option>`)
        .join('');
      // Prefer an interface that has a description (physical adapters usually do).
      const best = ifaces.findIndex((d) => /wi-?fi|ethernet|wireless|realtek|intel/i.test(d.description || ''));
      if (best >= 0) els.interfaceSelect.selectedIndex = best;
    } else {
      els.interfaceSelect.innerHTML = '<option>No interfaces — is Npcap installed?</option>';
    }
  } catch {
    els.interfaceSelect.innerHTML = '<option>Error loading interfaces</option>';
  }
}

// ---- Capture control ----
async function startCapture() {
  const iface = els.interfaceSelect.value;
  const filter = els.filterInput.value || null;
  try {
    // reset session
    state.packets = []; state.flows.clear(); state.packetCount = 0;
    state.stats = { totalPackets: 0, totalBytes: 0, perProtocol: {}, topTalkersSent: [], topDomains: [] };
    await invoke('start_capture', { interface: iface, filter });
    setStatus(STATES.CAPTURING);
    els.startBtn.disabled = true;
    els.stopBtn.disabled = false;
    renderAll();
  } catch (e) {
    alert(`Could not start capture:\n${e}`);
  }
}
async function stopCapture() {
  try { await invoke('stop_capture'); } catch (e) { console.error(e); }
  setStatus(STATES.IDLE);
  els.startBtn.disabled = false;
  els.stopBtn.disabled = true;
}
function setStatus(s) {
  state.status = s;
  els.statusText.textContent = `● ${s}`;
  els.statusText.className = s === STATES.CAPTURING ? 'status-capturing' : 'status-idle';
}

// ---- Packet ingest ----
function onPacket(event) {
  const pkt = event.payload;
  state.packets.push(pkt);
  if (state.packets.length > 10000) state.packets.shift();
  state.packetCount++;
  els.packetCount.textContent = `${state.packetCount} packets`;

  updateStats(pkt);
  updateFlow(pkt);

  if (state.view === 'packets') renderPacketList();
  else if (state.view === 'connections') renderConnections();
  else if (state.view === 'dashboard') renderStats();
}

// ---- Flow aggregation (Connections view) ----
function transportOf(proto) {
  if (['TCP', 'HTTP', 'TLS'].includes(proto)) return 'tcp';
  if (['UDP', 'DNS'].includes(proto)) return 'udp';
  if (proto === 'ICMP') return 'icmp';
  if (proto === 'ARP') return 'arp';
  return 'other';
}
function protoRank(proto) {
  if (proto === 'HTTP') return 4;
  if (proto === 'TLS' || proto === 'DNS') return 3;
  return 1;
}
function updateFlow(pkt) {
  if (!pkt.src_addr || !pkt.dst_addr) return;
  const t = transportOf(pkt.protocol);
  const a = `${pkt.src_addr}:${pkt.src_port ?? ''}`;
  const b = `${pkt.dst_addr}:${pkt.dst_port ?? ''}`;
  const key = (a <= b ? `${a}|${b}` : `${b}|${a}`) + `|${t}`;

  let f = state.flows.get(key);
  if (!f) {
    f = {
      clientAddr: pkt.src_addr, clientPort: pkt.src_port,
      serverAddr: pkt.dst_addr, serverPort: pkt.dst_port,
      serverHost: pkt.dst_host || null,
      proto: pkt.protocol, rank: protoRank(pkt.protocol),
      packets: 0, bytes: 0,
    };
    state.flows.set(key, f);
  }
  f.packets++;
  f.bytes += pkt.length;
  if (protoRank(pkt.protocol) > f.rank) { f.proto = pkt.protocol; f.rank = protoRank(pkt.protocol); }
  // learn the server's hostname whenever it shows up
  if (pkt.src_addr === f.serverAddr && pkt.src_host) f.serverHost = pkt.src_host;
  if (pkt.dst_addr === f.serverAddr && pkt.dst_host) f.serverHost = pkt.dst_host;
}

function renderConnections() {
  const flows = [...state.flows.values()].sort((a, b) => b.bytes - a.bytes);
  els.connSummary.innerHTML = flows.length
    ? `${flows.length} connections · <b>${state.blocked.size}</b> blocked` +
      (state.elevated ? '' : ' · <span style="color:var(--warn)">run as Administrator to block</span>')
    : 'No connections yet — start a capture.';

  els.connList.innerHTML = flows.map((f) => {
    const isBlocked = state.blocked.has(f.serverAddr);
    const server = f.serverHost
      ? `<span class="conn-host">${f.serverHost}</span> <span class="conn-ip mono">${f.serverAddr}${f.serverPort != null ? ':' + f.serverPort : ''}</span>`
      : `<span class="conn-host mono">${endpointLabel(f.serverAddr, null, f.serverPort)}</span>`;
    const client = endpointLabel(f.clientAddr, null, f.clientPort);
    const btn = isBlocked
      ? `<button class="btn btn-small btn-unblock" data-unblock="${f.serverAddr}">Unblock</button>`
      : `<button class="btn btn-small btn-block" data-block="${f.serverAddr}" ${state.elevated ? '' : 'title="Needs Administrator"'}>⛔ Block</button>`;
    return `
      <div class="conn-row conn-row-grid${isBlocked ? ' blocked' : ''}">
        <span class="mono">${client}</span>
        <span class="conn-server">${server}</span>
        <span class="conn-proto" style="color:${protoColor(f.proto)}">${f.proto}</span>
        <span>${f.packets}</span>
        <span>${formatBytes(f.bytes)}</span>
        <span>${btn}</span>
      </div>`;
  }).join('');
}

async function doBlock(ip) {
  try {
    await invoke('block_ip', { ip });
    state.blocked.add(ip);
    renderConnections();
    renderStats();
  } catch (e) {
    alert(`Could not block ${ip}:\n${e}`);
  }
}
async function doUnblock(ip) {
  try {
    await invoke('unblock_ip', { ip });
    state.blocked.delete(ip);
    renderConnections();
    renderStats();
  } catch (e) {
    alert(`Could not unblock ${ip}:\n${e}`);
  }
}

// ---- Packets view ----
function matchesFilter(pkt, text) {
  const l = text.toLowerCase();
  return (
    pkt.summary.toLowerCase().includes(l) ||
    pkt.protocol.toLowerCase().includes(l) ||
    (pkt.src_addr && pkt.src_addr.includes(l)) ||
    (pkt.dst_addr && pkt.dst_addr.includes(l)) ||
    (pkt.src_host && pkt.src_host.toLowerCase().includes(l)) ||
    (pkt.dst_host && pkt.dst_host.toLowerCase().includes(l))
  );
}
function renderPacketList() {
  const packets = state.filterText
    ? state.packets.filter((p) => matchesFilter(p, state.filterText))
    : state.packets;
  state.filteredPackets = packets;

  // Wireshark-style display-filter feedback (green = hits, red = no match)
  els.filterInput.classList.toggle('filter-hit', !!state.filterText && packets.length > 0);
  els.filterInput.classList.toggle('filter-miss', !!state.filterText && packets.length === 0);

  if (!packets.length) {
    els.packetList.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted)">No packets yet</div>';
    return;
  }
  const start = Math.max(0, packets.length - 500);
  els.packetList.innerHTML = packets.slice(start).map((pkt, i) => {
    const idx = start + i;
    const c = protoColor(pkt.protocol);
    const sel = idx === state.selectedIndex ? ' selected' : '';
    const src = esc(endpointLabel(pkt.src_addr, pkt.src_host, pkt.src_port));
    const dst = esc(endpointLabel(pkt.dst_addr, pkt.dst_host, pkt.dst_port));
    return `
      <div class="packet-row proto-${esc(pkt.protocol)}${sel}" data-index="${idx}">
        <span class="col-num">${idx + 1}</span>
        <span class="col-time">${esc(pkt.timestamp)}</span>
        <span class="col-src">${src}</span>
        <span class="col-dir" style="color:${c}">→</span>
        <span class="col-dst">${dst}</span>
        <span class="col-proto" style="color:${c}">${esc(pkt.protocol)}</span>
        <span class="col-len">${pkt.length}B</span>
        <span class="col-info">${esc(pkt.summary)}</span>
      </div>`;
  }).join('');
}

// Human transport-layer name for the packet's protocol.
function transportName(proto) {
  if (['TCP', 'HTTP', 'TLS'].includes(proto)) return 'TCP';
  if (['UDP', 'DNS'].includes(proto)) return 'UDP';
  if (proto === 'ICMP' || proto === 'ARP') return proto;
  return null;
}
// One collapsible protocol layer for the detail tree.
function treeNode(label, sub, fields, extraClass = '') {
  const head = `<div class="tnode-head"><span class="twist">▾</span>` +
    `<span class="tlabel">${esc(label)}${sub ? ` <span class="tlabel-sub">${esc(sub)}</span>` : ''}</span></div>`;
  const body = `<div class="tbody">${fields.map(([k, v, mono]) =>
    `<div class="tfield"><span class="tkey">${esc(k)}</span><span class="tval${mono ? ' mono' : ''}">${esc(v)}</span></div>`
  ).join('')}</div>`;
  return `<div class="tnode ${extraClass}">${head}${body}</div>`;
}

// Build the Wireshark-style layered protocol tree for one packet.
function buildDetailTree(pkt, index) {
  const nodes = [];
  const ipVer = pkt.src_addr ? (pkt.src_addr.includes(':') ? 'IPv6' : 'IPv4') : null;
  const transport = transportName(pkt.protocol);
  const chain = ['Ethernet', ipVer, transport !== pkt.protocol ? transport : null, pkt.protocol]
    .filter((x, i, a) => x && a.indexOf(x) === i);

  // Frame layer
  nodes.push(treeNode(`Frame ${index + 1}`, `${pkt.length} bytes on wire`, [
    ['Arrival time', pkt.timestamp],
    ['Frame length', `${pkt.length} bytes`],
    ['Captured bytes', `${(pkt.raw || []).length} bytes`],
    ['Protocols in frame', chain.join(' · ')],
  ]));

  // Network layer
  if (pkt.src_addr || pkt.dst_addr) {
    const net = [];
    if (pkt.src_addr) net.push(['Source address', pkt.src_addr, true]);
    if (pkt.src_host) net.push(['Source host', pkt.src_host]);
    if (pkt.dst_addr) net.push(['Destination address', pkt.dst_addr, true]);
    if (pkt.dst_host) net.push(['Destination host', pkt.dst_host]);
    nodes.push(treeNode(`Internet Protocol ${ipVer ? `(${ipVer})` : ''}`.trim(),
      pkt.src_addr && pkt.dst_addr ? `${pkt.src_addr} → ${pkt.dst_addr}` : '', net));
  }

  // GeoIP placeholders — filled in asynchronously by enrichGeo() for public IPs.
  for (const [role, ip] of [['Destination', pkt.dst_addr], ['Source', pkt.src_addr]]) {
    if (!isPublicIp(ip)) continue;
    nodes.push(`<div class="tnode tnode-geo geo-node" data-ip="${esc(ip)}" data-role="${role}">` +
      `<div class="tnode-head"><span class="twist">▾</span>` +
      `<span class="tlabel">🌍 ${role} location <span class="tlabel-sub">${esc(ip)}</span></span></div>` +
      `<div class="tbody"><div class="tfield"><span class="tkey">Location</span>` +
      `<span class="tval geo-status">Looking up…</span></div></div></div>`);
  }

  // Transport layer
  if (transport && (pkt.src_port != null || pkt.dst_port != null)) {
    const t = [['Transport', transport]];
    if (pkt.src_port != null) t.push(['Source port', String(pkt.src_port), true]);
    if (pkt.dst_port != null) t.push(['Destination port', String(pkt.dst_port), true]);
    nodes.push(treeNode(transport,
      `${pkt.src_port ?? '?'} → ${pkt.dst_port ?? '?'}`, t));
  }

  // Application / summary layer
  nodes.push(treeNode(pkt.protocol, 'application data', [
    ['Protocol', pkt.protocol],
    ['Info', pkt.summary || '—'],
  ]));

  // netscope's plain-language explanation (its edge over Wireshark)
  if (pkt.explanation) {
    nodes.push(`<div class="tnode tnode-explain"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">ℹ What is this?</span></div>` +
      `<div class="tbody">${esc(pkt.explanation)}</div></div>`);
  }
  return nodes.join('');
}

// ---- GeoIP enrichment ----
// Looked up on demand (only when a packet is opened), cached per IP, so we add
// at most one request per unique remote host you actually inspect.
const geoCache = new Map(); // ip -> { status: 'ok'|'failed', data? }

function isPublicIp(ip) {
  if (!ip) return false;
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    if (l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l === '::') return false;
    return true;
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(isNaN)) return false;
  if (p[0] === 10 || p[0] === 127 || p[0] === 0 || p[0] >= 224) return false;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
  if (p[0] === 192 && p[1] === 168) return false;
  if (p[0] === 169 && p[1] === 254) return false;
  return true;
}

async function lookupGeo(ip) {
  const cached = geoCache.get(ip);
  if (cached && cached.status !== 'pending') return cached;
  if (cached && cached.status === 'pending') return cached.promise;

  const promise = (async () => {
    try {
      const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
      const j = await r.json();
      if (j && j.success) {
        const c = j.connection || {};
        const entry = { status: 'ok', data: {
          country: j.country, code: j.country_code, flag: j.flag && j.flag.emoji,
          city: j.city, region: j.region,
          isp: c.isp || c.org, org: c.org, asn: c.asn,
        } };
        geoCache.set(ip, entry);
        return entry;
      }
    } catch { /* offline or blocked — fall through */ }
    const failed = { status: 'failed' };
    geoCache.set(ip, failed);
    return failed;
  })();
  geoCache.set(ip, { status: 'pending', promise });
  return promise;
}

function fillGeoNode(node, g) {
  const body = node.querySelector('.tbody');
  if (!body) return;
  if (!g || g.status !== 'ok') {
    body.innerHTML = `<div class="tfield"><span class="tkey">Location</span><span class="tval">Unknown (lookup unavailable)</span></div>`;
    return;
  }
  const d = g.data;
  const rows = [['Country', `${d.flag ? d.flag + ' ' : ''}${d.country || '—'}${d.code ? ` (${d.code})` : ''}`]];
  const place = [d.city, d.region].filter(Boolean).join(', ');
  if (place) rows.push(['City', place]);
  if (d.isp) rows.push(['Service / owner', d.isp]);
  if (d.org && d.org !== d.isp) rows.push(['Organisation', d.org]);
  if (d.asn) rows.push(['Network', `AS${d.asn}`]);
  body.innerHTML = rows.map(([k, v]) =>
    `<div class="tfield"><span class="tkey">${esc(k)}</span><span class="tval">${esc(v)}</span></div>`).join('');
}

async function enrichGeo(pkt) {
  for (const [role, ip] of [['Destination', pkt.dst_addr], ['Source', pkt.src_addr]]) {
    if (!isPublicIp(ip)) continue;
    const g = await lookupGeo(ip);
    // Only apply if this packet is still the one on screen.
    const sel = `.geo-node[data-ip="${ip}"][data-role="${role}"]`;
    const node = els.detailTree.querySelector(sel);
    if (node) fillGeoNode(node, g);
  }
}

function showDetail(index) {
  const pkt = state.filteredPackets[index];
  if (!pkt) return;
  state.selectedIndex = index;
  $('#view-packets').classList.add('with-detail');
  els.detailTree.innerHTML = buildDetailTree(pkt, index);
  els.hexDump.innerHTML = hexDump(pkt.raw || []);
  els.hexLen.textContent = `${(pkt.raw || []).length} bytes`;
  enrichGeo(pkt);
}
function hideDetail() {
  state.selectedIndex = -1;
  $('#view-packets').classList.remove('with-detail');
  renderPacketList();
}
function hexDump(bytes) {
  if (!bytes.length) return '<span class="hx-off">(no data)</span>';
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    out += `<span class="hx-off">${i.toString(16).padStart(4, '0')}</span>  ` +
      `<span class="hx-hex">${hex.padEnd(47)}</span>  ` +
      `<span class="hx-asc">${esc(ascii)}</span>\n`;
  }
  return out;
}

// ---- Dashboard ----
function updateStats(pkt) {
  const s = state.stats;
  s.totalPackets++; s.totalBytes += pkt.length;
  if (!s.perProtocol[pkt.protocol]) s.perProtocol[pkt.protocol] = { total_packets: 0, total_bytes: 0 };
  s.perProtocol[pkt.protocol].total_packets++;
  s.perProtocol[pkt.protocol].total_bytes += pkt.length;

  if (pkt.src_addr) {
    const e = s.topTalkersSent.find(([ip]) => ip === (pkt.src_host || pkt.src_addr));
    if (e) e[1] += pkt.length; else s.topTalkersSent.push([pkt.src_host || pkt.src_addr, pkt.length]);
    s.topTalkersSent.sort((a, b) => b[1] - a[1]);
    s.topTalkersSent = s.topTalkersSent.slice(0, 10);
  }
  if (pkt.protocol === 'DNS') {
    const m = pkt.summary.match(/DNS (?:Query|Response) — (\S+)/);
    if (m) {
      const d = s.topDomains.find(([x]) => x === m[1]);
      if (d) d[1]++; else s.topDomains.push([m[1], 1]);
      s.topDomains.sort((a, b) => b[1] - a[1]);
      s.topDomains = s.topDomains.slice(0, 12);
    }
  }
}
function renderStats() {
  const s = state.stats;
  els.statTotalPackets.textContent = s.totalPackets.toLocaleString();
  els.statTotalBytes.textContent = formatBytes(s.totalBytes);
  els.statBlocked.textContent = state.blocked.size;

  const protos = Object.entries(s.perProtocol).sort((a, b) => b[1].total_packets - a[1].total_packets);
  const max = protos.length ? protos[0][1].total_packets : 1;
  els.protoBars.innerHTML = protos.map(([p, st]) => {
    const c = protoColor(p);
    const pct = s.totalPackets ? ((st.total_packets / s.totalPackets) * 100).toFixed(1) : '0';
    return `<div class="proto-bar-row"><span class="proto-label" style="color:${c}">${p}</span>
      <div class="proto-bar-bg"><div class="proto-bar-fill" style="width:${(st.total_packets / max) * 100}%;background:${c}"></div></div>
      <span class="proto-pct">${pct}%</span></div>`;
  }).join('') || '<div style="color:var(--text-muted);font-size:12px">No data</div>';

  els.talkerList.innerHTML = s.topTalkersSent.slice(0, 8).map(([ip, b]) =>
    `<div class="talker-item"><span class="talker-ip">${ip}</span><span class="talker-bytes">${formatBytes(b)}</span></div>`
  ).join('') || '<div style="color:var(--text-muted);font-size:12px">No data</div>';

  els.dnsList.innerHTML = s.topDomains.slice(0, 12).map(([d, n]) =>
    `<div class="dns-item"><span class="dns-domain">${d}</span><span class="dns-count">${n}</span></div>`
  ).join('') || '<div style="color:var(--text-muted);font-size:12px">No domains</div>';
}

// ---- Learn ----
async function loadLearn() {
  try {
    const lessons = await invoke('get_lessons');
    const glossary = await invoke('get_glossary');
    if (lessons) {
      els.lessonCards.innerHTML = lessons.map((l) => {
        const c = protoColor(l.protocol);
        return `<div class="lesson-card" style="border-left-color:${c}">
          <h4 style="color:${c}">${l.title}</h4>
          <div class="gist">${l.summary}</div>
          <div class="body">${l.body}</div>
          <div class="look">${l.look_for}</div>
        </div>`;
      }).join('');
    }
    if (glossary) {
      els.glossaryList.innerHTML = glossary.map((t) =>
        `<div class="glossary-item"><span class="term">${t.term}</span> — ${t.meaning}</div>`
      ).join('');
    }
  } catch (e) { console.error('learn load', e); }
}

// ---- Views ----
function switchView(view) {
  state.view = view;
  $$('.view').forEach((el) => el.classList.remove('active'));
  $$('.tab').forEach((el) => el.classList.toggle('active', el.dataset.view === view));
  $(`#view-${view}`).classList.add('active');
  renderAll();
}
function renderAll() {
  if (state.view === 'packets') renderPacketList();
  else if (state.view === 'connections') renderConnections();
  else if (state.view === 'dashboard') renderStats();
}

// ---- Keyboard ----
function handleKeydown(e) {
  if (document.activeElement === els.filterInput) return;
  if (e.key === 'Tab') {
    e.preventDefault();
    const views = ['packets', 'connections', 'dashboard', 'learn'];
    switchView(views[(views.indexOf(state.view) + 1) % views.length]);
  } else if (state.view === 'packets') {
    if (e.key === 'ArrowDown' || e.key === 'j') {
      e.preventDefault();
      showDetail(Math.min(state.selectedIndex + 1, state.filteredPackets.length - 1));
      renderPacketList();
    } else if (e.key === 'ArrowUp' || e.key === 'k') {
      e.preventDefault();
      showDetail(Math.max(state.selectedIndex - 1, 0));
      renderPacketList();
    } else if (e.key === 'Escape') hideDetail();
  }
}

// ---- Init ----
async function init() {
  Object.assign(els, {
    interfaceSelect: $('#interface-select'), startBtn: $('#start-btn'), stopBtn: $('#stop-btn'),
    statusText: $('#status-text'), packetCount: $('#packet-count'), filterInput: $('#filter-input'),
    elevationBadge: $('#elevation-badge'), packetList: $('#packet-list'),
    detailTree: $('#detail-tree'), detailClose: $('#detail-close'),
    hexDump: $('#hex-dump'), hexLen: $('#hex-len'),
    connSummary: $('#conn-summary'), connList: $('#conn-list'),
    statTotalPackets: $('#stat-total-packets'), statTotalBytes: $('#stat-total-bytes'),
    statBandwidth: $('#stat-bandwidth'), statBlocked: $('#stat-blocked'), protoBars: $('#proto-bars'),
    talkerList: $('#talker-list'), dnsList: $('#dns-list'), lessonCards: $('#lesson-cards'),
    glossaryList: $('#glossary-list'),
  });

  await loadInterfaces();
  await loadLearn();

  // elevation + existing blocks
  try {
    state.elevated = await invoke('is_elevated');
    if (!state.elevated) els.elevationBadge.classList.remove('hidden');
    const blocked = await invoke('list_blocked');
    if (blocked) blocked.forEach((ip) => state.blocked.add(ip));
  } catch (e) { console.error(e); }

  await listen('packet', onPacket);
  await listen('capture-finished', () => { setStatus(STATES.IDLE); els.startBtn.disabled = false; els.stopBtn.disabled = true; });

  els.startBtn.addEventListener('click', startCapture);
  els.stopBtn.addEventListener('click', stopCapture);
  els.filterInput.addEventListener('input', () => { state.filterText = els.filterInput.value; renderPacketList(); });
  els.detailClose.addEventListener('click', hideDetail);
  els.detailTree.addEventListener('click', (e) => {
    const head = e.target.closest('.tnode-head');
    if (head) head.parentElement.classList.toggle('collapsed');
  });
  els.packetList.addEventListener('click', (e) => {
    const row = e.target.closest('.packet-row');
    if (row) { showDetail(parseInt(row.dataset.index)); renderPacketList(); }
  });
  els.connList.addEventListener('click', (e) => {
    const b = e.target.closest('[data-block]');
    const u = e.target.closest('[data-unblock]');
    if (b) doBlock(b.dataset.block);
    else if (u) doUnblock(u.dataset.unblock);
  });
  $$('.tab').forEach((t) => t.addEventListener('click', () => switchView(t.dataset.view)));
  document.addEventListener('keydown', handleKeydown);

  renderAll();
}

document.addEventListener('DOMContentLoaded', init);
