// netscope Desktop — Frontend
// Talks to the Rust backend over Tauri IPC (window.__TAURI__).

const PROTOCOL_COLORS = {
  TCP: '#4a9ef5', UDP: '#45d1c5', DNS: '#a78bfa', HTTP: '#34d399',
  TLS: '#6ee7b7', ICMP: '#fbbf24', ARP: '#9ca3af',
};
const protoColor = (p) => PROTOCOL_COLORS[p] || '#f87171';

const STATES = { IDLE: 'Idle', CAPTURING: 'Capturing' };

// ---- Persisted settings & profiles (localStorage — survives app restarts) ----
function loadJSON(key, fallback) {
  try { const v = JSON.parse(localStorage.getItem(key)); return v == null ? fallback : v; } catch { return fallback; }
}
function saveJSON(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable — settings just won't persist */ }
}

// Built-in task presets — mirrors Wireshark's Configuration Profiles, scoped to
// what netscope actually supports (a starting filter, a starting view, and
// display preferences), not per-protocol column layouts.
const BUILTIN_PROFILES = {
  'HTTP Analysis': {
    filter: 'http or tls', view: 'packets', timeFormat: 'time', showHostnames: true,
    hint: 'Filters to web traffic (HTTP + HTTPS/TLS) so requests and responses aren’t buried in noise.',
  },
  'VoIP': {
    filter: 'udp', view: 'dashboard', timeFormat: 'time', showHostnames: true,
    hint: 'VoIP calls (SIP/RTP) run over UDP, so this filters to UDP traffic. netscope doesn’t decode SIP/RTP call detail yet — this just narrows the noise.',
  },
  'Security Review': {
    filter: '', view: 'connections', timeFormat: 'datetime', showHostnames: true,
    hint: 'Shows every connection with full date + time stamps, for lining traffic up against an incident timeline.',
  },
};

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
  // Time Display Format: 'time' (HH:MM:SS.mmm), 'datetime' (date + time),
  // 'relative' (seconds since the first packet of this capture session).
  settings: Object.assign({ timeFormat: 'time', showHostnames: true, profile: 'HTTP Analysis' }, loadJSON('netscope.settings', {})),
  customProfiles: loadJSON('netscope.profiles', {}),
  captureStartEpoch: null,
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
  const useHost = state.settings.showHostnames && !!host;
  const name = useHost ? host : addr;
  const p = port != null ? `:${port}` : '';
  // bracket IPv6 when no host name
  const base = !useHost && addr.includes(':') ? `[${addr}]` : name;
  return `${base}${p}`;
}

// ---- Time Display Format (Wireshark: View > Time Display Format) ----
function pad(n, len = 2) { return String(n).padStart(len, '0'); }
function formatPacketTime(pkt) {
  const fmt = state.settings.timeFormat;
  if (fmt === 'time' || pkt.epoch_ms == null) return pkt.timestamp; // "HH:MM:SS.mmm", backend-formatted
  if (fmt === 'relative') {
    if (state.captureStartEpoch == null) state.captureStartEpoch = pkt.epoch_ms;
    return `${((pkt.epoch_ms - state.captureStartEpoch) / 1000).toFixed(6)}s`;
  }
  // 'datetime' — full date + time, computed client-side from the raw epoch
  const d = new Date(pkt.epoch_ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
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
    state.captureStartEpoch = null; // "Seconds since beginning of capture" baseline resets each run
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
  else if (state.view === 'script') updateScriptCount();
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
// Cap how many packets we keep per flow for "Follow Stream" — bounds memory
// on long-running captures without limiting the visible conversation in practice.
const FLOW_STREAM_CAP = 4000;

function updateFlow(pkt) {
  if (!pkt.src_addr || !pkt.dst_addr) return;
  const t = transportOf(pkt.protocol);
  const a = `${pkt.src_addr}:${pkt.src_port ?? ''}`;
  const b = `${pkt.dst_addr}:${pkt.dst_port ?? ''}`;
  const key = (a <= b ? `${a}|${b}` : `${b}|${a}`) + `|${t}`;

  let f = state.flows.get(key);
  if (!f) {
    f = {
      key,
      clientAddr: pkt.src_addr, clientPort: pkt.src_port,
      serverAddr: pkt.dst_addr, serverPort: pkt.dst_port,
      serverHost: pkt.dst_host || null,
      proto: pkt.protocol, rank: protoRank(pkt.protocol),
      packets: 0, bytes: 0,
      pkts: [], // raw frames in order, for Follow Stream — see openFollowStream()
    };
    state.flows.set(key, f);
  }
  f.packets++;
  f.bytes += pkt.length;
  if (protoRank(pkt.protocol) > f.rank) { f.proto = pkt.protocol; f.rank = protoRank(pkt.protocol); }
  // learn the server's hostname whenever it shows up
  if (pkt.src_addr === f.serverAddr && pkt.src_host) f.serverHost = pkt.src_host;
  if (pkt.dst_addr === f.serverAddr && pkt.dst_host) f.serverHost = pkt.dst_host;

  if (t === 'tcp' || t === 'udp') {
    if (f.pkts.length < FLOW_STREAM_CAP) {
      f.pkts.push({ fromClient: pkt.src_addr === f.clientAddr && pkt.src_port === f.clientPort, raw: pkt.raw, ts: pkt.timestamp });
    }
  }
}

function renderConnections() {
  const flows = [...state.flows.values()].sort((a, b) => b.bytes - a.bytes);
  els.connSummary.innerHTML = flows.length
    ? `${flows.length} connections · <b>${state.blocked.size}</b> blocked` +
      (state.elevated ? '' : ' · <span style="color:var(--warn)">run as Administrator to block</span>')
    : 'No connections yet — start a capture.';

  els.connList.innerHTML = flows.map((f) => {
    const isBlocked = state.blocked.has(f.serverAddr);
    const server = (state.settings.showHostnames && f.serverHost)
      ? `<span class="conn-host">${esc(f.serverHost)}</span> <span class="conn-ip mono">${esc(f.serverAddr)}${f.serverPort != null ? ':' + f.serverPort : ''}</span>`
      : `<span class="conn-host mono">${esc(endpointLabel(f.serverAddr, null, f.serverPort))}</span>`;
    const client = esc(endpointLabel(f.clientAddr, null, f.clientPort));
    const btn = isBlocked
      ? `<button class="btn btn-small btn-unblock" data-unblock="${esc(f.serverAddr)}">Unblock</button>`
      : `<button class="btn btn-small btn-block" data-block="${esc(f.serverAddr)}" ${state.elevated ? '' : 'title="Needs Administrator"'}>⛔ Block</button>`;
    const followBtn = f.pkts.length
      ? `<button class="btn btn-small" data-follow="${esc(f.key)}" title="Read the full conversation as text">💬 Follow</button>`
      : '';
    return `
      <div class="conn-row conn-row-grid${isBlocked ? ' blocked' : ''}">
        <span class="mono">${client}</span>
        <span class="conn-server">${server}</span>
        <span class="conn-proto" style="color:${protoColor(f.proto)}">${esc(f.proto)}</span>
        <span>${f.packets}</span>
        <span>${formatBytes(f.bytes)}</span>
        <span class="conn-actions">${followBtn}${btn}</span>
      </div>`;
  }).join('');
}

// ---- Follow Stream (Wireshark's "Follow TCP/UDP Stream") ----
// Strips Ethernet + IP + TCP/UDP headers from a captured frame to get the
// application payload. Best-effort: handles a single 802.1Q VLAN tag and
// variable-length IPv4/TCP headers; does not walk IPv6 extension headers.
function extractPayload(raw) {
  if (!raw || raw.length < 14) return null;
  let o = 14;
  let etherType = (raw[12] << 8) | raw[13];
  if (etherType === 0x8100) { // 802.1Q VLAN tag
    if (raw.length < 18) return null;
    etherType = (raw[16] << 8) | raw[17];
    o = 18;
  }
  let proto;
  if (etherType === 0x0800) { // IPv4
    if (raw.length < o + 20) return null;
    const ihl = (raw[o] & 0x0f) * 4;
    proto = raw[o + 9];
    o += Math.max(ihl, 20);
  } else if (etherType === 0x86dd) { // IPv6 (fixed header only, extension headers not walked)
    if (raw.length < o + 40) return null;
    proto = raw[o + 6];
    o += 40;
  } else {
    return null;
  }
  if (proto === 6) { // TCP
    if (raw.length < o + 20) return null;
    const doff = ((raw[o + 12] >> 4) & 0x0f) * 4;
    o += Math.max(doff, 20);
  } else if (proto === 17) { // UDP
    if (raw.length < o + 8) return null;
    o += 8;
  } else {
    return null;
  }
  return o <= raw.length ? raw.slice(o) : new Uint8Array(0);
}

// Render bytes as text the way Wireshark's stream view does: printable ASCII
// and newlines kept as-is, everything else shown as a middle dot.
function decodeStreamText(bytes) {
  let out = '';
  for (const b of bytes) {
    if (b === 10 || b === 13 || b === 9) out += String.fromCharCode(b);
    else if (b >= 32 && b < 127) out += String.fromCharCode(b);
    else out += '·';
  }
  return out;
}

function openFollowStream(key) {
  const f = state.flows.get(key);
  if (!f || !f.pkts.length) return;
  let clientBytes = 0, serverBytes = 0, clientPkts = 0, serverPkts = 0;
  const chunks = [];
  for (const p of f.pkts) {
    const payload = extractPayload(p.raw);
    if (!payload || !payload.length) continue;
    if (p.fromClient) { clientBytes += payload.length; clientPkts++; } else { serverBytes += payload.length; serverPkts++; }
    chunks.push({ fromClient: p.fromClient, text: decodeStreamText(payload) });
  }

  const client = endpointLabel(f.clientAddr, null, f.clientPort);
  const server = endpointLabel(f.serverAddr, f.serverHost, f.serverPort);
  els.streamTitle.innerHTML = `💬 Conversation — <span class="mono">${esc(client)}</span> ⇄ ${esc(server)}`;
  els.streamMeta.textContent = chunks.length
    ? `${client} sent ${formatBytes(clientBytes)} (${clientPkts} pkt) · ${server} sent ${formatBytes(serverBytes)} (${serverPkts} pkt)`
    : 'No readable payload in this conversation (headers/handshake only, or encrypted binary data).';

  els.streamBody.innerHTML = chunks.length
    ? chunks.map((c) =>
        `<div class="stream-chunk ${c.fromClient ? 'from-client' : 'from-server'}">` +
        `<span class="stream-dir">${c.fromClient ? 'Client → Server' : 'Server → Client'}</span>` +
        `<pre>${esc(c.text)}</pre></div>`
      ).join('')
    : '<div class="stream-empty">Nothing to show — this connection has no plain-text payload (common for TLS/HTTPS, which is encrypted by design).</div>';

  els.streamModal.classList.remove('hidden');
}
function closeFollowStream() {
  els.streamModal.classList.add('hidden');
}

// ---- Replay / Repeater — resend a payload to a target and read the response ----
// The application-layer replay (Burp Repeater / Packet Sender style): take the
// selected packet's payload, let the user edit target + bytes, and send it over
// a fresh socket via the backend. Deliberate, user-initiated — see replay_packet.
function bytesToLatin1(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}
function latin1ToBytes(str) {
  const out = new Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}
function renderReplayResponse(bytes, truncated) {
  if (!bytes.length) return '';
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    out += `${i.toString(16).padStart(4, '0')}  ${hex.padEnd(47)}  ${esc(ascii)}\n`;
  }
  if (truncated) out += '\n… (response truncated at 64 KiB)';
  return out;
}

function openReplay() {
  const pkt = state.filteredPackets[state.selectedIndex];
  if (!pkt) return;
  const payload = extractPayload(pkt.raw || []);
  els.replayProto.value = transportName(pkt.protocol) === 'UDP' ? 'udp' : 'tcp';
  els.replayHost.value = pkt.dst_host || pkt.dst_addr || '';
  els.replayPort.value = pkt.dst_port != null ? String(pkt.dst_port) : '';
  els.replayPayload.value = payload ? bytesToLatin1(payload) : (pkt.summary || '');
  els.replayResponse.textContent = '';
  els.replayStatus.textContent = '';
  els.replayModal.classList.remove('hidden');
  els.replayHost.focus();
}
function closeReplay() {
  els.replayModal.classList.add('hidden');
}
async function sendReplay() {
  const host = els.replayHost.value.trim();
  const port = parseInt(els.replayPort.value, 10);
  const protocol = els.replayProto.value;
  const timeout_ms = parseInt(els.replayTimeout.value, 10) || 3000;
  if (!host) { els.replayStatus.textContent = 'Enter a host'; return; }
  if (!(port >= 0 && port <= 65535)) { els.replayStatus.textContent = 'Invalid port'; return; }

  const data = latin1ToBytes(els.replayPayload.value);
  els.replaySend.disabled = true;
  els.replayStatus.textContent = 'Sending…';
  els.replayResponse.textContent = '';
  try {
    const r = await invoke('replay_packet', { host, port, protocol, data, timeoutMs: timeout_ms });
    if (!r) { els.replayStatus.textContent = 'No backend (run inside the desktop app)'; return; }
    const bytes = r.response || [];
    els.replayStatus.textContent = `sent ${r.sent} B · got ${bytes.length} B · ${r.elapsed_ms} ms`;
    els.replayResponse.textContent = bytes.length ? renderReplayResponse(bytes, r.truncated) : (r.note || '(no response)');
  } catch (e) {
    els.replayStatus.textContent = 'Failed';
    els.replayResponse.textContent = `✖ ${e}`;
  } finally {
    els.replaySend.disabled = false;
  }
}

// ---- Expert Info — plain-language flags for notable packets, from real dissector output only ----
function expertInfo(pkt) {
  const s = pkt.summary || '';
  if (s.includes('Malformed')) return { icon: '⛔', label: 'Malformed packet', cls: 'expert-danger' };
  if (s.includes('reset (RST)')) return { icon: '⚠', label: 'Connection reset', cls: 'expert-warn' };
  return null;
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
    const ei = expertInfo(pkt);
    const badge = ei ? `<span class="expert-badge ${ei.cls}" title="${esc(ei.label)}">${ei.icon}</span> ` : '';
    return `
      <div class="packet-row proto-${esc(pkt.protocol)}${sel}" data-index="${idx}">
        <span class="col-num">${idx + 1}</span>
        <span class="col-time" title="${esc(formatPacketTime(pkt))}">${esc(formatPacketTime(pkt))}</span>
        <span class="col-src">${src}</span>
        <span class="col-dir" style="color:${c}">→</span>
        <span class="col-dst">${dst}</span>
        <span class="col-proto" style="color:${c}">${esc(pkt.protocol)}</span>
        <span class="col-len">${pkt.length}B</span>
        <span class="col-info">${badge}${esc(pkt.summary)}</span>
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
    ['Arrival time', formatPacketTime(pkt)],
    ['Frame length', `${pkt.length} bytes`],
    ['Captured bytes', `${(pkt.raw || []).length} bytes`],
    ['Protocols in frame', chain.join(' · ')],
  ]));

  // Network layer
  if (pkt.src_addr || pkt.dst_addr) {
    const net = [];
    if (pkt.src_addr) net.push(['Source address', pkt.src_addr, true]);
    if (state.settings.showHostnames && pkt.src_host) net.push(['Source host', pkt.src_host]);
    if (pkt.dst_addr) net.push(['Destination address', pkt.dst_addr, true]);
    if (state.settings.showHostnames && pkt.dst_host) net.push(['Destination host', pkt.dst_host]);
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

  // Expert Info — only for real anomalies the dissector actually reported
  const ei = expertInfo(pkt);
  if (ei) {
    nodes.push(`<div class="tnode tnode-expert ${ei.cls}"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">${ei.icon} Expert Info</span></div>` +
      `<div class="tbody"><div class="tfield"><span class="tkey">Notice</span><span class="tval">${esc(ei.label)}</span></div></div></div>`);
  }

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
// Desktop-only capabilities (not shared with the TUI, so they live here
// rather than in the Rust education module) — explained the same plain way
// as the protocol lessons above.
const FEATURE_CARDS = [
  {
    icon: '🔬', color: 'var(--tcp)', title: 'Wireshark-style Inspector',
    gist: 'Click any row in Packets to open the full analyzer.',
    body: 'A protocol tree (Frame → IP → TCP/UDP → app layer) and a live hex/ASCII byte view appear below the list — the same three-pane layout Wireshark uses, but each layer is one click to expand or collapse.',
    look: 'Try it: click any packet row, then click a layer heading in the middle pane to fold it.',
  },
  {
    icon: '🌍', color: 'var(--udp)', title: 'Where is it going?',
    gist: 'See the remote host\'s country, city, and owner.',
    body: 'Open a packet and look for the "🌍 Destination location" layer — it shows the country (with flag), city, and the company or ISP that owns the address (e.g. Google LLC, Cloudflare, Inc.).',
    look: 'Looked up only for the packet you open, and cached per IP — never for every packet in the background.',
  },
  {
    icon: '💬', color: 'var(--http)', title: 'Follow Stream',
    gist: 'Read a whole conversation as plain text.',
    body: 'In the Connections view, press 💬 Follow on any TCP/UDP row to see every packet in that conversation reassembled into readable text, color-coded by direction (client vs. server).',
    look: 'Encrypted connections (TLS/HTTPS) will say there\'s no plain text to show — that\'s expected, it means the encryption is working.',
  },
  {
    icon: '⚠', color: 'var(--warn)', title: 'Expert Info',
    gist: 'A small warning badge for real problems.',
    body: 'When a packet\'s connection was reset or its header couldn\'t be parsed, you\'ll see a small ⚠/⛔ badge next to it in the packet list, and an "Expert Info" layer in its detail view — in plain language, not jargon.',
    look: 'Only flags what the dissector actually detected — no guessed-at anomalies.',
  },
  {
    icon: '🗂', color: 'var(--dns)', title: 'Profiles',
    gist: 'Save a filter + view as a named preset.',
    body: 'Click 🗂 Profile (top right) to switch between task presets — HTTP Analysis, VoIP, Security Review — or save your own with "Save current as…". Your choice is remembered next time you open netscope.',
    look: 'Try switching to Security Review — it flips to the Connections view and shows full timestamps automatically.',
  },
  {
    icon: '🕐', color: 'var(--tls)', title: 'Time Display Format',
    gist: 'Show times the way that\'s useful to you.',
    body: 'In the same 🗂 Profile menu, choose Time of Day, full Date and Time of Day, or Seconds Since Beginning of Capture (relative to the first packet) — whichever makes the timeline easiest to read.',
    look: 'Switch to "Seconds Since Beginning" if you want to measure how long something took after capture started.',
  },
  {
    icon: '🛡', color: 'var(--ok)', title: 'Insights (auto security scan)',
    gist: 'netscope reads your capture and tells you what matters.',
    body: 'Open the 🛡 Insights tab and press Scan. Instead of leaving you to eyeball thousands of rows, netscope surfaces plain-language findings: cleartext passwords, unencrypted HTTP, possible port scans, connection errors, and how much of your traffic was actually encrypted — each rated high / warning / info.',
    look: 'This is the thing Wireshark won\'t do: it shows everything but interprets nothing. Insights interprets.',
  },
  {
    icon: '↻', color: 'var(--danger)', title: 'Replay (Repeater)',
    gist: 'Resend a packet to a target and see the response.',
    body: 'Open a packet and press ↻ Replay to reload its payload into a small editor. Tweak it, pick the target host/port, and Send — netscope opens a fresh socket and shows you the response, so you don\'t need Packet Sender or Burp Repeater as a second tool.',
    look: '⚠ This sends real traffic to the target you choose — only use it against systems you\'re authorised to test.',
  },
  {
    icon: '⚡', color: 'var(--http)', title: 'Script Console',
    gist: 'Analyze packets with JavaScript — no export needed.',
    body: 'Open the ⚡ Script tab to run code directly over the captured packets. No more exporting a .pcap and re-reading it with Python/Scapy — every packet is already there as a `packets` array. Flag anomalies, aggregate stats, or scan payloads, then press Ctrl+Enter.',
    look: 'Use the "Load example…" menu for ready-made scripts: connection-reset anomalies, top talkers, unencrypted-secret scanning, and more.',
  },
  {
    icon: '🏷', color: 'var(--icmp)', title: 'Name Resolution toggle',
    gist: 'Flip between hostnames and raw IPs.',
    body: 'Also in the 🗂 Profile menu: uncheck "Resolve hostnames" to see raw IP addresses everywhere instead of names like github.com — useful on very large captures, or when you want the literal address.',
    look: 'This only affects display — netscope never makes active DNS lookups, it just reads DNS traffic that already crossed the wire.',
  },
];

async function loadLearn() {
  try {
    const lessons = await invoke('get_lessons');
    const glossary = await invoke('get_glossary');
    els.featureCards.innerHTML = FEATURE_CARDS.map((f) => `
      <div class="lesson-card" style="border-left-color:${f.color}">
        <h4 style="color:${f.color}">${f.icon} ${f.title}</h4>
        <div class="gist">${f.gist}</div>
        <div class="body">${f.body}</div>
        <div class="look">${f.look}</div>
      </div>`).join('');
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

// ---- Configuration Profiles (Wireshark: Edit > Configuration Profiles) ----
function allProfiles() { return Object.assign({}, BUILTIN_PROFILES, state.customProfiles); }

function applyProfile(name) {
  const p = allProfiles()[name];
  if (!p) return;
  state.settings.profile = name;
  state.settings.timeFormat = p.timeFormat || 'time';
  state.settings.showHostnames = p.showHostnames !== false;
  state.filterText = p.filter || '';
  els.filterInput.value = state.filterText;
  saveJSON('netscope.settings', state.settings);
  renderProfilePanel();
  switchView(p.view || 'packets'); // also re-renders the active view
}

function renderProfilePanel() {
  const all = allProfiles();
  els.profileName.textContent = state.settings.profile;
  els.profileList.innerHTML = Object.keys(all).map((name) => {
    const isCustom = !!state.customProfiles[name];
    const active = name === state.settings.profile ? ' active' : '';
    const del = isCustom ? `<button class="profile-del" data-del-profile="${esc(name)}" title="Delete this profile">×</button>` : '';
    return `<span class="profile-chip${active}" data-profile="${esc(name)}" title="${esc(all[name].hint || '')}">${esc(name)}${del}</span>`;
  }).join('');
  els.timeFormatSelect.value = state.settings.timeFormat;
  els.resolveNamesCheck.checked = state.settings.showHostnames;
}

function saveCurrentAsProfile() {
  const name = (prompt('Profile name (e.g. "DNS debugging"):') || '').trim();
  if (!name) return;
  state.customProfiles[name] = {
    filter: state.filterText, view: state.view,
    timeFormat: state.settings.timeFormat, showHostnames: state.settings.showHostnames,
    hint: 'Custom profile',
  };
  saveJSON('netscope.profiles', state.customProfiles);
  state.settings.profile = name;
  saveJSON('netscope.settings', state.settings);
  renderProfilePanel();
}
function deleteProfile(name) {
  delete state.customProfiles[name];
  saveJSON('netscope.profiles', state.customProfiles);
  if (state.settings.profile === name) applyProfile(Object.keys(BUILTIN_PROFILES)[0]);
  else renderProfilePanel();
}

// ---- Script console — run JavaScript directly over the captured packet stream ----
// This is the "no more exporting to .pcap and re-reading with Scapy" feature:
// every packet is already a plain JS object in state.packets, so user code can
// filter, aggregate and flag anomalies in place. Runs in the renderer (the
// user's own machine, their own code — like a devtools console scoped to packets).

const SCRIPT_DEFAULT =
`// 'packets' is an array of every captured packet.
// Each packet: { timestamp, epoch_ms, src_addr, dst_addr, src_host,
//   dst_host, src_port, dst_port, protocol, length, summary, raw }
// Helpers: flag(pkt, reason)  print(...)  h.payloadText(pkt)  h.formatBytes(n)
//
// Return a value to display it, or use flag()/print(). Ctrl+Enter runs.

let total = 0;
for (const p of packets) total += p.length;
print('Captured', packets.length, 'packets,', h.formatBytes(total), 'total');

// Flag every connection reset as an anomaly:
for (const p of packets) {
  if (p.summary.includes('reset (RST)')) flag(p, 'TCP connection reset');
}`;

const SCRIPT_EXAMPLES = {
  anomaly:
`// Find hosts causing an unusual number of connection resets (RST).
const resets = {};
for (const p of packets) {
  if (!p.summary.includes('reset (RST)')) continue;
  const key = p.src_addr || '?';
  resets[key] = (resets[key] || 0) + 1;
}
for (const [ip, n] of Object.entries(resets)) {
  if (n >= 3) print('⚠', ip, 'sent', n, 'resets');
}
return Object.keys(resets).length ? resets : 'No connection resets seen.';`,

  talkers:
`// Top 10 destinations by bytes sent to them.
const bytes = {};
for (const p of packets) {
  const key = p.dst_host || p.dst_addr;
  if (!key) continue;
  bytes[key] = (bytes[key] || 0) + p.length;
}
return Object.entries(bytes)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 10)
  .map(([host, n]) => host + '  →  ' + h.formatBytes(n));`,

  plaintext:
`// Scan unencrypted HTTP payloads for anything that looks like a credential.
const needles = ['password', 'passwd', 'pass=', 'token', 'authorization', 'api_key'];
for (const p of packets) {
  if (p.protocol !== 'HTTP') continue;
  const text = h.payloadText(p).toLowerCase();
  for (const n of needles) {
    if (text.includes(n)) { flag(p, 'HTTP payload contains "' + n + '"'); break; }
  }
}
return 'Scanned ' + packets.filter(p => p.protocol === 'HTTP').length + ' HTTP packets.';`,

  domains:
`// Flag DNS lookups to unusually long or high-entropy domains
// (a rough heuristic for tunneling / DGA malware).
for (const p of packets) {
  if (p.protocol !== 'DNS') continue;
  const m = p.summary.match(/DNS (?:Query|Response) [—-] (\\S+)/);
  if (!m) continue;
  const domain = m[1];
  const label = domain.split('.')[0] || '';
  const digits = (label.match(/[0-9]/g) || []).length;
  if (label.length > 25 || digits > 8) flag(p, 'Suspicious domain: ' + domain);
}
return 'Checked DNS traffic.';`,

  protos:
`// Count packets and bytes per protocol.
const byProto = {};
for (const p of packets) {
  const b = byProto[p.protocol] || (byProto[p.protocol] = { packets: 0, bytes: 0 });
  b.packets++; b.bytes += p.length;
}
return Object.entries(byProto)
  .sort((a, b) => b[1].packets - a[1].packets)
  .map(([name, s]) => name.padEnd(8) + s.packets + ' pkts, ' + h.formatBytes(s.bytes));`,
};

function runScript() {
  const code = els.scriptEditor.value;
  const packets = state.packets;
  const logs = [];
  const flagged = [];
  const print = (...a) => logs.push(a.map((x) => (x && typeof x === 'object') ? JSON.stringify(x) : String(x)).join(' '));
  const flag = (pkt, reason) => flagged.push({ pkt, reason: reason == null ? '' : String(reason) });
  const helpers = {
    formatBytes,
    payloadText: (pkt) => { const p = extractPayload((pkt && pkt.raw) || []); return p ? decodeStreamText(p) : ''; },
    bytesToText: (bytes) => decodeStreamText(bytes || []),
  };

  let ret, err;
  const t0 = performance.now();
  try {
    // eslint-disable-next-line no-new-func
    const fn = new Function('packets', 'flag', 'print', 'h', `"use strict";\n${code}`);
    ret = fn(packets, flag, print, helpers);
  } catch (e) { err = e; }
  const ms = (performance.now() - t0).toFixed(1);

  renderScriptOutput({ logs, flagged, ret, err, ms, total: packets.length });
}

function renderScriptOutput({ logs, flagged, ret, err, ms, total }) {
  els.scriptTime.textContent = `ran over ${total} packets · ${ms} ms`;
  let html = '';
  if (err) {
    html += `<div class="script-err">✖ ${esc(err.name || 'Error')}: ${esc(err.message || String(err))}</div>`;
  }
  if (logs.length) {
    html += `<div class="script-block"><div class="script-block-h">print()</div><pre class="script-log">${esc(logs.join('\n'))}</pre></div>`;
  }
  if (flagged.length) {
    html += `<div class="script-block"><div class="script-block-h">🚩 Flagged (${flagged.length})</div>` +
      flagged.slice(0, 200).map((f) => {
        const p = f.pkt || {};
        const c = protoColor(p.protocol);
        const where = `${endpointLabel(p.src_addr, p.src_host, p.src_port)} → ${endpointLabel(p.dst_addr, p.dst_host, p.dst_port)}`;
        return `<div class="script-flag">
          <span class="script-flag-proto" style="color:${c}">${esc(p.protocol || '?')}</span>
          <span class="mono">${esc(where)}</span>
          <span class="script-flag-reason">${esc(f.reason)}</span>
        </div>`;
      }).join('') +
      (flagged.length > 200 ? `<div class="script-more">…and ${flagged.length - 200} more</div>` : '') +
      `</div>`;
  }
  if (ret !== undefined) {
    let retText;
    if (Array.isArray(ret)) retText = ret.map((r) => (r && typeof r === 'object') ? JSON.stringify(r) : String(r)).join('\n');
    else if (ret && typeof ret === 'object') retText = JSON.stringify(ret, null, 2);
    else retText = String(ret);
    html += `<div class="script-block"><div class="script-block-h">return</div><pre class="script-ret">${esc(retText)}</pre></div>`;
  }
  if (!html) html = '<div class="script-empty">No output — return a value, or call print() / flag() in your script.</div>';
  els.scriptOutput.innerHTML = html;
}

function updateScriptCount() {
  if (els.scriptCount) els.scriptCount.textContent = `${state.packets.length} packets available`;
}

// ---- Insights — automatic security & privacy analysis over the capture ----
// Wireshark shows you everything but interprets nothing; this pass turns the
// captured packets into plain-language findings. All heuristics run on data
// already in state.packets — no extra capture, no network calls.
const SEV_RANK = { high: 0, warn: 1, info: 2, ok: 3 };

function analyzeCapture(pkts) {
  const findings = [];
  const add = (severity, icon, title, detail, evidence) =>
    findings.push({ severity, icon, title, detail, evidence: evidence || [] });

  // Byte accounting for the privacy headline.
  let tlsBytes = 0, httpBytes = 0, totalBytes = 0;
  const httpHosts = new Set();
  const creds = [];
  const credNeedles = ['password', 'passwd', 'pass=', 'pwd=', 'token', 'authorization:', 'api_key', 'apikey', 'secret'];
  const dnsDomains = new Map();
  const suspiciousDomains = [];
  let resets = 0, malformed = 0;
  const portsPerTarget = new Map(); // "src|dst" -> Set(dstPort)
  const hostsPerSrc = new Map();     // src -> Set(dstAddr)

  for (const p of pkts) {
    totalBytes += p.length || 0;
    if (p.protocol === 'TLS') tlsBytes += p.length || 0;

    if (p.protocol === 'HTTP') {
      httpBytes += p.length || 0;
      if (p.dst_host || p.dst_addr) httpHosts.add(p.dst_host || p.dst_addr);
      const text = (extractPayload(p.raw || []) ? decodeStreamText(extractPayload(p.raw || [])) : '').toLowerCase();
      if (text) {
        for (const n of credNeedles) {
          if (text.includes(n)) { creds.push({ host: p.dst_host || p.dst_addr || '?', needle: n }); break; }
        }
      }
    }

    if (p.protocol === 'DNS') {
      const m = (p.summary || '').match(/DNS (?:Query|Response) [—-] (\S+)/);
      if (m) {
        const d = m[1];
        dnsDomains.set(d, (dnsDomains.get(d) || 0) + 1);
        const label = d.split('.')[0] || '';
        const digits = (label.match(/[0-9]/g) || []).length;
        if (label.length > 25 || digits > 8) suspiciousDomains.push(d);
      }
    }

    if ((p.summary || '').includes('reset (RST)')) resets++;
    if ((p.summary || '').includes('Malformed')) malformed++;

    if (p.src_addr && p.dst_addr) {
      const pair = `${p.src_addr}|${p.dst_addr}`;
      if (p.dst_port != null) {
        if (!portsPerTarget.has(pair)) portsPerTarget.set(pair, new Set());
        portsPerTarget.get(pair).add(p.dst_port);
      }
      if (!hostsPerSrc.has(p.src_addr)) hostsPerSrc.set(p.src_addr, new Set());
      hostsPerSrc.get(p.src_addr).add(p.dst_addr);
    }
  }

  // 1. Cleartext credentials — highest priority.
  if (creds.length) {
    const hosts = [...new Set(creds.map((c) => c.host))];
    add('high', '🔓', `Possible credential sent in cleartext (${creds.length})`,
      'Unencrypted HTTP payloads contained words like "password" or "token". Anyone between you and the server could read these. The site should be using HTTPS.',
      hosts.slice(0, 5).map((h) => `to ${h}`));
  }

  // 2. Unencrypted HTTP traffic.
  if (httpHosts.size) {
    add('warn', '🌐', `Unencrypted HTTP to ${httpHosts.size} site${httpHosts.size > 1 ? 's' : ''}`,
      'Plain HTTP is readable by anyone on the network path (your ISP, Wi-Fi operator, etc.). Prefer HTTPS.',
      [...httpHosts].slice(0, 6));
  }

  // 3. Connection problems.
  if (resets + malformed >= 5) {
    add('warn', '⚠', `${resets} resets, ${malformed} malformed packets`,
      'A burst of connection resets or malformed packets can mean an unstable link, a firewall cutting connections, or scanning activity.');
  }

  // 4. Possible port scan (one source probing many ports on one target).
  for (const [pair, ports] of portsPerTarget) {
    if (ports.size >= 15) {
      const [src, dst] = pair.split('|');
      add('high', '📡', `Possible port scan: ${src} → ${dst}`,
        `${src} contacted ${ports.size} different ports on ${dst}. Hitting many ports on one host is a classic scan pattern.`);
    }
  }

  // 5. High fan-out (one host reaching an unusually large number of destinations).
  for (const [src, hosts] of hostsPerSrc) {
    if (hosts.size >= 40) {
      add('info', '🕸', `${src} contacted ${hosts.size} different hosts`,
        'A single host reaching very many destinations can be normal (a browser, an updater) or can indicate scanning or malware beaconing. Worth a glance.');
    }
  }

  // 6. Plaintext DNS exposure.
  if (dnsDomains.size) {
    const top = [...dnsDomains.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([d, n]) => `${d} (${n})`);
    add('info', '🕵', `${dnsDomains.size} domain${dnsDomains.size > 1 ? 's' : ''} looked up in cleartext`,
      'Standard DNS is unencrypted, so your network and ISP can see every domain you resolve — even for HTTPS sites. Consider DNS-over-HTTPS/TLS for privacy.',
      top);
  }
  if (suspiciousDomains.length) {
    add('warn', '🧬', `${suspiciousDomains.length} unusual domain name${suspiciousDomains.length > 1 ? 's' : ''}`,
      'Very long or high-digit domain labels can indicate DNS tunneling or algorithmically-generated malware domains.',
      [...new Set(suspiciousDomains)].slice(0, 5));
  }

  // 7. Privacy headline (encrypted vs cleartext web traffic).
  const webBytes = tlsBytes + httpBytes;
  if (webBytes > 0) {
    const enc = Math.round((tlsBytes / webBytes) * 100);
    if (httpBytes === 0) {
      add('ok', '🔒', 'All web traffic was encrypted', 'Every web (HTTP/TLS) byte in this capture used HTTPS. Good — its contents are private in transit.');
    } else {
      add(enc >= 80 ? 'info' : 'warn', '🔐', `${enc}% of web traffic was encrypted`,
        `${formatBytes(tlsBytes)} went over HTTPS and ${formatBytes(httpBytes)} over plain HTTP. The plain part is readable in transit.`);
    }
  }

  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
  return findings;
}

function renderInsights() {
  const pkts = state.packets;
  if (!pkts.length) {
    els.insightsSummary.textContent = '';
    els.insightsList.innerHTML = '<div class="insights-empty">No packets captured yet. Start a capture (or open a .pcap), then scan.</div>';
    return;
  }
  const findings = analyzeCapture(pkts);
  const highs = findings.filter((f) => f.severity === 'high').length;
  const warns = findings.filter((f) => f.severity === 'warn').length;
  els.insightsSummary.innerHTML = `Scanned <b>${pkts.length}</b> packets · ` +
    `${highs ? `<span class="sev-dot sev-high"></span><b>${highs}</b> high · ` : ''}` +
    `${warns ? `<span class="sev-dot sev-warn"></span><b>${warns}</b> warnings · ` : ''}` +
    `${findings.length} finding${findings.length === 1 ? '' : 's'}`;

  els.insightsList.innerHTML = findings.map((f) => `
    <div class="finding sev-${f.severity}">
      <div class="finding-head">
        <span class="finding-icon">${f.icon}</span>
        <span class="finding-title">${esc(f.title)}</span>
        <span class="finding-sev">${f.severity.toUpperCase()}</span>
      </div>
      <div class="finding-detail">${esc(f.detail)}</div>
      ${f.evidence.length ? `<ul class="finding-evidence">${f.evidence.map((e) => `<li class="mono">${esc(e)}</li>`).join('')}</ul>` : ''}
    </div>`).join('') || '<div class="insights-empty">Nothing notable found — no cleartext secrets, scans, or errors in this capture.</div>';
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
  else if (state.view === 'script') updateScriptCount();
  else if (state.view === 'insights') renderInsights();
}

// ---- Keyboard ----
function handleKeydown(e) {
  if (e.key === 'Escape' && !els.replayModal.classList.contains('hidden')) { closeReplay(); return; }
  if (e.key === 'Escape' && !els.streamModal.classList.contains('hidden')) { closeFollowStream(); return; }
  if (document.activeElement === els.filterInput || document.activeElement === els.scriptEditor) return;
  if (!els.replayModal.classList.contains('hidden')) return; // don't hijack keys while editing the replay form
  if (e.key === 'Tab') {
    e.preventDefault();
    const views = ['packets', 'connections', 'dashboard', 'insights', 'script', 'learn'];
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
    glossaryList: $('#glossary-list'), featureCards: $('#feature-cards'),
    scriptEditor: $('#script-editor'), scriptRun: $('#script-run'), scriptClear: $('#script-clear'),
    scriptExamples: $('#script-examples'), scriptOutput: $('#script-output'),
    scriptTime: $('#script-time'), scriptCount: $('#script-count'),
    insightsRescan: $('#insights-rescan'), insightsSummary: $('#insights-summary'), insightsList: $('#insights-list'),
    streamModal: $('#stream-modal'), streamTitle: $('#stream-title'), streamMeta: $('#stream-meta'),
    streamBody: $('#stream-body'), streamClose: $('#stream-close'),
    replayOpen: $('#replay-open'), replayModal: $('#replay-modal'), replayClose: $('#replay-close'),
    replayProto: $('#replay-proto'), replayHost: $('#replay-host'), replayPort: $('#replay-port'),
    replayTimeout: $('#replay-timeout'), replaySend: $('#replay-send'),
    replayPayload: $('#replay-payload'), replayResponse: $('#replay-response'), replayStatus: $('#replay-status'),
    profileBtn: $('#profile-btn'), profileName: $('#profile-name'), profilePanel: $('#profile-panel'),
    profileList: $('#profile-list'), profileSaveBtn: $('#profile-save-btn'),
    timeFormatSelect: $('#time-format-select'), resolveNamesCheck: $('#resolve-names-check'),
  });

  await loadInterfaces();
  await loadLearn();

  // Restore the persisted profile (or fall back if it was deleted elsewhere)
  if (!allProfiles()[state.settings.profile]) state.settings.profile = Object.keys(BUILTIN_PROFILES)[0];
  applyProfile(state.settings.profile);

  // Script console: restore last script or seed with the default
  els.scriptEditor.value = loadJSON('netscope.script', SCRIPT_DEFAULT);

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
    const f = e.target.closest('[data-follow]');
    if (b) doBlock(b.dataset.block);
    else if (u) doUnblock(u.dataset.unblock);
    else if (f) openFollowStream(f.dataset.follow);
  });
  els.streamClose.addEventListener('click', closeFollowStream);
  els.streamModal.addEventListener('click', (e) => { if (e.target === els.streamModal) closeFollowStream(); });

  els.insightsRescan.addEventListener('click', renderInsights);

  els.replayOpen.addEventListener('click', openReplay);
  els.replayClose.addEventListener('click', closeReplay);
  els.replayModal.addEventListener('click', (e) => { if (e.target === els.replayModal) closeReplay(); });
  els.replaySend.addEventListener('click', sendReplay);

  els.profileBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    els.profilePanel.classList.toggle('hidden');
  });
  document.addEventListener('click', (e) => {
    if (els.profilePanel.classList.contains('hidden')) return;
    if (!els.profilePanel.contains(e.target) && !els.profileBtn.contains(e.target)) els.profilePanel.classList.add('hidden');
  });
  els.profileList.addEventListener('click', (e) => {
    const del = e.target.closest('[data-del-profile]');
    if (del) { e.stopPropagation(); deleteProfile(del.dataset.delProfile); return; }
    const chip = e.target.closest('[data-profile]');
    if (chip) applyProfile(chip.dataset.profile);
  });
  els.profileSaveBtn.addEventListener('click', saveCurrentAsProfile);
  els.timeFormatSelect.addEventListener('change', () => {
    state.settings.timeFormat = els.timeFormatSelect.value;
    saveJSON('netscope.settings', state.settings);
    renderPacketList();
    if (state.selectedIndex >= 0) showDetail(state.selectedIndex);
  });
  els.resolveNamesCheck.addEventListener('change', () => {
    state.settings.showHostnames = els.resolveNamesCheck.checked;
    saveJSON('netscope.settings', state.settings);
    renderAll();
    if (state.selectedIndex >= 0) showDetail(state.selectedIndex);
  });
  // Script console
  els.scriptRun.addEventListener('click', runScript);
  els.scriptClear.addEventListener('click', () => { els.scriptOutput.innerHTML = ''; els.scriptTime.textContent = ''; });
  els.scriptEditor.addEventListener('input', () => saveJSON('netscope.script', els.scriptEditor.value));
  els.scriptEditor.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScript(); }
    if (e.key === 'Tab') { // insert a tab instead of moving focus
      e.preventDefault();
      const el = els.scriptEditor, s = el.selectionStart, en = el.selectionEnd;
      el.value = el.value.slice(0, s) + '  ' + el.value.slice(en);
      el.selectionStart = el.selectionEnd = s + 2;
      saveJSON('netscope.script', el.value);
    }
  });
  els.scriptExamples.addEventListener('change', () => {
    const ex = SCRIPT_EXAMPLES[els.scriptExamples.value];
    if (ex) { els.scriptEditor.value = ex; saveJSON('netscope.script', ex); }
    els.scriptExamples.value = '';
    els.scriptEditor.focus();
  });

  $$('.tab').forEach((t) => t.addEventListener('click', () => switchView(t.dataset.view)));
  document.addEventListener('keydown', handleKeydown);

  renderAll();
}

document.addEventListener('DOMContentLoaded', init);
