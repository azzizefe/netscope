// netscope Desktop — Frontend
// Talks to the Rust backend over Tauri IPC (window.__TAURI__).

const PROTOCOL_COLORS = {
  TCP: '#4a9ef5', UDP: '#45d1c5', DNS: '#a78bfa', HTTP: '#34d399',
  TLS: '#6ee7b7', ICMP: '#fbbf24', ARP: '#9ca3af',
  DHCP: '#f9a825', NTP: '#38bdf8', mDNS: '#c084fc',
  SNMP: '#facc15', QUIC: '#2dd4bf', SIP: '#818cf8',
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
// Pick a sensible starting UI language from the browser locale, falling back to
// English. The user's explicit choice (persisted in settings) always wins.
function detectDefaultLang() {
  const supported = ['en', 'de', 'fr', 'it', 'pt', 'ar', 'tr'];
  const nav = ((typeof navigator !== 'undefined' && navigator.language) || 'en').slice(0, 2).toLowerCase();
  return supported.includes(nav) ? nav : 'en';
}

// ---- Themes (customizable UX — VS Code-style and friends) ----
// Each theme overrides the core CSS custom properties defined in styles.css.
// Protocol accent colours (--tcp, --udp, …) are left alone so packet colouring
// stays recognisable across themes.
const THEMES = {
  midnight: { '--bg': '#0f1520', '--bg-elev': '#161d2b', '--bg-elev-2': '#1c2536', '--border': '#2a3547', '--text': '#e6ebf2', '--text-muted': '#8b98ab', '--accent': '#4a9ef5' },
  vscode:   { '--bg': '#1e1e1e', '--bg-elev': '#252526', '--bg-elev-2': '#2d2d30', '--border': '#3c3c3c', '--text': '#d4d4d4', '--text-muted': '#858585', '--accent': '#007acc' },
  dracula:  { '--bg': '#282a36', '--bg-elev': '#2f3140', '--bg-elev-2': '#383a4a', '--border': '#44475a', '--text': '#f8f8f2', '--text-muted': '#9aa0b5', '--accent': '#bd93f9' },
  nord:     { '--bg': '#2e3440', '--bg-elev': '#3b4252', '--bg-elev-2': '#434c5e', '--border': '#4c566a', '--text': '#eceff4', '--text-muted': '#9aa5b8', '--accent': '#88c0d0' },
  light:    { '--bg': '#f4f6fa', '--bg-elev': '#ffffff', '--bg-elev-2': '#eef1f6', '--border': '#d3d9e3', '--text': '#1c2430', '--text-muted': '#5c6675', '--accent': '#2563eb' },
};
function applyTheme(name) {
  const t = THEMES[name] || THEMES.midnight;
  const root = document.documentElement;
  for (const [k, v] of Object.entries(t)) root.style.setProperty(k, v);
  root.dataset.theme = name;
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
  // Workspace modes — "self-configuring" presets that adapt netscope to the task
  // (filter + view + noise filter + display), the way you'd expect Wireshark to
  // set itself up if you told it what you were doing today.
  'Web Dev': {
    filter: 'http or tls or dns', view: 'topology', timeFormat: 'time', showHostnames: true, noiseFilter: true,
    hint: 'Web/API work: web + DNS traffic on the topology map, OS-update noise hidden. Good for watching what a page or API actually calls.',
  },
  'Kernel / Driver Dev': {
    filter: '', view: 'packets', timeFormat: 'relative', showHostnames: false, noiseFilter: false,
    hint: 'Low-level work: raw IPs, relative timestamps, everything shown (nothing filtered) so you don\'t miss a stray frame.',
  },
  'IoT': {
    filter: 'udp or arp or icmp', view: 'topology', timeFormat: 'time', showHostnames: true, noiseFilter: false,
    hint: 'IoT/device discovery: the chatty broadcast/UDP protocols devices use, drawn as a device map.',
  },
  'Malware Analysis': {
    filter: '', view: 'insights', timeFormat: 'datetime', showHostnames: true, noiseFilter: false,
    hint: 'Threat hunting: opens straight into Insights (signatures, beaconing, exfil) with full timestamps for your report.',
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
    topTalkersSent: [], topDomains: [], errorPackets: 0,
  },
  // Time Display Format: 'time' (HH:MM:SS.mmm), 'datetime' (date + time),
  // 'relative' (seconds since the first packet of this capture session).
  settings: Object.assign({ timeFormat: 'time', showHostnames: true, profile: 'HTTP Analysis', theme: 'midnight', noiseFilter: false, lang: detectDefaultLang(), geoip: false }, loadJSON('netscope.settings', {})),
  customProfiles: loadJSON('netscope.profiles', {}),
  captureStartEpoch: null,
  // Live dashboard sampling (1 Hz): rolling history for the sparkline widgets.
  live: {
    lastSample: null,                 // { packets, bytes, errors, t }
    throughput: [], pps: [], errRate: [], // ring buffers, newest last
    timer: null,
  },
  hostsSeen: new Set(),               // distinct IPs, for "active hosts" + topology
  topo: { layout: new Map(), frozen: false, lastBuilt: 0, view: null },
  diff: { a: null, b: null },
  alerts: [], alertsSeen: 0,          // Smart Alerts feed
  triggers: loadJSON('netscope.triggers', []), // Event triggers (IFTTT)
  reportRaw: '',
};
const LIVE_HISTORY = 60; // seconds of sparkline history

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
    state.stats = { totalPackets: 0, totalBytes: 0, perProtocol: {}, topTalkersSent: [], topDomains: [], errorPackets: 0 };
    state.hostsSeen.clear();
    state.live.lastSample = null; state.live.throughput = []; state.live.pps = []; state.live.errRate = [];
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
  els.statusText.textContent = s === STATES.CAPTURING ? I18N.t('status.capturing') : I18N.t('status.idle');
  els.statusText.className = s === STATES.CAPTURING ? 'status-capturing' : 'status-idle';
}

// ---- Packet ingest ----
function onPacket(event) {
  const pkt = event.payload;
  state.packets.push(pkt);
  if (state.packets.length > 10000) state.packets.shift();
  state.packetCount++;
  els.packetCount.textContent = `${state.packetCount} ${I18N.t('unit.packets')}`;

  updateStats(pkt);
  updateFlow(pkt);
  if (state.triggers.length) evaluateTriggers(pkt);

  if (state.view === 'packets') renderPacketList();
  else if (state.view === 'connections') renderConnections();
  else if (state.view === 'dashboard') renderStats();
  else if (state.view === 'topology') renderTopology();
  else if (state.view === 'script') updateScriptCount();
}

// ---- Flow aggregation (Connections view) ----
function transportOf(proto) {
  if (['TCP', 'HTTP', 'TLS'].includes(proto)) return 'tcp';
  if (['UDP', 'DNS', 'DHCP', 'NTP', 'mDNS', 'SNMP', 'QUIC', 'SIP'].includes(proto)) return 'udp';
  if (proto === 'ICMP') return 'icmp';
  if (proto === 'ARP') return 'arp';
  return 'other';
}
function protoRank(proto) {
  if (proto === 'HTTP') return 4;
  if (['TLS', 'DNS', 'DHCP', 'NTP', 'mDNS', 'SNMP', 'QUIC', 'SIP'].includes(proto)) return 3;
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
      (state.elevated ? '' : ` · <span style="color:var(--warn)">${esc(I18N.t('conn.admin'))}</span>`)
    : I18N.t('conn.empty');

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

// ---- Clipboard helper (works in the Tauri webview and the browser preview) ----
async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through to legacy path */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch { return false; }
}

// ---- Copy as cURL — turn a captured HTTP request into a runnable cURL command ----
function packetToCurl(pkt) {
  const payload = extractPayload(pkt.raw || []);
  if (!payload) return null;
  const text = decodeStreamText(payload);
  const lines = text.split(/\r?\n/);
  const req = lines[0].match(/^([A-Z]+)\s+(\S+)\s+HTTP\/\d/);
  if (!req) return null; // not an HTTP request (probably a response or non-HTTP)
  const method = req[1];
  let path = req[2];

  const headers = [];
  let host = pkt.dst_host || pkt.dst_addr || 'host';
  let i = 1;
  for (; i < lines.length; i++) {
    if (lines[i] === '') { i++; break; } // blank line ends headers
    const h = lines[i].match(/^([!#$%&'*+\-.^_`|~0-9A-Za-z]+):\s?(.*)$/);
    if (!h) continue;
    if (h[1].toLowerCase() === 'host') host = h[2].trim();
    else headers.push([h[1], h[2]]);
  }
  const body = lines.slice(i).join('\n').replace(/\n+$/, '');

  const scheme = (pkt.dst_port === 443 || pkt.protocol === 'TLS') ? 'https' : 'http';
  const sq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`; // safe single-quote for shells
  let cmd = `curl -X ${method} ${sq(scheme + '://' + host + path)}`;
  for (const [k, v] of headers) cmd += ` \\\n  -H ${sq(k + ': ' + v)}`;
  if (body) cmd += ` \\\n  --data-raw ${sq(body)}`;
  return cmd;
}

async function copyCurl() {
  const pkt = state.filteredPackets[state.selectedIndex];
  if (!pkt) return;
  const curl = packetToCurl(pkt);
  if (!curl) { flashButton(els.curlCopy, '✖ not an HTTP request'); return; }
  const ok = await copyText(curl);
  flashButton(els.curlCopy, ok ? '✓ Copied' : '✖ Copy failed');
}

// Briefly show feedback text on a button, then restore its label.
function flashButton(btn, msg) {
  if (!btn) return;
  const prev = btn.dataset.label || btn.textContent;
  btn.dataset.label = prev;
  btn.textContent = msg;
  clearTimeout(btn._flash);
  btn._flash = setTimeout(() => { btn.textContent = btn.dataset.label; }, 1600);
}

// ---- Capture report — a shareable Markdown summary ----
function buildReport() {
  const pkts = state.packets;
  const s = state.stats;
  const now = new Date();
  const L = [];
  L.push(`# netscope capture report`);
  L.push('');
  L.push(`_Generated ${now.toISOString().replace('T', ' ').slice(0, 19)} · ${pkts.length} packets · ${formatBytes(s.totalBytes)}_`);
  L.push('');

  // Findings
  const findings = analyzeCapture(pkts);
  L.push(`## Security & privacy findings`);
  if (findings.length) {
    for (const f of findings) {
      L.push(`- **[${f.severity.toUpperCase()}]** ${f.title} — ${f.detail}`);
      for (const e of f.evidence) L.push(`  - \`${e}\``);
    }
  } else {
    L.push(`_Nothing notable found._`);
  }
  L.push('');

  // Protocol breakdown
  const protos = Object.entries(s.perProtocol).sort((a, b) => b[1].total_packets - a[1].total_packets);
  if (protos.length) {
    L.push(`## Protocol breakdown`);
    L.push(`| Protocol | Packets | Bytes |`);
    L.push(`|---|--:|--:|`);
    for (const [p, st] of protos) L.push(`| ${p} | ${st.total_packets} | ${formatBytes(st.total_bytes)} |`);
    L.push('');
  }

  // Top talkers
  if (s.topTalkersSent.length) {
    L.push(`## Top talkers (bytes sent)`);
    L.push(`| Host | Bytes |`);
    L.push(`|---|--:|`);
    for (const [ip, b] of s.topTalkersSent.slice(0, 10)) L.push(`| ${ip} | ${formatBytes(b)} |`);
    L.push('');
  }

  // Top domains
  if (s.topDomains.length) {
    L.push(`## Top domains`);
    for (const [d, n] of s.topDomains.slice(0, 12)) L.push(`- ${d} (${n})`);
    L.push('');
  }

  // Automated dependency map — which external services this app/host talks to.
  const deps = buildDependencyTree();
  if (deps.size) {
    L.push(`## Dependency map (external services)`);
    const order = [...deps.entries()].sort((a, b) => b[1].size - a[1].size);
    for (const [svc, hosts] of order) {
      L.push(`- **${svc}**`);
      for (const [host, ips] of hosts) L.push(`  - ${host}${host !== [...ips][0] ? ` (${[...ips].join(', ')})` : ''}`);
    }
    L.push('');
  }

  // Connections
  const flows = [...state.flows.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 20);
  if (flows.length) {
    L.push(`## Connections (top ${flows.length} by bytes)`);
    L.push(`| Client | Server | Proto | Pkts | Bytes |`);
    L.push(`|---|---|---|--:|--:|`);
    for (const f of flows) {
      const server = f.serverHost ? `${f.serverHost} (${f.serverAddr})` : f.serverAddr;
      L.push(`| ${endpointLabel(f.clientAddr, null, f.clientPort)} | ${server}${f.serverPort != null ? ':' + f.serverPort : ''} | ${f.proto} | ${f.packets} | ${formatBytes(f.bytes)} |`);
    }
    L.push('');
  }

  L.push(`---`);
  L.push(`_Made with netscope — https://github.com/azzizefe/netscope_`);
  return L.join('\n');
}

function renderReportBody() {
  const scrub = els.reportScrub && els.reportScrub.checked;
  const anon = els.reportAnon && els.reportAnon.checked;
  let text = state.reportRaw || '';
  if (scrub) text = scrubText(text);
  if (anon) text = anonymizeIps(text).text;
  els.reportBody.textContent = text;
  const parts = [];
  if (scrub) parts.push('secrets masked');
  if (anon) parts.push('IPs anonymised');
  els.reportStatus.textContent = parts.length
    ? `🛡 Sanitised (${parts.join(' + ')}) — safe to share.`
    : '⚠ Raw — may contain sensitive strings. Markdown — paste into an issue, doc, or chat.';
}
// A short, plain-language TL;DR — the "kısaca özet" the full report isn't.
function buildQuickSummary() {
  const pkts = state.packets;
  const s = state.stats;
  const L = [];
  L.push(`# Quick summary`);
  const span = pkts.length && pkts[0].epoch_ms != null ? (pkts[pkts.length - 1].epoch_ms - pkts[0].epoch_ms) / 1000 : 0;
  L.push(`- **${pkts.length.toLocaleString()} packets**, ${formatBytes(s.totalBytes)}${span ? `, over ${span.toFixed(0)} s` : ''}, ${state.hostsSeen.size} hosts.`);

  const sites = analyzePrivacy(pkts);
  if (sites.length) {
    const top = sites.slice(0, 3).map((x) => `${x.host} (${formatBytes(x.total)})`).join(', ');
    L.push(`- **Top sites:** ${top}.`);
    const trk = sites.filter((x) => x.tracker && x.tracker.cat !== 'CDN').length;
    const cookies = sites.reduce((a, x) => a + x.cookiesSet.size, 0);
    if (trk || cookies) L.push(`- **Privacy:** ${trk} tracker${trk === 1 ? '' : 's'}, ${cookies} cookie${cookies === 1 ? '' : 's'} seen.`);
    const waf = sites.filter((x) => x.waf || x.wafInferred);
    if (waf.length) L.push(`- **WAF:** ${waf.map((x) => `${x.host} → ${x.waf || x.wafInferred + ' (likely)'}`).join(', ')}.`);
    const errs = sites.filter((x) => x.errors);
    if (errs.length) L.push(`- **Errors:** ${errs.map((x) => `${x.host} ${[...x.errors].map(([c, n]) => `${n}×${c}`).join(' ')}`).join('; ')}.`);
    const risky = sites.filter((x) => x.risk && x.risk.level !== 'low').sort((a, b) => b.risk.score - a.risk.score)[0];
    if (risky) L.push(`- **Highest risk:** ${risky.host} (score ${risky.risk.score}) — ${risky.risk.reasons.join(', ')}.`);
  }
  const b = analyzeBusiest(pkts);
  if (b) L.push(`- **Busiest:** ${pad(b.peakStart.getHours())}:${pad(b.peakStart.getMinutes())}:${pad(b.peakStart.getSeconds())} (${formatBytes(b.peakBytes)} in that window).`);

  const findings = analyzeCapture(pkts).filter((f) => f.severity === 'high' || f.severity === 'warn').slice(0, 4);
  if (findings.length) {
    L.push('');
    L.push(`**Top findings:**`);
    for (const f of findings) L.push(`- ${f.icon} ${f.title}`);
  } else {
    L.push(`- No high/warning security findings.`);
  }
  return L.join('\n');
}
function openSummary() {
  if (!state.packets.length) { flashButton(els.summaryOpen, 'Nothing captured yet'); return; }
  state.reportRaw = buildQuickSummary();
  renderReportBody();
  els.reportModal.classList.remove('hidden');
}
function openReport() {
  if (!state.packets.length) { flashButton(els.reportOpen, 'Nothing captured yet'); return; }
  state.reportRaw = buildReport();
  renderReportBody();
  els.reportModal.classList.remove('hidden');
}
function closeReport() { els.reportModal.classList.add('hidden'); }
async function copyReport() {
  const ok = await copyText(els.reportBody.textContent);
  flashButton(els.reportCopy, ok ? '✓ Copied' : '✖ Failed');
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
  // Prefer the structured display-filter language (ip.addr == x, tcp.port ==
  // 443, dns && frame.len > 1000). If the text isn't a valid filter
  // expression, fall back to the free-text substring search so partial input
  // and plain keywords still filter.
  let packets;
  if (state.filterText) {
    const compiled = typeof NetscopeFilter !== 'undefined'
      ? NetscopeFilter.compile(state.filterText)
      : null;
    packets = compiled
      ? state.packets.filter((p) => compiled.matches(p))
      : state.packets.filter((p) => matchesFilter(p, state.filterText));
  } else {
    packets = state.packets;
  }
  if (state.settings.noiseFilter) packets = packets.filter((p) => !isNoise(p));
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
      `<span class="tval geo-status">${state.settings.geoip ? 'Looking up…' : esc(I18N.t('geoip.off'))}</span></div></div></div>`);
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

  // Protocol guesser — for traffic the dissector couldn't name (obfuscated /
  // non-standard ports), suggest what it most likely is and show the reasoning.
  if (pkt.protocol === 'Unknown' || (['TCP', 'UDP'].includes(pkt.protocol) && (pkt.raw || []).length > 42)) {
    const g = guessProtocol(pkt);
    if (g) {
      const pct = Math.round(g.confidence * 100);
      nodes.push(`<div class="tnode tnode-guess"><div class="tnode-head">` +
        `<span class="twist">▾</span><span class="tlabel">🔮 Protocol guess <span class="tlabel-sub">${esc(g.label)} · ${pct}% confidence</span></span></div>` +
        `<div class="tbody">${g.reasons.map((r) => `<div class="tfield"><span class="tkey">•</span><span class="tval">${esc(r)}</span></div>`).join('')}</div></div>`);
    }
  }

  // Semantic Log Parsing — the business-logic meaning of this packet.
  const events = semanticEvents(pkt);
  if (events.length) {
    nodes.push(`<div class="tnode tnode-semantic"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">🧩 What happened</span></div>` +
      `<div class="tbody">${events.map((e) => `<div class="tfield"><span class="tkey">${e.icon}</span><span class="tval">${esc(e.text)}</span></div>`).join('')}</div></div>`);
  }

  // Dynamic Payload Beautifier — JSON/XML rendered as a coloured tree.
  const beauty = beautifyPayload(pkt.raw && pkt.raw.length ? decodeStreamText(extractPayload(pkt.raw) || []) : '');
  if (beauty) {
    nodes.push(`<div class="tnode tnode-beauty"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">✨ Payload (${beauty.kind}) <span class="tlabel-sub">beautified</span></span></div>` +
      `<div class="tbody jt-root">${beauty.html}</div></div>`);
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
  const ip = node.dataset.ip;
  body.innerHTML = rows.map(([k, v]) =>
    `<div class="tfield"><span class="tkey">${esc(k)}</span><span class="tval">${esc(v)}</span></div>`).join('') +
    threatIntelRow(ip);
}

// ---- Threat intelligence pivots — one-click reputation checks for an IP ----
// netscope makes no silent calls to paid feeds; instead it gives you direct,
// pre-filled links into the reputation services you already trust.
function threatIntelRow(ip) {
  if (!ip) return '';
  const e = encodeURIComponent(ip);
  const links = [
    ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${e}`],
    ['AbuseIPDB', `https://www.abuseipdb.com/check/${e}`],
    ['AlienVault OTX', `https://otx.alienvault.com/indicator/ip/${e}`],
    ['Shodan', `https://www.shodan.io/host/${e}`],
  ];
  return `<div class="tfield"><span class="tkey">Reputation</span><span class="tval ti-links">` +
    links.map(([n, u]) => `<a href="${u}" target="_blank" rel="noreferrer noopener" class="ti-link">${n} ↗</a>`).join('') +
    `</span></div>`;
}

async function enrichGeo(pkt) {
  // Opt-in only: netscope makes no external calls unless the user turns this on.
  if (!state.settings.geoip) return;
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
  const sum = pkt.summary || '';
  if (sum.includes('reset (RST)') || sum.includes('Malformed')) s.errorPackets++;
  if (pkt.src_addr) state.hostsSeen.add(pkt.src_addr);
  if (pkt.dst_addr) state.hostsSeen.add(pkt.dst_addr);
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
  if (els.statProjection) {
    const proj = projectBandwidth();
    els.statProjection.textContent = proj
      ? `${fmtRate(proj.in5min).join(' ')} (${proj.trend}) · ~${formatBytes(proj.bytes5min)}`
      : '— (need a few seconds of data)';
  }

  const protos = Object.entries(s.perProtocol).sort((a, b) => b[1].total_packets - a[1].total_packets);
  const max = protos.length ? protos[0][1].total_packets : 1;
  els.protoBars.innerHTML = protos.map(([p, st]) => {
    const c = protoColor(p);
    const pct = s.totalPackets ? ((st.total_packets / s.totalPackets) * 100).toFixed(1) : '0';
    return `<div class="proto-bar-row"><span class="proto-label" style="color:${c}">${p}</span>
      <div class="proto-bar-bg"><div class="proto-bar-fill" style="width:${(st.total_packets / max) * 100}%;background:${c}"></div></div>
      <span class="proto-pct">${pct}%</span></div>`;
  }).join('') || '<div style="color:var(--text-muted);font-size:12px">No data</div>';

  els.talkerList.innerHTML = s.topTalkersSent.slice(0, 10).map(([ip, b]) =>
    `<div class="talker-item"><span class="talker-ip">${ip}</span><span class="talker-bytes">${formatBytes(b)}</span></div>`
  ).join('') || '<div style="color:var(--text-muted);font-size:12px">No data</div>';

  els.dnsList.innerHTML = s.topDomains.slice(0, 12).map(([d, n]) =>
    `<div class="dns-item"><span class="dns-domain">${d}</span><span class="dns-count">${n}</span></div>`
  ).join('') || '<div style="color:var(--text-muted);font-size:12px">No domains</div>';

  renderBusiest();
}

function renderBusiest() {
  if (!els.busiestPeak) return;
  const b = analyzeBusiest(state.packets);
  if (!b) { els.busiestPeak.textContent = '—'; els.busiestChart.innerHTML = ''; els.busiestHint.textContent = 'No timed traffic yet.'; return; }
  const fmt = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  els.busiestPeak.innerHTML = `Peak: <b>${fmt(b.peakStart)}–${fmt(b.peakEnd)}</b> · ${formatBytes(b.peakBytes)}`;
  const W = 300, H = 60, max = Math.max(...b.buckets, 1), n = b.buckets.length, bw = W / n;
  els.busiestChart.innerHTML = b.buckets.map((v, i) => {
    const h = (v / max) * (H - 4);
    const peak = v === b.peakBytes;
    return `<rect x="${(i * bw).toFixed(1)}" y="${(H - h).toFixed(1)}" width="${Math.max(bw - 1, 1).toFixed(1)}" height="${h.toFixed(1)}" fill="${peak ? 'var(--danger)' : 'var(--accent)'}" opacity="${peak ? 1 : 0.6}"/>`;
  }).join('');
  els.busiestHint.textContent = b.longEnough
    ? `Busiest hour-of-day: ${pad(b.peakHour)}:00 (capture spans ${(b.spanMs / 3600000).toFixed(1)} h)`
    : 'Capture a few hours+ to reveal daily/weekly patterns.';
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
  {
    icon: '🕸', color: 'var(--tcp)', title: 'Topology Map',
    gist: 'Watch the network draw itself as a graph.',
    body: 'The 🕸 Topology tab plots every host as a node and every conversation as an edge, live. Circle size scales with traffic, green nodes are on your local network, blue nodes are remote. It settles into a stable layout — hit ⤢ Fit to reframe, or Freeze to stop it moving.',
    look: 'Hover a node for its hostname and byte total. A single node with many edges is either a busy server or, sometimes, a host scanning everything.',
  },
  {
    icon: '📊', color: 'var(--udp)', title: 'Live Dashboard',
    gist: 'Throughput, packets/sec and error-rate sparklines.',
    body: 'The Dashboard now updates every second with "Grafana-style" tiles: instant throughput, packets per second, error rate, and active host count — each with a 60-second sparkline so you can see spikes as they happen, plus the top-10 talkers.',
    look: 'A climbing error-rate spark usually means resets or malformed frames — cross-check it in the 🛡 Insights tab.',
  },
  {
    icon: '🔀', color: 'var(--dns)', title: 'Traffic Diff',
    gist: 'Compare "before" and "during" an incident.',
    body: 'In the 🔀 Diff tab, take Snapshot A as a baseline, let traffic change, then take Snapshot B and Compare. netscope shows the delta — which protocols and hosts appeared, grew, or vanished between the two moments — instead of making you eyeball two captures.',
    look: 'Great for "what changed the instant the alert fired?" — NEW/GONE tags call out endpoints that only exist in one snapshot.',
  },
  {
    icon: '🧷', color: 'var(--danger)', title: 'Signature & DLP scan',
    gist: 'Match payloads against known-bad indicators.',
    body: 'Insights now runs a transparent YARA-lite signature set over payloads (Log4Shell, Shellshock, reverse shells, SQLi, scanner User-Agents, EICAR and more) and flags large outbound transfers from a local host — the classic shape of data exfiltration (DLP).',
    look: 'Every signature is readable in the code — no black box. Matches show the endpoints involved so you can pivot straight to them.',
  },
  {
    icon: '🔮', color: 'var(--dns)', title: 'Protocol Guesser',
    gist: 'Identify obfuscated / non-standard traffic.',
    body: 'Open a TCP/UDP packet the dissector couldn\'t name and look for the 🔮 Protocol guess layer. It combines port hints, byte "magic", printable-text ratio and Shannon entropy to suggest what the payload most likely is — and shows its reasoning and a confidence score.',
    look: 'High entropy (>7.5 bits/byte) means encrypted or compressed; mostly-printable means a text protocol.',
  },
  {
    icon: '🌐', color: 'var(--tls)', title: 'Threat Intel pivots',
    gist: 'One-click reputation checks for any IP.',
    body: 'Open a packet to a public IP and the 🌍 location layer now includes a Reputation row with pre-filled links to VirusTotal, AbuseIPDB, AlienVault OTX and Shodan. netscope never quietly calls paid feeds — it hands you a direct link into the services you already trust.',
    look: 'Use it the moment a host looks suspicious in the Topology map or Insights.',
  },
  {
    icon: '🛡', color: 'var(--ok)', title: 'Report scrubbing (GDPR/KVKK)',
    gist: 'Mask secrets before you share a report.',
    body: 'The 📄 Export report dialog has a "Scrub sensitive data" toggle (on by default). It masks passwords, tokens, emails and card numbers in the Markdown before you copy it, so a shared report can\'t leak the very credentials it found.',
    look: 'Toggle it off to see the raw report — the status line tells you which mode you\'re in.',
  },
  {
    icon: '🎨', color: 'var(--accent)', title: 'Themes',
    gist: 'VS Code Dark+, Dracula, Nord, Light and more.',
    body: 'Pick a theme in the 🗂 Profile menu. Beyond the default Midnight, there\'s a VS Code Dark+ look, Dracula, Nord, and a Daylight light mode. Your choice is remembered next time you open netscope.',
    look: 'Protocol colours stay consistent across themes so packet colouring is always recognisable.',
  },
  {
    icon: '🧩', color: 'var(--http)', title: 'Semantic parsing',
    gist: 'Reads the meaning, not just the bytes.',
    body: 'Open a packet and the "🧩 What happened" layer translates it into business logic: "Client asked example.com to GET /login", "Request requires authentication (401)", "Starting an encrypted session (TLS ClientHello)", "A user presented credentials".',
    look: 'Turns a wall of hex into a plain sentence about what the two machines were actually doing.',
  },
  {
    icon: '✨', color: 'var(--tls)', title: 'Payload Beautifier',
    gist: 'JSON & XML as a collapsible colour tree.',
    body: 'When a packet carries JSON or XML, the "✨ Payload" layer renders it as a syntax-coloured, collapsible tree instead of a cramped one-liner. Click any node to fold it.',
    look: 'Great for REST/GraphQL debugging — the response body is readable at a glance.',
  },
  {
    icon: '🔔', color: 'var(--warn)', title: 'Smart Alerts & Triggers',
    gist: 'Proactive notifications + your own IFTTT rules.',
    body: 'The 🔔 bell (top bar) collects alerts: traffic spikes and error bursts netscope spots on its own, plus your own Event Triggers — "host contains 185.220 → alert", "length ≥ 100000 → alert". Rules persist across restarts.',
    look: 'Add a trigger in the bell popover; the badge counts unseen alerts.',
  },
  {
    icon: '📶', color: 'var(--danger)', title: 'Threat-actor heuristics',
    gist: 'Beaconing & suspect-port detection.',
    body: 'Insights flags C2-shaped behaviour: a host contacted at very regular intervals (classic malware "phone home"), and traffic on ports historically tied to backdoors/botnets. Honest heuristics — a prompt to look, not an accusation.',
    look: 'Regular-interval beaconing is the tell; the finding shows the interval and destination.',
  },
  {
    icon: '💡', color: 'var(--accent)', title: 'One-click exploit demo',
    gist: 'How a finding could be abused — and fixed.',
    body: 'Each Insights finding that can be exploited gets a "💡 How could this be exploited?" expander with a plain-language attack scenario and the concrete fix. Learn *why* it matters, not just that it\'s flagged.',
    look: 'Educational — built for teaching, not for attacking.',
  },
  {
    icon: '🧬', color: 'var(--dns)', title: 'Dependency map & code export',
    gist: 'Services an app talks to + hex→C/Rust/Python.',
    body: 'The 📄 report now includes an automated dependency map (which services — Google, AWS/CloudFront, Cloudflare… — a host reaches). And the Bytes pane has Copy-as C / Rust / Python buttons to turn a payload into a code literal.',
    look: 'The 🕶 Anonymize IPs and 🛡 Scrub toggles make that report safe to share (GDPR/KVKK).',
  },
  {
    icon: '🔎', color: 'var(--danger)', title: 'Privacy X-ray',
    gist: 'What each site takes from you, and its data cost.',
    body: 'The 🔎 Privacy tab groups traffic by site and answers the human question Wireshark won\'t: what you send it (cookies, User-Agent, Referer, form data, email, location), which trackers/ad networks it calls behind your back, the cookies it sets (tracking cookies and weak Secure/HttpOnly/SameSite flags flagged), and how much of your data — up and down — it actually cost. A meter shows what share went to trackers.',
    look: 'Encrypted (HTTPS) sites hide their content, but the tab still shows who was contacted, the trackers, and the data volume — the metadata HTTPS doesn\'t protect.',
  },
  {
    icon: '🛡', color: 'var(--ok)', title: 'WAF, errors & site health',
    gist: 'Is there a firewall? Why the 403? When is it busy?',
    body: 'The 🔎 Privacy tab now fingerprints Web Application Firewalls (Cloudflare, Akamai, Imperva, AWS, F5, ModSecurity…) from response headers, explains HTTP errors in plain words (why a 403/429/502 happened), shows a 0–100 risk score per site, and flags outdated servers with a known CVE. The Dashboard "Busiest Period" card shows when traffic peaked, and 🛡 Insights → 📋 Quick summary gives a short TL;DR you can paste anywhere.',
    look: 'A 403 with a WAF badge usually means the firewall blocked the request — not that you\'re logged out.',
  },
  {
    icon: '🧭', color: 'var(--udp)', title: 'Workspace modes',
    gist: 'netscope configures itself for the task.',
    body: 'The 🗂 Profile menu adds self-configuring workspaces — Web Dev, Kernel / Driver Dev, IoT, Malware Analysis — each setting the right filter, starting view, timestamps and noise filter in one click. Plus a "Hide OS/update noise" toggle (Zero-touch) that strips update/telemetry chatter.',
    look: 'Pick "Malware Analysis" and netscope opens on Insights with full timestamps, ready to hunt.',
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
  if (p.noiseFilter !== undefined) state.settings.noiseFilter = !!p.noiseFilter;
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
  if (els.noiseFilterCheck) els.noiseFilterCheck.checked = !!state.settings.noiseFilter;
  if (els.geoipCheck) els.geoipCheck.checked = !!state.settings.geoip;
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
  if (!html) html = `<div class="script-empty">${esc(I18N.t('script.empty'))}</div>`;
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

  // 6b. Signature matches (YARA-lite) — known-bad indicators in payloads.
  for (const h of scanSignatures(pkts)) {
    add(h.sig.sev === 'high' ? 'high' : 'warn', '🧷', `Signature match: ${h.sig.name} (${h.count}×)`,
      'A payload matched a known malicious/attack indicator. Investigate the endpoints involved.',
      [...h.samples]);
  }

  // 6c. Data exfiltration (DLP) — large outbound transfers from a local host to a
  // remote destination. Uses the connection flows: bytes a private host pushed out.
  const exfil = new Map(); // "local -> remote" -> bytes
  for (const f of state.flows.values()) {
    if (!f.clientAddr || !f.serverAddr) continue;
    if (!isPublicIp(f.clientAddr) && isPublicIp(f.serverAddr)) {
      const key = `${f.clientAddr}|${f.serverHost || f.serverAddr}`;
      exfil.set(key, (exfil.get(key) || 0) + f.bytes);
    }
  }
  const EXFIL_BYTES = 2 * 1024 * 1024; // 2 MB from one host to one destination
  const bigUploads = [...exfil.entries()].filter(([, b]) => b >= EXFIL_BYTES).sort((a, b) => b[1] - a[1]);
  for (const [pair, b] of bigUploads.slice(0, 5)) {
    const [src, dst] = pair.split('|');
    add('warn', '📤', `Large outbound transfer: ${src} → ${dst} (${formatBytes(b)})`,
      'A local host sent an unusually large amount of data to a single external destination. Normal for backups/uploads, but this is the classic shape of data exfiltration — confirm it is expected.');
  }

  // 6d. Threat-actor heuristics — beaconing intervals + suspect ports (NOT real
  // attribution; flags automation/C2-shaped behaviour worth a human look).
  for (const b of detectBeaconing(pkts)) {
    add('warn', '📶', `Possible beaconing to ${b.dst} (every ~${b.interval}s, ${b.count}×)`,
      'This host was contacted at very regular intervals — the signature of an automated agent or malware "phoning home" (C2). Legitimate for some apps (polling, keep-alives); confirm what it is.');
  }
  const suspectSeen = new Map();
  for (const [pair, ports] of portsPerTarget) for (const port of ports) if (SUSPECT_PORTS[port]) suspectSeen.set(port, SUSPECT_PORTS[port]);
  if (suspectSeen.size) {
    add('warn', '🚩', `Traffic on ${suspectSeen.size} suspect port${suspectSeen.size > 1 ? 's' : ''}`,
      'These ports are historically associated with backdoors/botnet C2. Not proof of anything, but unusual on a normal network.',
      [...suspectSeen.entries()].map(([p, n]) => `port ${p} — ${n}`));
  }

  // 6e. Site posture — WAF presence, HTTP error reasons, service CVEs.
  const siteData = analyzePrivacy(pkts);
  const wafSites = siteData.filter((s) => s.waf || s.wafInferred);
  if (wafSites.length) {
    add('info', '🛡', `WAF detected on ${wafSites.length} site${wafSites.length > 1 ? 's' : ''}`,
      'A Web Application Firewall sits in front of these sites (helps explain blocks/403s and rate-limits). "likely" entries are inferred from the fronting CDN, not confirmed headers.',
      wafSites.slice(0, 6).map((s) => `${s.host} — ${s.waf || s.wafInferred + ' (likely)'}`));
  }
  for (const s of siteData) {
    if (!s.errors) continue;
    for (const [code, n] of s.errors) {
      if (![401, 403, 404, 429, 500, 502, 503, 504].includes(code)) continue;
      add(code >= 500 ? 'warn' : 'info', '🚫', `${s.host}: ${n}× HTTP ${code} ${HTTP_STATUS_TEXT[code] || ''}`,
        HTTP_ERR_REASON[code] || 'Unusual HTTP status.');
    }
  }
  for (const s of siteData) {
    if (!s.server) continue;
    const cve = matchCVE(s.server);
    if (cve) add('warn', '🐛', `${s.host} exposes ${s.server}`, cve.desc, [cve.id]);
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

// One-Click Exploit Demo — for each kind of finding, a plain-language "how could
// this be abused, and how do you stop it" teaching scenario. Educational only.
const EXPLOIT_DEMOS = [
  { match: (t) => /credential sent in cleartext/i.test(t), scenario: 'An attacker on the same Wi-Fi or any hop between you and the server runs a passive sniffer (e.g. tcpdump). Because the login POST is plain HTTP, the username and password appear in the clear — they copy them and log in as you.', fix: 'Serve the site over HTTPS (TLS) and set HSTS so browsers refuse the plain-HTTP version.' },
  { match: (t) => /unencrypted http/i.test(t), scenario: 'A man-in-the-middle injects or rewrites the unencrypted response — swapping a download link, adding a script, or reading the page you viewed.', fix: 'Force HTTPS everywhere; redirect HTTP→HTTPS and add HSTS.' },
  { match: (t) => /port scan/i.test(t), scenario: 'The scan is reconnaissance: the attacker maps which services are open (SSH, RDP, databases) to pick a target for the next stage — a brute-force or an exploit against whatever answered.', fix: 'Firewall off unused ports, rate-limit, and alert on many-ports-one-host patterns (this finding).' },
  { match: (t) => /web traffic was encrypted|% of web traffic/i.test(t), scenario: 'The cleartext slice can be read and modified in transit. On a hostile network an attacker reads exactly which pages and data went unencrypted.', fix: 'Move the remaining plain-HTTP endpoints to HTTPS.' },
  { match: (t) => /Log4Shell/i.test(t), scenario: 'The ${jndi:...} string makes a vulnerable Log4j server fetch and run attacker-controlled Java from a remote LDAP/RMI server — full remote code execution.', fix: 'Patch Log4j to ≥2.17, and block outbound LDAP/RMI from servers.' },
  { match: (t) => /beaconing/i.test(t), scenario: 'Malware checks in with its command-and-control server on a timer to fetch instructions or exfiltrate data. The regular interval is what gives it away.', fix: 'Isolate the host, capture full payloads, and block the destination while you investigate.' },
  { match: (t) => /outbound transfer/i.test(t), scenario: 'This is what data theft looks like on the wire: a large, one-directional upload from an inside host to an outside server the org doesn\'t normally use.', fix: 'Confirm the transfer is sanctioned; if not, block the destination and rotate any credentials that host held.' },
];
function demoFor(title) { return EXPLOIT_DEMOS.find((d) => d.match(title)) || null; }
function demoDetails(title) {
  const d = demoFor(title);
  if (!d) return '';
  return `<details class="finding-demo"><summary>💡 How could this be exploited?</summary>` +
    `<div class="demo-scenario"><b>Scenario.</b> ${esc(d.scenario)}</div>` +
    `<div class="demo-fix"><b>Fix.</b> ${esc(d.fix)}</div></details>`;
}

function renderInsights() {
  const pkts = state.packets;
  if (!pkts.length) {
    els.insightsSummary.textContent = '';
    els.insightsList.innerHTML = `<div class="insights-empty">${esc(I18N.t('empty.capture'))}</div>`;
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
      ${demoDetails(f.title)}
    </div>`).join('') || `<div class="insights-empty">${esc(I18N.t('insights.nofindings'))}</div>`;
}

// ---- Live dashboard sampling (1 Hz) — "Grafana-style" metric tiles ----
// Sampled every second regardless of the active view so the sparkline history
// stays continuous; the DOM is only redrawn while the Dashboard is on screen.
function sampleLive() {
  const s = state.stats;
  const now = performance.now();
  const cur = { packets: s.totalPackets, bytes: s.totalBytes, errors: s.errorPackets, t: now };
  const prev = state.live.lastSample;
  state.live.lastSample = cur;
  if (!prev) return;
  const dt = Math.max((now - prev.t) / 1000, 0.001);
  const dPkts = Math.max(cur.packets - prev.packets, 0);
  const dBytes = Math.max(cur.bytes - prev.bytes, 0);
  const dErr = Math.max(cur.errors - prev.errors, 0);
  const push = (arr, v) => { arr.push(v); if (arr.length > LIVE_HISTORY) arr.shift(); };
  push(state.live.throughput, dBytes / dt);
  push(state.live.pps, dPkts / dt);
  push(state.live.errRate, dPkts ? (dErr / dPkts) * 100 : 0);
  checkAnomalies();
  if (state.view === 'dashboard') renderLive();
}
function sparkline(svg, data, color) {
  if (!svg) return;
  if (!data.length) { svg.innerHTML = ''; return; }
  const W = 120, H = 32, max = Math.max(...data, 1e-9);
  const step = data.length > 1 ? W / (data.length - 1) : W;
  const pts = data.map((v, i) => `${(i * step).toFixed(1)},${(H - (v / max) * (H - 3) - 1).toFixed(1)}`).join(' ');
  const area = `0,${H} ${pts} ${((data.length - 1) * step).toFixed(1)},${H}`;
  svg.innerHTML = `<polygon points="${area}" fill="${color}" opacity="0.14"/>` +
    `<polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>`;
}
function fmtRate(bps) {
  if (bps < 1024) return [`${bps.toFixed(0)}`, 'B/s'];
  if (bps < 1048576) return [`${(bps / 1024).toFixed(1)}`, 'KB/s'];
  return [`${(bps / 1048576).toFixed(2)}`, 'MB/s'];
}
function renderLive() {
  const L = state.live;
  const last = (a) => (a.length ? a[a.length - 1] : 0);
  const [tv, tu] = fmtRate(last(L.throughput));
  const setTile = (id, val, unit) => { const el = $(id); if (el) el.innerHTML = `${val} <span>${unit}</span>`; };
  setTile('#metric-throughput', tv, tu);
  setTile('#metric-pps', last(L.pps).toFixed(0), 'pps');
  setTile('#metric-errrate', last(L.errRate).toFixed(1), '%');
  setTile('#metric-hosts', state.hostsSeen.size, 'ip');
  sparkline($('#spark-throughput'), L.throughput, '#4a9ef5');
  sparkline($('#spark-pps'), L.pps, '#45d1c5');
  sparkline($('#spark-err'), L.errRate, '#f87171');
}

// ---- Topology map — live node/edge graph of who talks to whom ----
// A small force-directed layout over the connection flows. Node size ~ traffic,
// colour = local (private) vs. remote (public). Positions persist between rebuilds
// so the graph settles instead of jumping every second.
const TOPO_MAX_NODES = 60;
function buildTopologyGraph() {
  const nodeBytes = new Map();     // addr -> total bytes
  const nodeHost = new Map();      // addr -> hostname (if known)
  const edges = new Map();         // "a|b" -> bytes
  for (const f of state.flows.values()) {
    if (!f.clientAddr || !f.serverAddr) continue;
    nodeBytes.set(f.clientAddr, (nodeBytes.get(f.clientAddr) || 0) + f.bytes);
    nodeBytes.set(f.serverAddr, (nodeBytes.get(f.serverAddr) || 0) + f.bytes);
    if (f.serverHost) nodeHost.set(f.serverAddr, f.serverHost);
    const key = f.clientAddr < f.serverAddr ? `${f.clientAddr}|${f.serverAddr}` : `${f.serverAddr}|${f.clientAddr}`;
    edges.set(key, (edges.get(key) || 0) + f.bytes);
  }
  // Keep the busiest nodes so the picture stays readable.
  const keep = [...nodeBytes.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOPO_MAX_NODES);
  const kept = new Set(keep.map(([a]) => a));
  const nodes = keep.map(([addr, bytes]) => ({ addr, bytes, host: nodeHost.get(addr) || null, local: !isPublicIp(addr) }));
  const edgeList = [];
  for (const [key, bytes] of edges) {
    const [a, b] = key.split('|');
    if (kept.has(a) && kept.has(b)) edgeList.push({ a, b, bytes });
  }
  return { nodes, edges: edgeList };
}
function layoutTopology(graph) {
  const pos = state.topo.layout;
  const W = 1000, H = 640, cx = W / 2, cy = H / 2;
  const alive = new Set(graph.nodes.map((n) => n.addr));
  for (const k of [...pos.keys()]) if (!alive.has(k)) pos.delete(k);
  graph.nodes.forEach((n, i) => {
    if (!pos.has(n.addr)) {
      const ang = (i / Math.max(graph.nodes.length, 1)) * Math.PI * 2;
      pos.set(n.addr, { x: cx + Math.cos(ang) * 220 + (Math.random() - 0.5) * 40, y: cy + Math.sin(ang) * 220 + (Math.random() - 0.5) * 40 });
    }
  });
  if (state.topo.frozen || graph.nodes.length < 2) return { W, H };
  const ITER = 70, REP = 42000, SPRING = 0.012, IDEAL = 130;
  for (let it = 0; it < ITER; it++) {
    for (const n of graph.nodes) { const p = pos.get(n.addr); p.fx = 0; p.fy = 0; }
    // repulsion (all pairs)
    for (let i = 0; i < graph.nodes.length; i++) {
      const pi = pos.get(graph.nodes[i].addr);
      for (let j = i + 1; j < graph.nodes.length; j++) {
        const pj = pos.get(graph.nodes[j].addr);
        let dx = pi.x - pj.x, dy = pi.y - pj.y;
        let d2 = dx * dx + dy * dy || 0.01;
        const f = REP / d2;
        const d = Math.sqrt(d2);
        const ux = dx / d, uy = dy / d;
        pi.fx += ux * f; pi.fy += uy * f; pj.fx -= ux * f; pj.fy -= uy * f;
      }
    }
    // attraction along edges
    for (const e of graph.edges) {
      const pa = pos.get(e.a), pb = pos.get(e.b);
      let dx = pb.x - pa.x, dy = pb.y - pa.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = (d - IDEAL) * SPRING;
      const ux = dx / d, uy = dy / d;
      pa.fx += ux * f * d; pa.fy += uy * f * d; pb.fx -= ux * f * d; pb.fy -= uy * f * d;
    }
    // integrate + gentle pull to centre
    for (const n of graph.nodes) {
      const p = pos.get(n.addr);
      p.x += Math.max(-30, Math.min(30, p.fx * 0.9)) + (cx - p.x) * 0.008;
      p.y += Math.max(-30, Math.min(30, p.fy * 0.9)) + (cy - p.y) * 0.008;
    }
  }
  return { W, H };
}
function renderTopology(force = false) {
  const svg = els.topologySvg;
  if (!svg) return;
  const now = performance.now();
  if (!force && !state.topo.frozen && now - state.topo.lastBuilt < 1100) return; // throttle rebuilds
  state.topo.lastBuilt = now;

  const graph = buildTopologyGraph();
  els.topologySummary.textContent = graph.nodes.length
    ? `${graph.nodes.length} hosts · ${graph.edges.length} conversations`
    : I18N.t('topo.empty');
  if (!graph.nodes.length) { svg.innerHTML = ''; els.topologyLegend.innerHTML = ''; return; }

  layoutTopology(graph);
  const pos = state.topo.layout;
  // Bounding box → viewBox (auto-fit)
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of graph.nodes) { const p = pos.get(n.addr); minX = Math.min(minX, p.x); minY = Math.min(minY, p.y); maxX = Math.max(maxX, p.x); maxY = Math.max(maxY, p.y); }
  const pad = 60;
  svg.setAttribute('viewBox', `${minX - pad} ${minY - pad} ${(maxX - minX) + pad * 2} ${(maxY - minY) + pad * 2}`);

  const maxBytes = Math.max(...graph.nodes.map((n) => n.bytes), 1);
  const maxEdge = Math.max(...graph.edges.map((e) => e.bytes), 1);
  const nodeR = (b) => 6 + Math.sqrt(b / maxBytes) * 22;

  const edgeSvg = graph.edges.map((e) => {
    const pa = pos.get(e.a), pb = pos.get(e.b);
    const w = 0.6 + (e.bytes / maxEdge) * 4;
    return `<line x1="${pa.x.toFixed(1)}" y1="${pa.y.toFixed(1)}" x2="${pb.x.toFixed(1)}" y2="${pb.y.toFixed(1)}" stroke="var(--border)" stroke-width="${w.toFixed(2)}" stroke-opacity="0.55"/>`;
  }).join('');

  const nodeSvg = graph.nodes.map((n) => {
    const p = pos.get(n.addr);
    const r = nodeR(n.bytes);
    const fill = n.local ? 'var(--ok)' : 'var(--tcp)';
    const label = n.host || n.addr;
    const showLabel = r > 11 || n.local;
    const text = showLabel
      ? `<text x="${p.x.toFixed(1)}" y="${(p.y + r + 12).toFixed(1)}" class="topo-label">${esc(label.length > 26 ? label.slice(0, 24) + '…' : label)}</text>`
      : '';
    return `<g class="topo-node" data-ip="${esc(n.addr)}"><title>${esc(label)} · ${formatBytes(n.bytes)}</title>` +
      `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r.toFixed(1)}" fill="${fill}" fill-opacity="0.85" stroke="var(--bg)" stroke-width="1.5"/>${text}</g>`;
  }).join('');

  svg.innerHTML = edgeSvg + nodeSvg;
  els.topologyLegend.innerHTML =
    `<span><i style="background:var(--ok)"></i> Local (your network)</span>` +
    `<span><i style="background:var(--tcp)"></i> Remote host</span>` +
    `<span class="topo-hint">circle size = traffic · line = a conversation</span>`;
}

// ---- Traffic Diff — compare two capture snapshots (delta) ----
function takeSnapshot() {
  const protos = {};
  for (const [p, st] of Object.entries(state.stats.perProtocol)) protos[p] = { packets: st.total_packets, bytes: st.total_bytes };
  const hosts = {};
  for (const f of state.flows.values()) {
    if (f.clientAddr) hosts[f.clientAddr] = (hosts[f.clientAddr] || 0) + f.bytes;
    if (f.serverAddr) hosts[f.serverAddr] = (hosts[f.serverAddr] || 0) + f.bytes;
  }
  const domains = {};
  for (const [d, n] of state.stats.topDomains) domains[d] = n;
  return { ts: new Date(), packets: state.stats.totalPackets, bytes: state.stats.totalBytes, protos, hosts, domains };
}
function diffLabel(snap) {
  if (!snap) return '—';
  return `${snap.packets.toLocaleString()} pkts · ${formatBytes(snap.bytes)} · ${snap.ts.toLocaleTimeString()}`;
}
function deltaCell(a, b, fmt = (x) => x) {
  const d = b - a;
  const cls = d > 0 ? 'diff-up' : d < 0 ? 'diff-down' : 'diff-zero';
  const sign = d > 0 ? '+' : '';
  return `<span class="${cls}">${sign}${fmt(d)}</span>`;
}
function renderDiff() {
  const { a, b } = state.diff;
  if (!a || !b) {
    els.diffBody.innerHTML = '<div class="diff-empty">Take <b>Snapshot A</b> (a baseline), let traffic change, then take <b>Snapshot B</b> and Compare. netscope highlights what appeared, grew, or vanished between the two — the delta.</div>';
    return;
  }
  const rows = [];
  rows.push(`<div class="diff-section"><h3>Totals</h3><table class="diff-table"><tr><th>Metric</th><th>A</th><th>B</th><th>Δ</th></tr>` +
    `<tr><td>Packets</td><td>${a.packets.toLocaleString()}</td><td>${b.packets.toLocaleString()}</td><td>${deltaCell(a.packets, b.packets, (x) => x.toLocaleString())}</td></tr>` +
    `<tr><td>Bytes</td><td>${formatBytes(a.bytes)}</td><td>${formatBytes(b.bytes)}</td><td>${deltaCell(a.bytes, b.bytes, formatBytes)}</td></tr></table></div>`);

  // Protocols
  const protoKeys = [...new Set([...Object.keys(a.protos), ...Object.keys(b.protos)])].sort();
  const protoRows = protoKeys.map((p) => {
    const pa = (a.protos[p] || {}).packets || 0, pb = (b.protos[p] || {}).packets || 0;
    const tag = !pa && pb ? '<span class="diff-new">NEW</span>' : pa && !pb ? '<span class="diff-gone">GONE</span>' : '';
    return `<tr><td style="color:${protoColor(p)}">${esc(p)} ${tag}</td><td>${pa}</td><td>${pb}</td><td>${deltaCell(pa, pb)}</td></tr>`;
  }).join('');
  rows.push(`<div class="diff-section"><h3>Protocols (packets)</h3><table class="diff-table"><tr><th>Protocol</th><th>A</th><th>B</th><th>Δ</th></tr>${protoRows}</table></div>`);

  // Hosts — biggest movers by byte delta
  const hostKeys = [...new Set([...Object.keys(a.hosts), ...Object.keys(b.hosts)])];
  const movers = hostKeys.map((h) => ({ h, a: a.hosts[h] || 0, b: b.hosts[h] || 0 }))
    .sort((x, y) => Math.abs(y.b - y.a) - Math.abs(x.b - x.a)).slice(0, 15);
  const hostRows = movers.map((m) => {
    const tag = !m.a && m.b ? '<span class="diff-new">NEW</span>' : m.a && !m.b ? '<span class="diff-gone">GONE</span>' : '';
    return `<tr><td class="mono">${esc(m.h)} ${tag}</td><td>${formatBytes(m.a)}</td><td>${formatBytes(m.b)}</td><td>${deltaCell(m.a, m.b, formatBytes)}</td></tr>`;
  }).join('');
  rows.push(`<div class="diff-section"><h3>Hosts — biggest movers</h3><table class="diff-table"><tr><th>Host</th><th>A</th><th>B</th><th>Δ bytes</th></tr>${hostRows}</table></div>`);

  els.diffBody.innerHTML = rows.join('');
}

// ---- Signature engine (YARA-lite) — match payloads against known-bad indicators ----
// A curated set of real IOC/attack signatures scanned against reassembled payload
// text. Not a full YARA runtime — a transparent, honest pattern set you can read.
const SIGNATURES = [
  { id: 'eicar', name: 'EICAR anti-malware test file', sev: 'high', rx: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR/ },
  { id: 'log4shell', name: 'Log4Shell JNDI lookup (CVE-2021-44228)', sev: 'high', rx: /\$\{jndi:(ldap|rmi|dns|ldaps|iiop):/i },
  { id: 'shellshock', name: 'Shellshock bash exploit (CVE-2014-6271)', sev: 'high', rx: /\(\)\s*\{\s*:;\s*\}\s*;/ },
  { id: 'revshell', name: 'Reverse shell command', sev: 'high', rx: /(bash\s+-i\s+>&\s*\/dev\/tcp\/|nc\s+-e\s+\/bin\/(ba)?sh|\/bin\/(ba)?sh\s+-i)/i },
  { id: 'sqli', name: 'SQL injection pattern', sev: 'warn', rx: /(union\s+select|'\s*or\s*'1'\s*=\s*'1|or\s+1\s*=\s*1--|sleep\(\d+\))/i },
  { id: 'traversal', name: 'Directory traversal', sev: 'warn', rx: /(\.\.\/){3,}|(\.\.\\){3,}|%2e%2e%2f/i },
  { id: 'ps-enc', name: 'Encoded PowerShell payload', sev: 'warn', rx: /powershell(\.exe)?\s+.*-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}/i },
  { id: 'basic-auth', name: 'HTTP Basic auth (credentials in header)', sev: 'warn', rx: /authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}/i },
  { id: 'scanner-ua', name: 'Known scanner/attack tool User-Agent', sev: 'warn', rx: /user-agent:.*(sqlmap|nikto|masscan|nmap\s+scripting|dirbuster|gobuster|hydra|wpscan|acunetix|nuclei)/i },
  { id: 'webshell', name: 'Web-shell style command execution', sev: 'high', rx: /(cmd=|exec=|system\(|passthru\(|shell_exec\()/i },
];
function scanSignatures(pkts) {
  const hits = new Map(); // sig.id -> { sig, count, samples:Set }
  for (const p of pkts) {
    const payload = extractPayload(p.raw || []);
    if (!payload || !payload.length) continue;
    const text = decodeStreamText(payload);
    for (const sig of SIGNATURES) {
      if (sig.rx.test(text)) {
        let h = hits.get(sig.id);
        if (!h) { h = { sig, count: 0, samples: new Set() }; hits.set(sig.id, h); }
        h.count++;
        const where = p.dst_host || p.dst_addr || p.src_addr;
        if (where && h.samples.size < 5) h.samples.add(`${p.src_addr || '?'} → ${where}`);
      }
    }
  }
  return [...hits.values()];
}

// ---- Protocol guesser — heuristic classifier for unknown/obfuscated traffic ----
// Combines port hints, byte "magic", printable-text ratio and Shannon entropy to
// suggest what an otherwise-unidentified payload most likely is. A transparent
// heuristic (it shows its reasoning), not a black-box model.
const PORT_HINTS = {
  22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 110: 'POP3',
  123: 'NTP', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS/TLS', 445: 'SMB',
  587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN', 3306: 'MySQL', 3389: 'RDP',
  5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-alt', 27017: 'MongoDB', 51820: 'WireGuard',
};
function shannonEntropy(bytes) {
  if (!bytes.length) return 0;
  const freq = new Array(256).fill(0);
  for (const b of bytes) freq[b]++;
  let e = 0;
  for (const f of freq) { if (!f) continue; const p = f / bytes.length; e -= p * Math.log2(p); }
  return e; // bits per byte, 0..8
}
function guessProtocol(pkt) {
  const payload = extractPayload(pkt.raw || []);
  const reasons = [];
  let best = null, conf = 0;
  const port = pkt.dst_port != null && PORT_HINTS[pkt.dst_port] ? pkt.dst_port
    : (pkt.src_port != null && PORT_HINTS[pkt.src_port] ? pkt.src_port : null);
  if (port != null) { best = PORT_HINTS[port]; conf = 0.55; reasons.push(`Port ${port} is registered for ${best}`); }

  if (payload && payload.length) {
    const head = payload.slice(0, 8);
    const asc = decodeStreamText(payload.slice(0, 16));
    const magics = [
      [/^SSH-/, 'SSH', 0.95], [/^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH) /, 'HTTP', 0.95],
      [/^HTTP\/\d/, 'HTTP', 0.9], [/^220[ -]/, 'SMTP/FTP banner', 0.7],
    ];
    for (const [rx, name, c] of magics) { if (rx.test(asc) && c > conf) { best = name; conf = c; reasons.push(`Payload begins "${asc.slice(0, 6).trim()}" — ${name} signature`); } }
    if (head[0] === 0x16 && head[1] === 0x03) { best = 'TLS'; conf = Math.max(conf, 0.9); reasons.push('Bytes 16 03 — TLS record header'); }

    const printable = [...payload.slice(0, 256)].filter((b) => (b >= 32 && b < 127) || b === 9 || b === 10 || b === 13).length;
    const ratio = printable / Math.min(payload.length, 256);
    const ent = shannonEntropy(payload.slice(0, 512));
    reasons.push(`Entropy ${ent.toFixed(2)} bits/byte, ${(ratio * 100).toFixed(0)}% printable`);
    if (ent > 7.5) { reasons.push('High entropy → encrypted or compressed'); if (!best) { best = 'Encrypted/compressed'; conf = 0.5; } }
    else if (ratio > 0.85) { reasons.push('Mostly printable → text-based protocol'); if (!best || conf < 0.5) { best = best || 'Text protocol'; conf = Math.max(conf, 0.5); } }
    else if (!best) { best = 'Binary protocol'; conf = 0.35; }
  }
  if (!best) return null;
  return { label: best, confidence: conf, reasons };
}

// ---- Sensitive-data scrubbing (GDPR/KVKK) for exported reports ----
function scrubText(s) {
  return String(s)
    .replace(/([\w.+-]+)@([\w-]+\.[\w.-]+)/g, '‹email›')
    .replace(/((?:password|passwd|pwd|pass|token|secret|api[_-]?key|authorization)["'\s:=]+)([^\s"'&,)]{3,})/gi, '$1‹redacted›')
    .replace(/\b([A-Za-z0-9+/]{24,}={0,2})\b/g, '‹token›')
    .replace(/\b(?:\d[ -]?){13,16}\b/g, '‹card›');
}
// Anonymise IP addresses consistently (each distinct IP → host-N) for GDPR/KVKK
// sanitised exports. Returns { text, map } so the mapping can be shown if wanted.
function anonymizeIps(text) {
  const map = new Map();
  let n = 0;
  const rx = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b/g;
  const out = String(text).replace(rx, (ip) => {
    if (ip === '127.0.0.1' || ip === '::1') return ip;
    if (!map.has(ip)) map.set(ip, `host-${++n}`);
    return map.get(ip);
  });
  return { text: out, map };
}

// ---- Semantic Log Parsing — turn a packet into a business-logic event ----
// "What happened", not "what bytes moved": HTTP verbs and status codes, DNS
// lookups, TLS handshakes, auth attempts and resets, in plain language.
const HTTP_STATUS_MEANING = {
  '2': 'succeeded', '301': 'moved permanently', '302': 'redirected', '304': 'not modified',
  '400': 'was rejected as malformed', '401': 'requires authentication', '403': 'was forbidden',
  '404': 'was not found', '429': 'was rate-limited', '500': 'hit a server error',
  '502': 'got a bad gateway', '503': 'found the service unavailable',
};
function semanticEvents(pkt) {
  const out = [];
  const payload = extractPayload(pkt.raw || []);
  const text = payload && payload.length ? decodeStreamText(payload) : '';
  const host = pkt.dst_host || pkt.dst_addr || 'the server';

  if (text) {
    const req = text.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/\d/);
    if (req) out.push({ icon: '📥', text: `Client asked ${host} to ${req[1]} ${req[2]}` });
    const resp = text.match(/^HTTP\/\d\.?\d?\s+(\d{3})\s*(.*)/);
    if (resp) {
      const code = resp[1];
      const meaning = HTTP_STATUS_MEANING[code] || HTTP_STATUS_MEANING[code[0]] || `returned ${code}`;
      out.push({ icon: code[0] === '2' ? '✅' : code[0] === '4' || code[0] === '5' ? '⚠' : 'ℹ', text: `Request ${meaning}${code[0] !== '2' ? ` (${code} ${resp[2].trim()})` : ''}` });
    }
    if (/authorization:\s*(basic|bearer|digest)/i.test(text)) out.push({ icon: '🔑', text: 'A user presented credentials (Authorization header)' });
    if (/set-cookie:/i.test(text)) out.push({ icon: '🍪', text: 'Server set a session cookie (likely a login/session start)' });
    if (/(error|exception|failed|denied|invalid)/i.test(text) && !req && !resp) out.push({ icon: '❗', text: 'Payload mentions an error/failure condition' });
  }
  if (pkt.protocol === 'DNS') {
    const m = (pkt.summary || '').match(/DNS (Query|Response) [—-] (\S+)/);
    if (m) out.push({ icon: '🔎', text: m[1] === 'Query' ? `Looking up the address of ${m[2]}` : `Got the address for ${m[2]}` });
  }
  if (payload && payload.length >= 2 && payload[0] === 0x16 && payload[1] === 0x03) {
    const hs = payload[5];
    out.push({ icon: '🔒', text: hs === 1 ? `Starting an encrypted session with ${host} (TLS ClientHello)` : hs === 2 ? 'Server accepted the encrypted session (TLS ServerHello)' : 'TLS handshake in progress' });
  }
  if ((pkt.summary || '').includes('reset (RST)')) out.push({ icon: '✂', text: 'The connection was abruptly closed (reset)' });
  return out;
}

// ---- Dynamic Payload Beautifier — JSON / XML as a collapsible coloured tree ----
function jsonTree(value, key) {
  const keyHtml = key != null ? `<span class="jt-key">${esc(key)}</span>: ` : '';
  if (value === null) return `<div class="jt-row">${keyHtml}<span class="jt-null">null</span></div>`;
  if (Array.isArray(value) || (typeof value === 'object')) {
    const entries = Array.isArray(value) ? value.map((v, i) => [i, v]) : Object.entries(value);
    const open = Array.isArray(value) ? '[' : '{', close = Array.isArray(value) ? ']' : '}';
    if (!entries.length) return `<div class="jt-row">${keyHtml}<span class="jt-punc">${open}${close}</span></div>`;
    return `<div class="jt-node"><div class="jt-row jt-toggle">${keyHtml}<span class="jt-twist">▾</span><span class="jt-punc">${open}</span><span class="jt-count">${entries.length}</span></div>` +
      `<div class="jt-children">${entries.map(([k, v]) => jsonTree(v, k)).join('')}</div>` +
      `<div class="jt-row"><span class="jt-punc">${close}</span></div></div>`;
  }
  const cls = typeof value === 'number' ? 'jt-num' : typeof value === 'boolean' ? 'jt-bool' : 'jt-str';
  const disp = typeof value === 'string' ? `"${value}"` : String(value);
  return `<div class="jt-row">${keyHtml}<span class="${cls}">${esc(disp)}</span></div>`;
}
function beautifyPayload(text) {
  if (!text) return null;
  const body = text.includes('\r\n\r\n') ? text.slice(text.indexOf('\r\n\r\n') + 4) : text;
  const trimmed = body.trim();
  if (!trimmed) return null;
  if ((trimmed[0] === '{' || trimmed[0] === '[')) {
    try { return { kind: 'JSON', html: jsonTree(JSON.parse(trimmed)) }; } catch { /* not valid JSON */ }
  }
  if (trimmed[0] === '<' && /<\/?[a-zA-Z][\w:-]*(\s|>|\/)/.test(trimmed)) {
    // Lightweight XML/HTML pretty-print with indentation + colouring.
    let depth = 0, out = '';
    const tokens = trimmed.replace(/></g, '>\n<').split('\n');
    for (const t of tokens) {
      if (/^<\//.test(t)) depth = Math.max(0, depth - 1);
      out += '  '.repeat(depth) + t + '\n';
      if (/^<[^!?/][^>]*[^/]>$/.test(t) && !/^<[^>]+\/>/.test(t)) depth++;
    }
    const colored = esc(out).replace(/(&lt;\/?)([\w:-]+)/g, '$1<span class="jt-key">$2</span>');
    return { kind: 'XML', html: `<pre class="jt-xml">${colored}</pre>` };
  }
  return null;
}

// ---- Hex → code: turn raw bytes into a C / Rust / Python literal ----
function bytesToCode(bytes, lang) {
  const b = Array.from(bytes || []);
  const hex = b.map((x) => '0x' + x.toString(16).padStart(2, '0'));
  if (lang === 'c') return `unsigned char payload[${b.length}] = {\n  ${hex.join(', ')}\n};`;
  if (lang === 'rust') return `let payload: [u8; ${b.length}] = [\n    ${hex.join(', ')}\n];`;
  if (lang === 'python') return `payload = bytes([${b.join(', ')}])`;
  return b.map((x) => x.toString(16).padStart(2, '0')).join('');
}

// ---- Automated Dependency Mapping — which services an app talks to ----
const SERVICE_PATTERNS = [
  [/(googleapis|gstatic|google-analytics|googlesyndication|doubleclick|ggpht|1e100|google)\b/i, 'Google'],
  [/(cloudfront\.net|amazonaws\.com|aws|awsstatic)/i, 'Amazon AWS / CloudFront'],
  [/(cloudflare|cloudflaressl|cf-)/i, 'Cloudflare'],
  [/(microsoft|windows\.net|azure|office|live\.com|msedge|bing)/i, 'Microsoft / Azure'],
  [/(apple|icloud|akadns)/i, 'Apple'],
  [/(akamai|akamaized)/i, 'Akamai'],
  [/(fastly)/i, 'Fastly'],
  [/(facebook|fbcdn|instagram|whatsapp|meta)/i, 'Meta'],
  [/(github|githubusercontent)/i, 'GitHub'],
];
function classifyService(host) {
  if (!host) return 'Other';
  for (const [rx, name] of SERVICE_PATTERNS) if (rx.test(host)) return name;
  return 'Other';
}
function buildDependencyTree() {
  const tree = new Map(); // service -> Map(host -> Set(ip))
  for (const f of state.flows.values()) {
    if (!isPublicIp(f.serverAddr)) continue;
    const host = f.serverHost || f.serverAddr;
    const svc = classifyService(host);
    if (!tree.has(svc)) tree.set(svc, new Map());
    const hosts = tree.get(svc);
    if (!hosts.has(host)) hosts.set(host, new Set());
    hosts.get(host).add(f.serverAddr);
  }
  return tree;
}

// ---- Predictive Traffic Modeling — project bandwidth from the recent trend ----
function projectBandwidth() {
  const hist = state.live.throughput;
  if (hist.length < 5) return null;
  // Least-squares slope over the last N samples (1 sample ≈ 1 s).
  const n = Math.min(hist.length, 30);
  const data = hist.slice(-n);
  let sx = 0, sy = 0, sxy = 0, sxx = 0;
  data.forEach((y, x) => { sx += x; sy += y; sxy += x * y; sxx += x * x; });
  const slope = (n * sxy - sx * sy) / Math.max(n * sxx - sx * sx, 1e-9);
  const cur = data[data.length - 1];
  const in5min = Math.max(0, cur + slope * 300); // 300 s ahead
  const trend = slope > cur * 0.02 ? 'rising' : slope < -cur * 0.02 ? 'falling' : 'steady';
  return { current: cur, in5min, trend, bytes5min: Math.max(0, (cur + in5min) / 2 * 300) };
}

// ---- Threat Actor Attribution (heuristic) — beaconing / C2-like behaviour ----
// Honest: this flags *patterns* consistent with automation/C2 (regular beacon
// intervals, known-suspect ports, DGA domains) — it is not real attribution.
const SUSPECT_PORTS = { 4444: 'Metasploit default', 6667: 'IRC (classic botnet C2)', 1337: 'common backdoor', 31337: 'elite/backdoor', 6666: 'IRC/botnet', 8888: 'alt C2' };
function detectBeaconing(pkts) {
  const byDst = new Map(); // dst -> [epoch_ms]
  for (const p of pkts) {
    if (!p.dst_addr || !isPublicIp(p.dst_addr) || p.epoch_ms == null) continue;
    if (!byDst.has(p.dst_addr)) byDst.set(p.dst_addr, []);
    byDst.get(p.dst_addr).push(p.epoch_ms);
  }
  const hits = [];
  for (const [dst, times] of byDst) {
    if (times.length < 6) continue;
    times.sort((a, b) => a - b);
    const gaps = [];
    for (let i = 1; i < times.length; i++) gaps.push(times[i] - times[i - 1]);
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    if (mean < 500) continue; // ignore bursts / sub-second chatter
    const variance = gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length;
    const cv = Math.sqrt(variance) / mean; // coefficient of variation — low = very regular
    if (cv < 0.25) hits.push({ dst, interval: Math.round(mean / 1000), count: times.length });
  }
  return hits;
}

// ---- Smart Alerts + Event Triggers (IFTTT) ----
// A lightweight rules engine over the live stream plus proactive anomaly alerts.
function pushAlert(sev, msg) {
  state.alerts.unshift({ ts: new Date(), sev, msg });
  if (state.alerts.length > 100) state.alerts.pop();
  updateAlertBadge();
  if (els.alertPanel && !els.alertPanel.classList.contains('hidden')) renderAlerts();
}
function updateAlertBadge() {
  if (!els.alertBadge) return;
  const unseen = state.alerts.length - state.alertsSeen;
  els.alertBadge.textContent = unseen > 0 ? String(unseen) : '';
  els.alertBadge.classList.toggle('hidden', unseen <= 0);
}
// Anomaly watchers — called once per second from the live sampler.
function checkAnomalies() {
  const L = state.live;
  const now = performance.now();
  state._alertCooldown = state._alertCooldown || {};
  const cool = (k, ms) => { if (now - (state._alertCooldown[k] || 0) < ms) return false; state._alertCooldown[k] = now; return true; };
  const thr = L.throughput;
  if (thr.length >= 8) {
    const recent = thr[thr.length - 1];
    const avg = thr.slice(-8, -1).reduce((a, b) => a + b, 0) / 7;
    if (avg > 0 && recent > avg * 3 && recent > 50000 && cool('spike', 15000)) pushAlert('warn', `Traffic spike: ${fmtRate(recent).join(' ')} (≈${(recent / avg).toFixed(1)}× recent average)`);
  }
  const er = L.errRate[L.errRate.length - 1] || 0;
  if (er > 25 && state.stats.totalPackets > 20 && cool('errrate', 20000)) pushAlert('warn', `Error rate ${er.toFixed(0)}% — connection resets/malformed frames`);
}
function evaluateTriggers(pkt) {
  for (const t of state.triggers) {
    if (t.enabled === false) continue;
    let val;
    if (t.field === 'protocol') val = pkt.protocol;
    else if (t.field === 'host') val = `${pkt.src_addr || ''} ${pkt.dst_addr || ''} ${pkt.src_host || ''} ${pkt.dst_host || ''}`;
    else if (t.field === 'port') val = `${pkt.src_port ?? ''} ${pkt.dst_port ?? ''}`;
    else if (t.field === 'length') val = pkt.length;
    else continue;
    let match = false;
    if (t.op === 'contains') match = String(val).toLowerCase().includes(String(t.value).toLowerCase());
    else if (t.op === 'equals') match = String(val).split(/\s+/).includes(String(t.value));
    else if (t.op === 'gte') match = Number(pkt.length) >= Number(t.value);
    if (match) {
      const key = `${t.field}|${t.op}|${t.value}`;
      state._trigCount = state._trigCount || {};
      state._trigCount[key] = (state._trigCount[key] || 0) + 1;
      // Rate-limit identical trigger alerts so a matching flood doesn't spam.
      if (state._trigCount[key] <= 3 || state._trigCount[key] % 25 === 0)
        pushAlert('info', `Trigger "${t.field} ${t.op} ${t.value}" fired (${state._trigCount[key]}×) — ${endpointLabel(pkt.dst_addr, pkt.dst_host, pkt.dst_port)}`);
    }
  }
}
function renderAlerts() {
  state.alertsSeen = state.alerts.length;
  updateAlertBadge();
  els.alertList.innerHTML = state.alerts.length
    ? state.alerts.map((a) => `<div class="alert-item alert-${a.sev}"><span class="alert-time">${a.ts.toLocaleTimeString()}</span><span class="alert-msg">${esc(a.msg)}</span></div>`).join('')
    : '<div class="alert-empty">No alerts yet. netscope watches for traffic spikes, error bursts and your triggers.</div>';
  renderTriggerList();
}
function renderTriggerList() {
  if (!els.triggerList) return;
  els.triggerList.innerHTML = state.triggers.length
    ? state.triggers.map((t, i) => `<div class="trigger-row"><span class="mono">${esc(t.field)} ${esc(t.op)} ${esc(String(t.value))}</span><button class="profile-del" data-del-trigger="${i}" title="Delete">×</button></div>`).join('')
    : '<div class="alert-empty">No triggers. Add one below — e.g. host contains 185.220 → alert.</div>';
}
function addTrigger() {
  const field = els.trigField.value, op = els.trigOp.value, value = els.trigValue.value.trim();
  if (!value) return;
  state.triggers.push({ field, op, value, enabled: true });
  saveJSON('netscope.triggers', state.triggers);
  els.trigValue.value = '';
  renderTriggerList();
}

// ---- Workspace-aware noise filter (Zero-touch capturing) ----
// Hides low-signal background traffic (OS updates, telemetry, discovery) so the
// packet list shows what the app you care about is actually doing.
const NOISE_PATTERNS = [
  /windowsupdate|update\.microsoft|delivery\.mp\.microsoft|dl\.delivery|msftconnecttest|msftncsi/i,
  /telemetry|vortex\.data\.microsoft|watson\.|settings-win\.data/i,
  /softwareupdate\.apple|swcdn\.apple|mesu\.apple/i,
  /pool\.ntp\.org|time\.(windows|apple|google)|ntp\./i,
  /mozilla\.(net|org).*update|firefox.*update|edgedl|google.*update/i,
  /ubuntu\.com|archive\.ubuntu|canonical|debian\.org/i,
];
const NOISE_PORTS = new Set([1900, 5353, 5355, 137, 138, 3702]); // SSDP, mDNS, LLMNR, NetBIOS, WS-Discovery
function isNoise(pkt) {
  if (NOISE_PORTS.has(pkt.dst_port) || NOISE_PORTS.has(pkt.src_port)) return true;
  const hay = `${pkt.dst_host || ''} ${pkt.src_host || ''} ${pkt.summary || ''}`;
  return NOISE_PATTERNS.some((rx) => rx.test(hay));
}

// ---- Privacy X-ray — what a site takes from you & runs in the background ----
// Wireshark shows the packets; this answers the human question: "what is this
// site actually collecting, who does it call behind my back, and how much of my
// data does it cost?" All from packets already captured — no extra traffic.
const TRACKER_DB = [
  [/doubleclick|googlesyndication|googleadservices|adservice\.google|pagead|adsystem/i, 'Advertising', 'Google Ads'],
  [/google-?analytics|googletagmanager|analytics\.google|google-analytics/i, 'Analytics', 'Google Analytics'],
  [/adnxs|rubiconproject|pubmatic|criteo|taboola|outbrain|moatads|adroll|bidswitch|casalemedia|openx|smartadserver|33across/i, 'Advertising', 'Ad network'],
  [/scorecardresearch|quantserve|quantcast|chartbeat|comscore/i, 'Analytics', 'Audience measurement'],
  [/hotjar|fullstory|mouseflow|mixpanel|segment\.(io|com)|amplitude|heap(analytics)?|matomo|plausible|statcounter|newrelic|nr-data|sentry|bugsnag/i, 'Analytics', 'Product analytics'],
  [/facebook|fbcdn|connect\.facebook|fbevents/i, 'Social', 'Meta / Facebook'],
  [/twitter|t\.co|ads-twitter|linkedin|licdn|tiktok|snapchat|sc-static|pinterest|pinimg|reddit/i, 'Social', 'Social widget'],
  [/branch\.io|appsflyer|adjust\.com|kochava|singular|onesignal/i, 'Advertising', 'Mobile attribution'],
  [/cloudfront|akamai|fastly|cloudflare|jsdelivr|unpkg|cdnjs|gstatic|bootstrapcdn/i, 'CDN', 'Content delivery'],
];
function classifyTracker(host) {
  if (!host) return null;
  for (const [rx, cat, name] of TRACKER_DB) if (rx.test(host)) return { cat, name };
  return null;
}
// Cookie names that exist to follow you across sites/sessions.
const TRACKING_COOKIE_RX = /^(_ga|_gid|_gcl|_gac|_fbp|_fbc|__utm|_hj|ajs_|mp_|IDE|MUID|MUIDB|NID|_pin_|_scid|amplitude|optimizely|__qca|uuid|_derived_epik)/i;

// ---- WAF (Web Application Firewall) fingerprints ----
// Matched against a site's response headers / cookies. Strong signals only —
// the tell-tale headers each vendor's edge inserts.
const WAF_SIGS = [
  [/cf-ray:|cf-cache-status:|server:\s*cloudflare|__cfduid|cf_clearance/i, 'Cloudflare'],
  [/x-sucuri-id:|x-sucuri-cache:|server:\s*sucuri/i, 'Sucuri CloudProxy'],
  [/x-iinfo:|incap_ses|visid_incap|x-cdn:\s*incapsula/i, 'Imperva Incapsula'],
  [/akamaighost|x-akamai-|akamai-grn:/i, 'Akamai (Kona)'],
  [/x-amz-cf-id:|server:\s*awselb|x-amzn-waf/i, 'AWS (CloudFront/WAF)'],
  [/server:\s*big-?ip|bigipserver|x-waf-|f5-/i, 'F5 BIG-IP ASM'],
  [/mod_security|modsecurity|x-mod-security/i, 'ModSecurity'],
  [/server:\s*barracuda|barra_counter/i, 'Barracuda'],
  [/x-fw-|fortiweb|fortigate/i, 'Fortinet FortiWeb'],
  [/x-sp-waf|server:\s*airlock|x-denied-reason/i, 'Generic WAF'],
];
// CDN vendors that also commonly *are* the WAF — used for a weaker, labelled guess
// when we only know the fronting service (e.g. HTTPS, no readable headers).
const CDN_WAF = { 'Content delivery': null };
function wafFromCdnName(name) {
  if (/cloudflare/i.test(name)) return 'Cloudflare';
  if (/akamai/i.test(name)) return 'Akamai';
  if (/sucuri/i.test(name)) return 'Sucuri';
  if (/imperva|incapsula/i.test(name)) return 'Imperva';
  return null;
}

// ---- HTTP error explanations — plain-language "why did I get this?" ----
const HTTP_STATUS_TEXT = {
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
  408: 'Request Timeout', 409: 'Conflict', 410: 'Gone', 413: 'Payload Too Large', 415: 'Unsupported Media',
  418: "I'm a teapot", 429: 'Too Many Requests', 451: 'Unavailable For Legal Reasons',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
};
const HTTP_ERR_REASON = {
  400: 'The request was malformed — bad syntax, a missing field, or a header the server rejected.',
  401: 'The endpoint needs you to log in / send a valid token, and none was accepted.',
  403: 'The server understood you but refuses — usually missing permissions, an IP/geo block, a bot/rate rule, or a WAF blocking the request.',
  404: 'That URL doesn\'t exist on the server (wrong path, moved, or deleted).',
  405: 'The HTTP method (GET/POST/…) isn\'t allowed on that endpoint.',
  408: 'The server gave up waiting for the rest of your request.',
  413: 'You sent more data than the server accepts (upload too big).',
  429: 'You hit a rate limit — too many requests in a short window (often a WAF/anti-abuse rule).',
  451: 'Blocked for legal reasons (censorship, DMCA, regional restriction).',
  500: 'The server\'s own code crashed handling the request — a bug on their side.',
  502: 'A gateway/proxy got a bad response from the upstream server — the backend is down or erroring.',
  503: 'The service is overloaded or in maintenance — temporarily can\'t serve you.',
  504: 'A gateway timed out waiting for the upstream server — the backend is too slow or unreachable.',
};

// ---- Tiny service→CVE map (from cleartext Server headers) — honest & limited ----
const CVE_DB = [
  [/Apache\/2\.4\.(4[0-9]|50)\b/i, 'CVE-2021-41773', 'Apache 2.4.49/2.4.50 path traversal → RCE. Upgrade to ≥2.4.51.'],
  [/OpenSSH_[0-6]\./i, 'legacy-openssh', 'Very old OpenSSH — multiple known issues (user enumeration, weak KEX). Upgrade.'],
  [/nginx\/1\.(1?[0-9])\.\b/i, 'old-nginx', 'Old nginx branch — several CVEs since. Upgrade to a current stable.'],
  [/PHP\/(5\.|7\.[0-3])/i, 'php-eol', 'End-of-life PHP (5.x / ≤7.3) — no security patches. Upgrade.'],
  [/Microsoft-IIS\/[0-6]\./i, 'iis-eol', 'End-of-life IIS (≤6.0) — unpatched. Migrate.'],
  [/Server:\s*Werkzeug/i, 'werkzeug-debug', 'Werkzeug dev server exposed — never run the Flask dev server in production.'],
];
function matchCVE(server) {
  for (const [rx, id, desc] of CVE_DB) if (rx.test(server)) return { id, desc };
  return null;
}

function analyzePrivacy(pkts) {
  const sites = new Map();
  // First pass: learn every IP↔hostname pairing so a request and its response
  // land on the same site even when only one direction carried the hostname.
  const ipHost = new Map();
  for (const p of pkts) {
    if (p.src_addr && p.src_host) ipHost.set(p.src_addr, p.src_host);
    if (p.dst_addr && p.dst_host) ipHost.set(p.dst_addr, p.dst_host);
  }
  const get = (host, ip) => {
    const key = host || ip || '?';
    if (!sites.has(key)) sites.set(key, { host: host || ip, ip, up: 0, down: 0, http: 0, tls: 0, reqs: 0, cookiesSet: new Map(), cookiesSent: new Set(), info: new Set() });
    return sites.get(key);
  };
  for (const p of pkts) {
    const srcPub = isPublicIp(p.src_addr), dstPub = isPublicIp(p.dst_addr);
    if (!srcPub && !dstPub) continue;
    const outbound = dstPub; // we → site
    const s = outbound
      ? get(p.dst_host || ipHost.get(p.dst_addr), p.dst_addr)
      : get(p.src_host || ipHost.get(p.src_addr), p.src_addr);
    if (outbound) s.up += p.length || 0; else s.down += p.length || 0;
    if (p.protocol === 'TLS') s.tls += p.length || 0;
    if (p.protocol === 'HTTP') {
      s.http += p.length || 0;
      const text = decodeStreamText(extractPayload(p.raw || []) || []);
      if (!text) continue;
      if (/^[A-Z]+\s+\S+\s+HTTP\//.test(text)) {
        s.reqs++;
        const first = text.match(/^[A-Z]+\s+(\S+)/);
        if (first && first[1].includes('?')) s.info.add('URL parameters');
        if (/^cookie:/im.test(text)) {
          s.info.add('Cookies (sent back)');
          const m = text.match(/^cookie:\s*(.+)$/im);
          if (m) m[1].split(';').forEach((c) => { const n = c.split('=')[0].trim(); if (n) s.cookiesSent.add(n); });
        }
        if (/^user-agent:/im.test(text)) s.info.add('Device / OS (User-Agent)');
        if (/^referer:/im.test(text)) s.info.add('Page you came from (Referer)');
        if (/^authorization:/im.test(text)) s.info.add('Credentials');
        if (/^accept-language:/im.test(text)) s.info.add('Your language');
        if (/[\w.+-]+@[\w-]+\.[\w.-]+/.test(text)) s.info.add('Email address');
        if (/(?:^|[?&])(lat|latitude|lon|lng|longitude|geo|location)=/i.test(text)) s.info.add('Location');
        const body = text.includes('\r\n\r\n') ? text.slice(text.indexOf('\r\n\r\n') + 4) : '';
        if (body.trim()) s.info.add('Form / body data');
      }
      const sc = text.match(/set-cookie:\s*[^\r\n]+/ig);
      if (sc) for (const line of sc) {
        const m = line.match(/set-cookie:\s*([^=]+)=([^;\r\n]*)(.*)$/i);
        if (m) { const attrs = m[3] || ''; s.cookiesSet.set(m[1].trim(), { secure: /secure/i.test(attrs), httpOnly: /httponly/i.test(attrs), sameSite: (attrs.match(/samesite=(\w+)/i) || [])[1] || null }); }
      }
      // Response-only signals: status code, Server header, WAF fingerprints.
      const status = text.match(/^HTTP\/\d\.?\d?\s+(\d{3})/);
      if (status) { const c = +status[1]; if (c >= 400) { s.errors = s.errors || new Map(); s.errors.set(c, (s.errors.get(c) || 0) + 1); } }
      const server = text.match(/^server:\s*(.+)$/im);
      if (server && !s.server) s.server = server[1].trim();
      if (!s.waf) for (const [rx, vendor] of WAF_SIGS) { if (rx.test(text)) { s.waf = vendor; break; } }
    }
  }
  const arr = [...sites.values()].map((s) => {
    const tracker = classifyTracker(s.host);
    const wafInferred = !s.waf && tracker && tracker.cat === 'CDN' ? wafFromCdnName(tracker.name + ' ' + s.host) : null;
    const o = { ...s, tracker, total: s.up + s.down, encrypted: s.tls > 0 && s.http === 0, wafInferred };
    o.risk = siteRiskScore(o);
    return o;
  }).filter((s) => s.total > 0).sort((a, b) => b.total - a.total);
  return arr;
}

// ---- Contextual security score (0–100) for a site/flow ----
// Transparent additive heuristic — higher = more exposure/risk. Shown as a chip.
function siteRiskScore(s) {
  let r = 5;
  const reasons = [];
  if (s.http > 0) { r += 25; reasons.push('plain HTTP (readable in transit)'); }
  if (s.info && s.info.has('Credentials') && s.http > 0) { r += 30; reasons.push('credentials sent in cleartext'); }
  if (s.info && s.info.has('Email address')) { r += 8; reasons.push('email address sent'); }
  if (s.info && s.info.has('Location')) { r += 8; reasons.push('location sent'); }
  if (s.tracker && (s.tracker.cat === 'Advertising' || s.tracker.cat === 'Analytics')) { r += 12; reasons.push('third-party tracker'); }
  if (s.cookiesSet) for (const [, f] of s.cookiesSet) { if (!f.httpOnly || !f.secure) { r += 4; reasons.push('cookie with weak flags'); break; } }
  if (s.errors) { const e5 = [...s.errors].filter(([c]) => c >= 500).reduce((a, [, n]) => a + n, 0); if (e5) { r += 6; reasons.push('server errors (5xx)'); } }
  r = Math.min(100, r);
  return { score: r, level: r >= 60 ? 'high' : r >= 30 ? 'medium' : 'low', reasons: [...new Set(reasons)] };
}

// ---- Busiest-period / temporal analysis ----
// Buckets traffic over time so you can answer "when is this busiest?" — overall
// and (for longer captures) which hour-of-day repeats.
function analyzeBusiest(pkts, host) {
  const rel = pkts.filter((p) => p.epoch_ms != null && (!host || p.dst_host === host || p.src_host === host));
  if (!rel.length) return null;
  const first = rel[0].epoch_ms, last = rel[rel.length - 1].epoch_ms;
  const spanMs = Math.max(last - first, 1);
  const nb = 30;
  const bucketMs = Math.max(Math.ceil(spanMs / nb), 1000);
  const buckets = new Array(Math.ceil(spanMs / bucketMs) + 1).fill(0);
  const hourOfDay = new Array(24).fill(0);
  for (const p of rel) {
    buckets[Math.floor((p.epoch_ms - first) / bucketMs)] += p.length || 0;
    hourOfDay[new Date(p.epoch_ms).getHours()] += p.length || 0;
  }
  let peakIdx = 0; buckets.forEach((v, i) => { if (v > buckets[peakIdx]) peakIdx = i; });
  const peakStart = new Date(first + peakIdx * bucketMs);
  const peakEnd = new Date(first + (peakIdx + 1) * bucketMs);
  let peakHour = 0; hourOfDay.forEach((v, i) => { if (v > hourOfDay[peakHour]) peakHour = i; });
  return {
    buckets, peakBytes: buckets[peakIdx], peakStart, peakEnd, bucketMs,
    peakHour, hourOfDay, spanMs, longEnough: spanMs > 3 * 3600 * 1000,
  };
}

function renderPrivacy() {
  const pkts = state.packets;
  if (!pkts.length) {
    els.privacySummary.textContent = '';
    els.privacyCost.innerHTML = '';
    els.privacyList.innerHTML = `<div class="insights-empty">${esc(I18N.t('empty.capture'))}</div>`;
    return;
  }
  const sites = analyzePrivacy(pkts).slice(0, 40);
  const trackers = sites.filter((s) => s.tracker && s.tracker.cat !== 'CDN');
  const trackerBytes = trackers.reduce((a, s) => a + s.total, 0);
  const totalBytes = sites.reduce((a, s) => a + s.total, 0) || 1;
  const cookieCount = sites.reduce((a, s) => a + s.cookiesSet.size, 0);
  const plainSites = sites.filter((s) => s.http > 0).length;

  els.privacySummary.innerHTML =
    `<b>${sites.length}</b> sites · <b>${trackers.length}</b> trackers · ` +
    `<b>${cookieCount}</b> cookies seen · <b>${formatBytes(totalBytes)}</b> of your data ` +
    `(<span style="color:var(--warn)">${formatBytes(trackerBytes)}</span> to trackers)`;

  // Data-cost meter: how much of your traffic went to trackers.
  const trkPct = Math.round((trackerBytes / totalBytes) * 100);
  els.privacyCost.innerHTML =
    `<div class="cost-meter"><div class="cost-bar"><div class="cost-fill" style="width:${trkPct}%"></div></div>` +
    `<div class="cost-legend"><span><i class="dot-trk"></i> Trackers/ads ${trkPct}% (${formatBytes(trackerBytes)})</span>` +
    `<span><i class="dot-first"></i> Everything else ${100 - trkPct}% (${formatBytes(totalBytes - trackerBytes)})</span></div></div>`;

  els.privacyList.innerHTML = sites.map((s) => {
    const badge = s.tracker
      ? `<span class="site-badge badge-${s.tracker.cat.toLowerCase()}">${s.tracker.cat} · ${esc(s.tracker.name)}</span>`
      : `<span class="site-badge badge-first">First-party / other</span>`;
    const lock = s.encrypted ? '<span class="site-lock enc" title="Encrypted (HTTPS)">🔒</span>'
      : s.http > 0 ? '<span class="site-lock plain" title="Some plain HTTP — readable in transit">🔓</span>' : '';
    const infoChips = [...s.info].map((i) => `<span class="info-chip">${esc(i)}</span>`).join('') ||
      (s.encrypted ? '<span class="info-chip muted">Encrypted — content hidden, but metadata & data volume are not</span>' : '<span class="info-chip muted">No readable request seen</span>');
    const setCookies = [...s.cookiesSet.entries()].slice(0, 12).map(([name, f]) => {
      const track = TRACKING_COOKIE_RX.test(name);
      const warn = [];
      if (!f.secure) warn.push('no Secure');
      if (!f.httpOnly) warn.push('no HttpOnly');
      if (!f.sameSite) warn.push('no SameSite');
      return `<span class="cookie-chip${track ? ' cookie-track' : ''}" title="${warn.length ? 'Weak flags: ' + warn.join(', ') : 'flags OK'}">${track ? '🎯 ' : '🍪 '}${esc(name)}${warn.length ? ' ⚠' : ''}</span>`;
    }).join('');
    const sentCookies = s.cookiesSent.size ? `<div class="site-row"><span class="site-k">Cookies you send back</span><span class="site-v">${s.cookiesSent.size} (${[...s.cookiesSent].slice(0, 8).map(esc).join(', ')})</span></div>` : '';
    const waf = s.waf ? `<span class="waf-badge" title="Web Application Firewall detected from response headers">🛡 WAF: ${esc(s.waf)}</span>`
      : s.wafInferred ? `<span class="waf-badge waf-guess" title="Fronted by a CDN that usually provides a WAF (inferred, not header-confirmed)">🛡 WAF likely: ${esc(s.wafInferred)}</span>` : '';
    const risk = s.risk ? `<span class="risk-chip risk-${s.risk.level}" title="${esc(s.risk.reasons.join('; ') || 'low exposure')}">risk ${s.risk.score}</span>` : '';
    const errs = s.errors ? `<div class="site-row"><span class="site-k">HTTP errors</span><span class="site-v">${[...s.errors.entries()].map(([c, n]) => `<span class="err-chip">${n}× ${c} ${esc(HTTP_STATUS_TEXT[c] || '')}</span>`).join('')}</span></div>` : '';

    return `<div class="site-card">
      <div class="site-head">
        ${lock}<span class="site-host">${esc(s.host)}</span>${badge}${waf}${risk}
        <span class="spacer"></span>
        <span class="site-cost" title="Data exchanged with this site">↑ ${formatBytes(s.up)} · ↓ ${formatBytes(s.down)} · Σ ${formatBytes(s.total)}</span>
      </div>
      <div class="site-body">
        <div class="site-row"><span class="site-k">What you send it</span><span class="site-v">${infoChips}</span></div>
        ${setCookies ? `<div class="site-row"><span class="site-k">Cookies it sets on you</span><span class="site-v cookie-wrap">${setCookies}${s.cookiesSet.size > 12 ? ` <span class="info-chip muted">+${s.cookiesSet.size - 12} more</span>` : ''}</span></div>` : ''}
        ${sentCookies}
        ${errs}
        ${s.server ? `<div class="site-row"><span class="site-k">Server</span><span class="site-v mono">${esc(s.server)}</span></div>` : ''}
      </div>
    </div>`;
  }).join('') || `<div class="insights-empty">${esc(I18N.t('privacy.nosites'))}</div>`;
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
  else if (state.view === 'dashboard') { renderStats(); renderLive(); }
  else if (state.view === 'topology') renderTopology(true);
  else if (state.view === 'diff') renderDiff();
  else if (state.view === 'privacy') renderPrivacy();
  else if (state.view === 'script') updateScriptCount();
  else if (state.view === 'insights') renderInsights();
}

// ---- Keyboard ----
function handleKeydown(e) {
  if (e.key === 'Escape' && !els.replayModal.classList.contains('hidden')) { closeReplay(); return; }
  if (e.key === 'Escape' && !els.streamModal.classList.contains('hidden')) { closeFollowStream(); return; }
  if (e.key === 'Escape' && els.reportModal && !els.reportModal.classList.contains('hidden')) { closeReport(); return; }
  const ae = document.activeElement;
  if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT')) return;
  if (!els.replayModal.classList.contains('hidden')) return; // don't hijack keys while editing the replay form
  if (e.key === 'Tab') {
    e.preventDefault();
    const views = ['packets', 'connections', 'dashboard', 'topology', 'insights', 'privacy', 'diff', 'script', 'learn'];
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
    themeSelect: $('#theme-select'), langSelect: $('#lang-select'),
    reportOpen: $('#report-open'), reportModal: $('#report-modal'), reportClose: $('#report-close'),
    reportCopy: $('#report-copy'), reportBody: $('#report-body'), reportStatus: $('#report-status'), reportScrub: $('#report-scrub'),
    topologySvg: $('#topology-svg'), topologySummary: $('#topology-summary'), topologyLegend: $('#topology-legend'),
    topoFreeze: $('#topo-freeze'), topoFit: $('#topo-fit'),
    diffSnapA: $('#diff-snap-a'), diffSnapB: $('#diff-snap-b'), diffALabel: $('#diff-a-label'),
    diffBLabel: $('#diff-b-label'), diffRun: $('#diff-run'), diffBody: $('#diff-body'),
    privacyRescan: $('#privacy-rescan'), privacySummary: $('#privacy-summary'), privacyCost: $('#privacy-cost'), privacyList: $('#privacy-list'),
    summaryOpen: $('#summary-open'), busiestPeak: $('#busiest-peak'), busiestChart: $('#busiest-chart'), busiestHint: $('#busiest-hint'),
    hexPanel: $('#hex-panel'), statProjection: $('#stat-projection'),
    noiseFilterCheck: $('#noise-filter-check'), geoipCheck: $('#geoip-check'), reportAnon: $('#report-anon'),
    alertBtn: $('#alert-btn'), alertBadge: $('#alert-badge'), alertPanel: $('#alert-panel'), alertList: $('#alert-list'),
    triggerList: $('#trigger-list'), trigField: $('#trig-field'), trigOp: $('#trig-op'), trigValue: $('#trig-value'), trigAdd: $('#trig-add'),
  });

  // Wire up view navigation FIRST, synchronously, before any await. Tab
  // switching and keyboard shortcuts must never depend on IPC or event
  // subscription succeeding — otherwise a slow/failed async step below would
  // abort init() and leave the tabs unresponsive.
  $$('.tab').forEach((t) => t.addEventListener('click', () => switchView(t.dataset.view)));
  document.addEventListener('keydown', handleKeydown);

  // Translate all static UI chrome to the saved/detected language up front.
  I18N.apply(state.settings.lang);
  els.langSelect.value = state.settings.lang;
  els.packetCount.textContent = `0 ${I18N.t('unit.packets')}`;

  await loadInterfaces();
  await loadLearn();

  // Restore the persisted profile (or fall back if it was deleted elsewhere)
  if (!allProfiles()[state.settings.profile]) state.settings.profile = Object.keys(BUILTIN_PROFILES)[0];
  applyProfile(state.settings.profile);

  // Start every launch with an empty display filter, even if the active profile
  // defines one — the filter box should be clear when the app opens.
  state.filterText = '';
  els.filterInput.value = '';
  if (state.view === 'packets') renderPacketList();

  // Script console: restore last script or seed with the default
  els.scriptEditor.value = loadJSON('netscope.script', SCRIPT_DEFAULT);

  // elevation + existing blocks
  try {
    state.elevated = await invoke('is_elevated');
    if (!state.elevated) els.elevationBadge.classList.remove('hidden');
    const blocked = await invoke('list_blocked');
    if (blocked) blocked.forEach((ip) => state.blocked.add(ip));
  } catch (e) { console.error(e); }

  try {
    await listen('packet', onPacket);
    await listen('capture-finished', () => { setStatus(STATES.IDLE); els.startBtn.disabled = false; els.stopBtn.disabled = true; });
  } catch (e) { console.error('event subscription failed', e); }

  els.startBtn.addEventListener('click', startCapture);
  els.stopBtn.addEventListener('click', stopCapture);
  els.filterInput.addEventListener('input', () => { state.filterText = els.filterInput.value; renderPacketList(); });
  els.detailClose.addEventListener('click', hideDetail);
  els.detailTree.addEventListener('click', (e) => {
    const jt = e.target.closest('.jt-toggle');
    if (jt) { jt.parentElement.classList.toggle('jt-collapsed'); return; }
    const head = e.target.closest('.tnode-head');
    if (head) head.parentElement.classList.toggle('collapsed');
  });
  // Hex → code literal buttons.
  els.hexPanel.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-hexcode]');
    if (!btn) return;
    const pkt = state.filteredPackets[state.selectedIndex];
    if (!pkt) return;
    const ok = await copyText(bytesToCode(pkt.raw || [], btn.dataset.hexcode));
    flashButton(btn, ok ? '✓' : '✖');
  });

  // Smart Alerts + Triggers
  els.alertBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    els.alertPanel.classList.toggle('hidden');
    if (!els.alertPanel.classList.contains('hidden')) renderAlerts();
  });
  document.addEventListener('click', (e) => {
    if (els.alertPanel.classList.contains('hidden')) return;
    if (!els.alertPanel.contains(e.target) && !els.alertBtn.contains(e.target)) els.alertPanel.classList.add('hidden');
  });
  els.trigAdd.addEventListener('click', addTrigger);
  els.trigValue.addEventListener('keydown', (e) => { if (e.key === 'Enter') addTrigger(); });
  els.triggerList.addEventListener('click', (e) => {
    const del = e.target.closest('[data-del-trigger]');
    if (del) { state.triggers.splice(+del.dataset.delTrigger, 1); saveJSON('netscope.triggers', state.triggers); renderTriggerList(); }
  });

  // Noise filter (Zero-touch)
  els.noiseFilterCheck.addEventListener('change', () => {
    state.settings.noiseFilter = els.noiseFilterCheck.checked;
    saveJSON('netscope.settings', state.settings);
    renderPacketList();
  });

  // GeoIP lookups (opt-in — the only external call netscope makes)
  els.geoipCheck.addEventListener('change', () => {
    state.settings.geoip = els.geoipCheck.checked;
    saveJSON('netscope.settings', state.settings);
    // Re-render the open packet so the location layer updates immediately.
    if (state.selectedIndex >= 0) showDetail(state.selectedIndex);
  });

  // Report IP anonymisation
  els.reportAnon.addEventListener('change', renderReportBody);
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
  els.privacyRescan.addEventListener('click', renderPrivacy);
  els.summaryOpen.addEventListener('click', openSummary);

  // Capture report (+ sensitive-data scrubbing)
  els.reportOpen.addEventListener('click', openReport);
  els.reportClose.addEventListener('click', closeReport);
  els.reportCopy.addEventListener('click', copyReport);
  els.reportScrub.addEventListener('change', renderReportBody);
  els.reportModal.addEventListener('click', (e) => { if (e.target === els.reportModal) closeReport(); });

  // Theme
  applyTheme(state.settings.theme);
  els.themeSelect.value = state.settings.theme;
  els.themeSelect.addEventListener('change', () => {
    state.settings.theme = els.themeSelect.value;
    applyTheme(state.settings.theme);
    saveJSON('netscope.settings', state.settings);
  });

  // Language selector — translate the UI and persist the choice.
  els.langSelect.addEventListener('change', () => {
    state.settings.lang = els.langSelect.value;
    I18N.apply(state.settings.lang);
    saveJSON('netscope.settings', state.settings);
    // Refresh the dynamic strings JS controls (static chrome is done by apply()).
    setStatus(state.status);
    els.packetCount.textContent = `${state.packetCount} ${I18N.t('unit.packets')}`;
    renderAll();
  });

  // Topology map controls
  els.topoFreeze.addEventListener('change', () => { state.topo.frozen = els.topoFreeze.checked; });
  els.topoFit.addEventListener('click', () => renderTopology(true));

  // Traffic diff controls
  els.diffSnapA.addEventListener('click', () => { state.diff.a = takeSnapshot(); els.diffALabel.textContent = `A: ${diffLabel(state.diff.a)}`; });
  els.diffSnapB.addEventListener('click', () => { state.diff.b = takeSnapshot(); els.diffBLabel.textContent = `B: ${diffLabel(state.diff.b)}`; });
  els.diffRun.addEventListener('click', renderDiff);

  // Live dashboard sampler (1 Hz)
  state.live.timer = setInterval(sampleLive, 1000);

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

  renderAll();
}

document.addEventListener('DOMContentLoaded', init);
