// netscope Desktop — Frontend
// Talks to the Rust backend over Tauri IPC (window.__TAURI__).

const PROTOCOL_COLORS = {
  TCP: '#4a9ef5', UDP: '#45d1c5', DNS: '#a78bfa', HTTP: '#34d399',
  TLS: '#6ee7b7', ICMP: '#fbbf24', ARP: '#9ca3af',
  DHCP: '#f9a825', NTP: '#38bdf8', mDNS: '#c084fc',
  SNMP: '#facc15', QUIC: '#2dd4bf', SIP: '#818cf8',
  SSH: '#5eead4', FTP: '#fb923c', SMTP: '#f472b6', IMAP: '#e879f9',
  POP3: '#d98ae8', Telnet: '#f87171', RDP: '#60a5fa', '802.11': '#22d3ee',
  WebSocket: '#a3e635', VXLAN: '#7dd3fc', 'HTTP/2': '#4ade80', gRPC: '#f9a8d4',
  PostgreSQL: '#336791', MySQL: '#00758f', MongoDB: '#4db33d', Redis: '#dc382d', Cassandra: '#1ba1e2',
  Modbus: '#f27a1a', DNP3: '#eab308', BACnet: '#c08a2b', 'EtherNet/IP': '#e15a3b', 'OPC UA': '#339999',
  RTP: '#f09e54', RTCP: '#d4843e',
  Kerberos: '#b45cf5', LDAP: '#8b7ad6', RADIUS: '#f47b9c', OpenVPN: '#ea7a3c', WireGuard: '#88171a',
  ESP: '#9ca3af', AH: '#848b98', MQTT: '#660066', CoAP: '#f59e0b',
  BGP: '#f97316', OSPF: '#2dd4bf', LLDP: '#93c5fd', LACP: '#64748b', STP: '#a8a29e', MPLS: '#cbd5e1',
};
// Colour-blind-safe protocol palette (ROADMAP §6.3) — Okabe–Ito hues chosen to
// stay distinct under deuteranopia/protanopia. Only the common protocols are
// remapped; the rest keep their default colour when CVD mode is on.
const CVD_COLORS = {
  TCP: '#0072b2', UDP: '#56b4e9', DNS: '#cc79a7', HTTP: '#009e73', TLS: '#e69f00',
  ICMP: '#d55e00', ARP: '#999999', QUIC: '#f0e442', 'HTTP/2': '#009e73', DHCP: '#e69f00',
};
const protoColor = (p) =>
  ((typeof state !== 'undefined' && state.settings && state.settings.cvd && CVD_COLORS[p]) ||
    PROTOCOL_COLORS[p] || '#f87171');

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
  // High-contrast (ROADMAP §6.3) — WCAG AA: pure black/white with a strong
  // border and a high-luminance accent for focus.
  contrast: { '--bg': '#000000', '--bg-elev': '#0a0a0a', '--bg-elev-2': '#161616', '--border': '#ffffff', '--text': '#ffffff', '--text-muted': '#e6e6e6', '--accent': '#ffd400' },
};
function applyTheme(name) {
  const t = THEMES[name] || THEMES.midnight;
  const root = document.documentElement;
  for (const [k, v] of Object.entries(t)) root.style.setProperty(k, v);
  root.dataset.theme = name;
}

// ---- Accessibility (ROADMAP §6.3) ----
// Interface/text scaling via CSS zoom — scales the whole UI uniformly, so the
// px-based layout and the virtual scroller's row math (both in layout pixels)
// stay consistent while everything gets larger/smaller.
function applyTextScale(scale) {
  const s = Number(scale) || 1;
  document.documentElement.style.zoom = s === 1 ? '' : String(s);
}

// Swap the protocol accent CSS custom properties to the colour-blind-safe
// palette (and back). protoColor() already prefers CVD_COLORS when enabled;
// this keeps the CSS-driven row stripes in sync.
const PROTO_VARS_DEFAULT = { '--tcp': '#4a9ef5', '--udp': '#45d1c5', '--dns': '#a78bfa', '--http': '#34d399', '--tls': '#6ee7b7', '--icmp': '#fbbf24', '--arp': '#9ca3af', '--unknown': '#f87171' };
const PROTO_VARS_CVD = { '--tcp': '#0072b2', '--udp': '#56b4e9', '--dns': '#cc79a7', '--http': '#009e73', '--tls': '#e69f00', '--icmp': '#d55e00', '--arp': '#999999', '--unknown': '#d55e00' };
function applyCvd(on) {
  const root = document.documentElement;
  const vars = on ? PROTO_VARS_CVD : PROTO_VARS_DEFAULT;
  for (const [k, v] of Object.entries(vars)) root.style.setProperty(k, v);
  root.dataset.cvd = on ? 'on' : 'off';
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

// ---- Coloring rules (Wireshark: View > Coloring Rules) ----
// Each rule is { name, filter, color, enabled }; rules match top-down and the
// first hit tints the packet row. Filters use the display-filter language, so
// anything you can type in the filter box can drive a colour.
const DEFAULT_COLOR_RULES = [
  { name: 'Bad TCP (reset / malformed)', filter: 'tcp.flags.rst == 1 || info contains "Malformed"', color: '#ef4444', enabled: true },
  { name: 'HTTP error response', filter: 'http.response.code >= 400', color: '#f97316', enabled: true },
  { name: 'TCP handshake (SYN / FIN)', filter: 'tcp.flags.syn == 1 || tcp.flags.fin == 1', color: '#94a3b8', enabled: true },
  { name: 'DNS', filter: 'dns || mdns', color: '#a78bfa', enabled: true },
  { name: 'ICMP', filter: 'icmp', color: '#fbbf24', enabled: true },
  { name: 'ARP', filter: 'arp', color: '#9ca3af', enabled: true },
];

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
  settings: Object.assign({ timeFormat: 'time', showHostnames: true, profile: 'HTTP Analysis', theme: 'midnight', noiseFilter: false, lang: detectDefaultLang(), geoip: false, geoipDb: '', textScale: 1, cvd: false }, loadJSON('netscope.settings', {})),
  customProfiles: loadJSON('netscope.profiles', {}),
  // Capture options (autostop limits, save-to-file + ring buffer) applied to
  // the next capture; set in Capture > Options…. Persisted like settings.
  captureOpts: Object.assign({
    stopDurationSecs: '', stopPackets: '', stopFilesizeKb: '',
    outputPath: '', ringFilesizeKb: '', ringDurationSecs: '', ringFiles: '',
  }, loadJSON('netscope.captureopts', {})),
  // Remote (SSH) capture connection details, remembered between sessions.
  remote: Object.assign({
    host: '', user: '', port: '', identity: '', iface: '', filter: '', command: '', sudo: false,
  }, loadJSON('netscope.remote', {})),
  captureStartEpoch: null,
  // Live dashboard sampling (1 Hz): rolling history for the sparkline widgets.
  live: {
    lastSample: null,                 // { packets, bytes, errors, t }
    throughput: [], pps: [], errRate: [], // ring buffers, newest last
    timer: null,
  },
  hostsSeen: new Set(),               // distinct IPs, for "active hosts" + topology
  topo: { layout: new Map(), frozen: false, lastBuilt: 0, view: null },
  // I/O graph samples — packed typed arrays (time, size, error flag) so a
  // whole capture can stream straight into a WebGL buffer (ROADMAP §4.3).
  io: { base: null, t: null, len: null, err: null, n: 0, tMax: 0, lenMax: 0, lastDraw: 0, uploaded: 0 },
  diff: { a: null, b: null },
  alerts: [], alertsSeen: 0,          // Smart Alerts feed
  triggers: loadJSON('netscope.triggers', []), // Event triggers (IFTTT)
  coloring: loadJSON('netscope.coloring', null) || DEFAULT_COLOR_RULES.map((r) => ({ ...r })),
  _colorMatchers: null, // compiled coloring rules, rebuilt lazily after edits
  geoDb: null,          // loaded offline GeoIP database info ({ path, db_type, build_epoch })
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
      // "All interfaces" (a sentinel value) captures on every listed interface
      // at once, Wireshark-style; individual interfaces follow.
      const allOpt = `<option value="__all__">${esc(I18N.t('iface.all'))}</option>`;
      // Hardware-bus sources (USB / Bluetooth / CAN) get a badge so they're
      // recognisable next to network adapters.
      const badge = (k) => (k && k !== 'ethernet' && k !== 'loopback') ? `[${k.toUpperCase()}] ` : '';
      els.interfaceSelect.innerHTML = allOpt + ifaces
        .map((d) => `<option value="${d.name}">${esc(badge(d.kind))}${d.description || d.name}</option>`)
        .join('');
      // Prefer an interface that has a description (physical adapters usually do).
      const best = ifaces.findIndex((d) => /wi-?fi|ethernet|wireless|realtek|intel/i.test(d.description || ''));
      // +1 offsets the prepended "All interfaces" option.
      els.interfaceSelect.selectedIndex = best >= 0 ? best + 1 : 1;
      showNpcapWarning(false);
    } else {
      els.interfaceSelect.innerHTML = `<option>${esc(I18N.t('iface.none'))}</option>`;
      showNpcapWarning(true);
    }
  } catch (e) {
    els.interfaceSelect.innerHTML = `<option>${esc(I18N.t('iface.error'))}</option>`;
    showNpcapWarning(true, String(e && e.message ? e.message : e));
  }
}

const NPCAP_URL = 'https://npcap.com';

/** Show/hide the "capture driver missing" badge. Clicking it opens setup help. */
function showNpcapWarning(show, detail) {
  const badge = $('#npcap-badge');
  if (!badge) return;
  badge.classList.toggle('hidden', !show);
  badge._detail = detail || '';
}

function openNpcapHelp() {
  const detail = ($('#npcap-badge') || {})._detail;
  const body = `
    <p>${esc(I18N.t('npcap.body'))}</p>
    <ul>
      <li><b>Windows:</b> ${esc(I18N.t('npcap.win'))} — <code>${NPCAP_URL}</code></li>
      <li><b>Linux:</b> ${esc(I18N.t('npcap.linux'))}</li>
      <li><b>macOS:</b> ${esc(I18N.t('npcap.mac'))}</li>
    </ul>
    ${detail ? `<pre class="tool-pre">${esc(detail)}</pre>` : ''}`;
  openToolModal(I18N.t('npcap.title'), body, () => copyText(NPCAP_URL));
}

// ---- Capture control ----

/** Reset per-session analysis state before a new capture starts. */
function resetSession() {
  state.packets = []; state.flows.clear(); state.packetCount = 0;
  state.stats = { totalPackets: 0, totalBytes: 0, perProtocol: {}, topTalkersSent: [], topDomains: [], errorPackets: 0 };
  state.hostsSeen.clear();
  state.live.lastSample = null; state.live.throughput = []; state.live.pps = []; state.live.errRate = [];
  state.captureStartEpoch = null; // "Seconds since beginning of capture" baseline resets each run
  ioReset();
}

function markCapturing() {
  setStatus(STATES.CAPTURING);
  els.startBtn.disabled = true;
  els.stopBtn.disabled = false;
  renderAll();
}

/** The Capture>Options values as the backend's `options` argument (camelCase
 *  keys match the Rust CaptureOptionsArg). Empty fields are omitted. */
function buildCaptureOptions() {
  const o = state.captureOpts;
  const num = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : null; };
  const opts = {
    stopDurationSecs: num(o.stopDurationSecs),
    stopPackets: num(o.stopPackets),
    stopFilesizeKb: num(o.stopFilesizeKb),
    outputPath: (o.outputPath || '').trim() || null,
    ringFilesizeKb: num(o.ringFilesizeKb),
    ringDurationSecs: num(o.ringDurationSecs),
    ringFiles: num(o.ringFiles),
  };
  return Object.values(opts).some((v) => v != null) ? opts : null;
}

async function startCapture() {
  const sel = els.interfaceSelect.value;
  // "__all__" expands to every real interface; otherwise capture on the one
  // chosen. The backend merges multiple interfaces into a single stream.
  const interfaces = sel === '__all__'
    ? [...els.interfaceSelect.options].map((o) => o.value).filter((v) => v && v !== '__all__')
    : [sel];
  const filter = els.filterInput.value || null;
  try {
    resetSession();
    await invoke('start_capture', {
      interfaces, filter,
      monitor: !!state.settings.monitor,
      options: buildCaptureOptions(),
    });
    markCapturing();
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

// The backend emits `capture-stopped` when a capture ends on its own — an
// autostop limit (duration/packets/size) was hit, or a remote/USB stream
// ended. Flip the UI back to idle; harmless after a manual stop.
function onCaptureStopped() {
  if (state.status !== STATES.CAPTURING) return;
  setStatus(STATES.IDLE);
  els.startBtn.disabled = false;
  els.stopBtn.disabled = true;
}

// ---- Capture > Options… (autostop + save file + ring buffer) ----
function openCaptureOptions() {
  const o = state.captureOpts;
  const field = (id, label, value, ph) => `
    <label class="capopt-row"><span>${esc(label)}</span>
      <input type="text" id="${id}" value="${esc(String(value || ''))}" placeholder="${esc(ph || '')}" spellcheck="false">
    </label>`;
  const body = `
    <p class="popover-hint">${esc(I18N.t('capopts.hint'))}</p>
    <fieldset class="capopt-group"><legend>${esc(I18N.t('capopts.autostop'))}</legend>
      ${field('co-stop-dur', I18N.t('capopts.stop.duration'), o.stopDurationSecs, '60')}
      ${field('co-stop-pkts', I18N.t('capopts.stop.packets'), o.stopPackets, '10000')}
      ${field('co-stop-size', I18N.t('capopts.stop.filesize'), o.stopFilesizeKb, '10240')}
    </fieldset>
    <fieldset class="capopt-group"><legend>${esc(I18N.t('capopts.file'))}</legend>
      ${field('co-out', I18N.t('capopts.output'), o.outputPath, 'C:\\captures\\session.pcap')}
      ${field('co-ring-size', I18N.t('capopts.ring.filesize'), o.ringFilesizeKb, '2048')}
      ${field('co-ring-dur', I18N.t('capopts.ring.duration'), o.ringDurationSecs, '300')}
      ${field('co-ring-files', I18N.t('capopts.ring.files'), o.ringFiles, '10')}
      <div class="popover-hint">${esc(I18N.t('capopts.ring.hint'))}</div>
    </fieldset>
    <div class="modal-actions">
      <button id="co-clear" class="btn btn-small">${esc(I18N.t('capopts.clear'))}</button>
      <button id="co-apply" class="btn btn-primary">${esc(I18N.t('capopts.apply'))}</button>
    </div>`;
  openToolModal(I18N.t('capopts.title'), body);
  $('#co-apply').addEventListener('click', () => {
    state.captureOpts = {
      stopDurationSecs: $('#co-stop-dur').value.trim(),
      stopPackets: $('#co-stop-pkts').value.trim(),
      stopFilesizeKb: $('#co-stop-size').value.trim(),
      outputPath: $('#co-out').value.trim(),
      ringFilesizeKb: $('#co-ring-size').value.trim(),
      ringDurationSecs: $('#co-ring-dur').value.trim(),
      ringFiles: $('#co-ring-files').value.trim(),
    };
    saveJSON('netscope.captureopts', state.captureOpts);
    closeToolModal();
  });
  $('#co-clear').addEventListener('click', () => {
    state.captureOpts = { stopDurationSecs: '', stopPackets: '', stopFilesizeKb: '', outputPath: '', ringFilesizeKb: '', ringDurationSecs: '', ringFiles: '' };
    saveJSON('netscope.captureopts', state.captureOpts);
    closeToolModal();
  });
}

// ---- Capture > Remote capture (SSH)… — sshdump-style ----
function openRemoteCapture() {
  const r = state.remote;
  const field = (id, label, value, ph) => `
    <label class="capopt-row"><span>${esc(label)}</span>
      <input type="text" id="${id}" value="${esc(String(value || ''))}" placeholder="${esc(ph || '')}" spellcheck="false">
    </label>`;
  const body = `
    <p class="popover-hint">${esc(I18N.t('remote.hint'))}</p>
    ${field('rc-host', I18N.t('remote.host'), r.host, '192.168.1.1')}
    ${field('rc-user', I18N.t('remote.user'), r.user, 'root')}
    ${field('rc-port', I18N.t('remote.port'), r.port, '22')}
    ${field('rc-identity', I18N.t('remote.identity'), r.identity, '~/.ssh/id_ed25519')}
    ${field('rc-iface', I18N.t('remote.iface'), r.iface, 'any')}
    ${field('rc-filter', I18N.t('remote.filter'), r.filter, 'not tcp port 22')}
    ${field('rc-command', I18N.t('remote.command'), r.command, I18N.t('remote.command.ph'))}
    <label class="capopt-row capopt-check"><input type="checkbox" id="rc-sudo" ${r.sudo ? 'checked' : ''}> <span>${esc(I18N.t('remote.sudo'))}</span></label>
    <div class="popover-hint">${esc(I18N.t('remote.auth.hint'))}</div>
    <div class="modal-actions">
      <button id="rc-start" class="btn btn-primary">${esc(I18N.t('remote.start'))}</button>
    </div>`;
  openToolModal(I18N.t('remote.title'), body);
  $('#rc-start').addEventListener('click', startRemoteCapture);
}

async function startRemoteCapture() {
  const r = {
    host: $('#rc-host').value.trim(),
    user: $('#rc-user').value.trim(),
    port: $('#rc-port').value.trim(),
    identity: $('#rc-identity').value.trim(),
    iface: $('#rc-iface').value.trim(),
    filter: $('#rc-filter').value.trim(),
    command: $('#rc-command').value.trim(),
    sudo: $('#rc-sudo').checked,
  };
  if (!r.host) { alert(I18N.t('remote.needhost')); return; }
  state.remote = r;
  saveJSON('netscope.remote', r);
  const startBtn = $('#rc-start');
  startBtn.disabled = true;
  startBtn.textContent = I18N.t('remote.connecting');
  try {
    resetSession();
    // Blocks until the SSH stream starts, so errors (auth, unreachable,
    // tcpdump missing) come back here with the server's message.
    const label = await invoke('start_remote_capture', {
      host: r.host,
      user: r.user || null,
      port: r.port ? parseInt(r.port, 10) : null,
      identityFile: r.identity || null,
      remoteInterface: r.iface || null,
      filter: r.filter || null,
      remoteCommand: r.command || null,
      useSudo: !!r.sudo,
      options: buildCaptureOptions(),
    });
    closeToolModal();
    markCapturing();
    els.statusText.textContent = `${I18N.t('status.capturing')} — ${label}`;
  } catch (e) {
    alert(`${I18N.t('remote.failed')}\n${e}`);
    startBtn.disabled = false;
    startBtn.textContent = I18N.t('remote.start');
  }
}
function setStatus(s) {
  state.status = s;
  els.statusText.textContent = s === STATES.CAPTURING ? I18N.t('status.capturing') : I18N.t('status.idle');
  els.statusText.className = s === STATES.CAPTURING ? 'status-capturing' : 'status-idle';
}

// ---- Packet ingest ----
// Bookkeeping for one packet, no rendering — rendering happens once per
// event (single packet or batch), not once per packet.
function ingestPacket(pkt) {
  state.packets.push(pkt);
  if (state.packets.length > 10000) state.packets.shift();
  state.packetCount++;

  updateStats(pkt);
  updateFlow(pkt);
  ioRecord(pkt);
  if (state.triggers.length) evaluateTriggers(pkt);
}

function refreshAfterIngest() {
  els.packetCount.textContent = `${state.packetCount} ${I18N.t('unit.packets')}`;

  if (state.view === 'packets') renderPacketList();
  else if (state.view === 'connections') renderConnections();
  else if (state.view === 'dashboard') renderStats();
  else if (state.view === 'topology') renderTopology();
  else if (state.view === 'script') updateScriptCount();
}

function onPacket(event) {
  ingestPacket(event.payload);
  refreshAfterIngest();
}

// Batched delivery — the backend sends `packets-batch` arrays when opening
// capture files, so a million-packet pcap costs ~a thousand IPC events and
// one render per batch instead of a million of each.
function onPacketBatch(event) {
  const batch = event.payload || [];
  for (const pkt of batch) ingestPacket(pkt);
  if (batch.length) refreshAfterIngest();
  updateLoadProgress(batch.length);
}

// ---- Flow aggregation (Connections view) ----
function transportOf(proto) {
  if (['TCP', 'HTTP', 'TLS', 'SSH', 'FTP', 'SMTP', 'IMAP', 'POP3', 'Telnet', 'RDP', 'WebSocket', 'HTTP/2', 'gRPC', 'PostgreSQL', 'MySQL', 'MongoDB', 'Redis', 'Cassandra', 'Modbus', 'DNP3', 'EtherNet/IP', 'OPC UA', 'LDAP', 'MQTT', 'BGP'].includes(proto)) return 'tcp';
  if (['UDP', 'DNS', 'DHCP', 'NTP', 'mDNS', 'SNMP', 'QUIC', 'SIP', 'VXLAN', 'BACnet', 'RTP', 'RTCP', 'Kerberos', 'RADIUS', 'OpenVPN', 'WireGuard', 'CoAP'].includes(proto)) return 'udp';
  if (proto === 'ICMP') return 'icmp';
  if (proto === 'ARP') return 'arp';
  return 'other';
}
function protoRank(proto) {
  // WebSocket outranks HTTP (after the upgrade the whole flow is WebSocket);
  // likewise gRPC outranks the HTTP/2 frames it rides on.
  if (proto === 'WebSocket' || proto === 'gRPC') return 5;
  if (proto === 'HTTP' || proto === 'HTTP/2') return 4;
  if (['TLS', 'DNS', 'DHCP', 'NTP', 'mDNS', 'SNMP', 'QUIC', 'SIP', 'SSH', 'FTP', 'SMTP', 'IMAP', 'POP3', 'Telnet', 'RDP', 'VXLAN', 'PostgreSQL', 'MySQL', 'MongoDB', 'Redis', 'Cassandra', 'Modbus', 'DNP3', 'BACnet', 'EtherNet/IP', 'OPC UA', 'RTP', 'RTCP', 'Kerberos', 'LDAP', 'RADIUS', 'OpenVPN', 'WireGuard', 'ESP', 'AH', 'MQTT', 'CoAP', 'BGP', 'OSPF', 'LLDP', 'LACP', 'STP', 'MPLS'].includes(proto)) return 3;
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
      // `epoch` (ms) drives the RTT / flow-graph timing charts (ROADMAP §6.4);
      // `len` lets the flow graph label segment sizes.
      f.pkts.push({ fromClient: pkt.src_addr === f.clientAddr && pkt.src_port === f.clientPort, raw: pkt.raw, ts: pkt.timestamp, epoch: pkt.epoch_ms, len: pkt.length, proto: pkt.protocol });
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
    const isTcp = transportOf(f.proto) === 'tcp';
    const graphBtn = (f.pkts.length && isTcp)
      ? `<button class="btn btn-small btn-graph" data-graph-stream="${esc(f.key)}" title="Plot TCP Stream Graphs (Stevens/tcptrace, throughput, RTT, window)">📈 Graph</button>`
      : '';
    return `
      <div class="conn-row conn-row-grid${isBlocked ? ' blocked' : ''}">
        <span class="mono">${client}</span>
        <span class="conn-server">${server}</span>
        <span class="conn-proto" style="color:${protoColor(f.proto)}">${esc(f.proto)}</span>
        <span>${f.packets}</span>
        <span>${formatBytes(f.bytes)}</span>
        <span class="conn-actions">${followBtn}${graphBtn}${btn}</span>
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

function decodeStreamText(bytes, proto) {
  if (proto === 'HTTP/2') {
    return decodeHttp2Stream(bytes);
  } else if (proto === 'TLS') {
    return decodeTlsStream(bytes);
  } else if (proto === 'QUIC') {
    return decodeQuicStream(bytes);
  }
  return decodePlainStream(bytes);
}

function decodePlainStream(bytes) {
  let out = '';
  for (const b of bytes) {
    if (b === 10 || b === 13 || b === 9) out += String.fromCharCode(b);
    else if (b >= 32 && b < 127) out += String.fromCharCode(b);
    else out += '·';
  }
  return out;
}

function decodeHttp2Stream(bytes) {
  let out = '';
  let off = 0;
  let isPreface = true;
  const pref = [80, 82, 73, 32, 42, 32, 72, 84, 84, 80, 47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10]; // PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
  if (bytes.length >= 24) {
    for (let i = 0; i < 24; i++) {
      if (bytes[i] !== pref[i]) { isPreface = false; break; }
    }
  } else {
    isPreface = false;
  }
  if (isPreface) {
    out += '[HTTP/2 Connection Preface]\n';
    off += 24;
  }

  let frameCount = 0;
  while (off + 9 <= bytes.length) {
    const len = (bytes[off] << 16) | (bytes[off + 1] << 8) | bytes[off + 2];
    const typ = bytes[off + 3];
    const flags = bytes[off + 4];
    const streamId = ((bytes[off + 5] & 0x7f) << 24) | (bytes[off + 6] << 16) | (bytes[off + 7] << 8) | bytes[off + 8];

    const typeNames = ["DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"];
    const typeName = typeNames[typ] || "UNKNOWN";

    out += `HTTP/2 Frame: ${typeName} (Stream ${streamId}, Length: ${len}, Flags: 0x${flags.toString(16).padStart(2, '0')})\n`;

    const payloadStart = off + 9;
    const payloadEnd = Math.min(payloadStart + len, bytes.length);
    if (payloadEnd > payloadStart) {
      const payload = bytes.slice(payloadStart, payloadEnd);
      if (typ === 0) { // DATA
        const txt = decodePlainStream(payload);
        if (txt) out += `  Data: ${txt.substring(0, 200)}\n`;
      } else if (typ === 1) { // HEADERS
        const txt = decodePlainStream(payload);
        if (txt) out += `  Headers (Huffman/Raw): ${txt.substring(0, 200)}\n`;
      }
    }

    off += 9 + len;
    frameCount++;
    if (frameCount > 50) {
      out += '... (truncated HTTP/2 frames)\n';
      break;
    }
  }

  return out || decodePlainStream(bytes);
}

function decodeTlsStream(bytes) {
  let out = '';
  let off = 0;
  let recordCount = 0;
  while (off + 5 <= bytes.length) {
    const contentType = bytes[off];
    const versionMajor = bytes[off + 1];
    const versionMinor = bytes[off + 2];
    const len = (bytes[off + 3] << 8) | bytes[off + 4];

    const typeName = { 20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat" }[contentType];
    if (!typeName) break;

    const versionStr = { 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3", 0x0300: "SSL 3.0" }[(versionMajor << 8) | versionMinor] || "Unknown TLS";

    if (contentType === 22 && off + 6 <= bytes.length) {
      const handshakeType = bytes[off + 5];
      const hsName = { 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished" }[handshakeType] || "Other Handshake";
      out += `TLS Record: Handshake - ${hsName} (${versionStr}, Length: ${len})\n`;
    } else {
      out += `TLS Record: ${typeName} (${versionStr}, Length: ${len})\n`;
    }

    off += 5 + len;
    recordCount++;
    if (recordCount > 50) {
      out += '... (truncated TLS records)\n';
      break;
    }
  }
  return out || decodePlainStream(bytes);
}

function decodeQuicStream(bytes) {
  if (!bytes.length) return '';
  let out = '';
  const first = bytes[0];
  if (first & 0x80) {
    let version = 0;
    if (bytes.length >= 5) {
      version = (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
    }
    const packetType = (first >> 4) & 3;
    const typeName = ["Initial", "0-RTT", "Handshake", "Retry"][packetType] || "Unknown";
    out += `QUIC Long Header Packet: ${typeName} (Version: 0x${version.toString(16).padStart(8, '0')}, Length: ${bytes.length})\n`;
  } else {
    const spin = (first & 0x20) ? "Spin" : "NoSpin";
    out += `QUIC Short Header Packet (1-RTT, Encrypted, ${spin}, Length: ${bytes.length})\n`;
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
    chunks.push({ fromClient: p.fromClient, text: decodeStreamText(payload, p.proto || f.proto) });
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

// Flow key for a packet — must mirror updateFlow()'s key computation exactly,
// so a packet can be traced back to its conversation.
function flowKeyOf(pkt) {
  if (!pkt.src_addr || !pkt.dst_addr) return null;
  const t = transportOf(pkt.protocol);
  const a = `${pkt.src_addr}:${pkt.src_port ?? ''}`;
  const b = `${pkt.dst_addr}:${pkt.dst_port ?? ''}`;
  return (a <= b ? `${a}|${b}` : `${b}|${a}`) + `|${t}`;
}

/** Wireshark's right-click → "Follow TCP Stream", from a single packet. */
function followStreamForPacket(pkt) {
  const key = flowKeyOf(pkt);
  const f = key && state.flows.get(key);
  if (!f || !f.pkts.length) return false;
  openFollowStream(key);
  return true;
}

// ---- Packet context menu (right-click on a packet row) ----
function hideCtxMenu() {
  const m = $('#ctx-menu');
  if (m) m.classList.add('hidden');
}

function showPacketContextMenu(ev, idx) {
  const pkt = state.filteredPackets[idx];
  const menu = $('#ctx-menu');
  if (!pkt || !menu) return;

  const t = transportOf(pkt.protocol);
  const items = [];
  if (t === 'tcp' || t === 'udp') {
    const key = flowKeyOf(pkt);
    const f = key && state.flows.get(key);
    const enabled = !!(f && f.pkts.length);
    items.push({ id: 'follow', label: `💬 Follow ${t.toUpperCase()} Stream`, enabled,
      title: enabled ? '' : 'No captured conversation for this packet' });
    if (t === 'tcp') {
      items.push({ id: 'tcp-graph', label: `📈 TCP Stream Graph`, enabled,
        title: enabled ? '' : 'No TCP stream to graph' });
    }
    items.push({ sep: true });
  }
  if (pkt.src_addr) items.push({ id: 'filter-src', label: `Filter: ip.addr == ${pkt.src_addr}`, enabled: true });
  if (pkt.dst_addr) items.push({ id: 'filter-dst', label: `Filter: ip.addr == ${pkt.dst_addr}`, enabled: true });
  items.push({ id: 'filter-proto', label: `Filter: protocol ${pkt.protocol}`, enabled: true });
  items.push({ sep: true });
  items.push({ id: 'copy-summary', label: '📋 Copy summary', enabled: true });
  items.push({ id: 'copy-hex', label: '📋 Copy Hex Stream', enabled: !!pkt.raw });
  items.push({ id: 'copy-c-array', label: '📋 Copy as C Array', enabled: !!pkt.raw });
  items.push({ id: 'copy-plain-text', label: '📋 Copy as Plain Text (Decoded)', enabled: !!pkt.raw });
  items.push({ id: 'export-bytes', label: '💾 Export Packet Bytes…', enabled: !!pkt.raw });
  if (packetToCurl(pkt)) items.push({ id: 'copy-curl', label: '📋 Copy as cURL', enabled: true });

  menu.innerHTML = items.map((it) => it.sep
    ? '<div class="ctx-sep"></div>'
    : `<button class="ctx-item" data-ctx="${it.id}" ${it.enabled ? '' : 'disabled'}${it.title ? ` title="${esc(it.title)}"` : ''}>${esc(it.label)}</button>`
  ).join('');
  menu.dataset.index = String(idx);

  // Place at the cursor, clamped to the viewport.
  menu.classList.remove('hidden');
  const pad = 6;
  const w = menu.offsetWidth, h = menu.offsetHeight;
  menu.style.left = `${Math.min(ev.clientX, window.innerWidth - w - pad)}px`;
  menu.style.top = `${Math.min(ev.clientY, window.innerHeight - h - pad)}px`;
}

async function onCtxMenuAction(action, idx) {
  const pkt = state.filteredPackets[idx];
  hideCtxMenu();
  if (!pkt) return;
  const applyFilter = (text) => {
    els.filterInput.value = text;
    state.filterText = text;
    renderPacketList();
  };
  switch (action) {
    case 'follow': followStreamForPacket(pkt); break;
    case 'tcp-graph': {
      const key = flowKeyOf(pkt);
      if (key) openTcpStreamGraph(key);
      break;
    }
    case 'filter-src': applyFilter(`ip.addr == ${pkt.src_addr}`); break;
    case 'filter-dst': applyFilter(`ip.addr == ${pkt.dst_addr}`); break;
    case 'filter-proto': applyFilter(pkt.protocol.toLowerCase()); break;
    case 'copy-summary': await copyText(pkt.summary || ''); break;
    case 'copy-hex': copyHexStream(pkt); break;
    case 'copy-c-array': copyCArray(pkt); break;
    case 'copy-plain-text': copyPlainText(pkt); break;
    case 'export-bytes': exportPacketBytes(pkt); break;
    case 'copy-curl': { const c = packetToCurl(pkt); if (c) await copyText(c); break; }
  }
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

// ---- Coloring rules engine + editor ----
let colorRuleGen = 0; // bumped on every rule change to invalidate per-packet caches

function compileColorRules() {
  colorRuleGen++;
  state._colorMatchers = state.coloring.map((r) => {
    if (!r.enabled || !r.filter || typeof NetscopeFilter === 'undefined') return null;
    const c = NetscopeFilter.compile(r.filter);
    return c ? { color: r.color, matches: c.matches } : null;
  });
}

/** First enabled coloring rule that matches `pkt`, or null. Memoized per
 * packet (field extraction parses frame bytes) until the rules change. */
function colorRuleFor(pkt) {
  if (!state._colorMatchers) compileColorRules();
  if (pkt._crGen === colorRuleGen) return pkt._crHit;
  let hit = null;
  for (const m of state._colorMatchers) {
    if (m && m.matches(pkt)) { hit = m; break; }
  }
  pkt._crGen = colorRuleGen;
  pkt._crHit = hit;
  return hit;
}

function saveColoring() {
  saveJSON('netscope.coloring', state.coloring);
  state._colorMatchers = null; // recompile on next render
  renderPacketList();
}

const colorRuleValid = (filter) =>
  !!filter && typeof NetscopeFilter !== 'undefined' && !!NetscopeFilter.compile(filter);

function renderColoringRules() {
  const list = $('#coloring-list');
  if (!list) return;
  list.innerHTML = state.coloring.map((r, i) => `
    <div class="color-rule" data-i="${i}">
      <input type="checkbox" data-cr="enabled" ${r.enabled ? 'checked' : ''} title="Enable / disable this rule">
      <input type="text" class="cr-name" data-cr="name" value="${esc(r.name)}" placeholder="Rule name">
      <input type="text" class="cr-filter mono${colorRuleValid(r.filter) ? '' : ' cr-invalid'}" data-cr="filter"
             value="${esc(r.filter)}" placeholder='display filter — e.g. tcp.flags.rst == 1' spellcheck="false">
      <input type="color" data-cr="color" value="${esc(r.color)}" title="Row colour">
      <button class="btn-icon" data-cr="up" title="Move up — rules match top-down, first hit wins">↑</button>
      <button class="btn-icon" data-cr="del" title="Delete rule">✖</button>
    </div>`).join('') || '<div class="tool-empty">No rules — click “+ Add rule”.</div>';
}

function openColoring() {
  renderColoringRules();
  $('#coloring-modal').classList.remove('hidden');
}
function closeColoring() { $('#coloring-modal').classList.add('hidden'); }

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
// ---- Virtual scrolling (ROADMAP §2.2) ----
// Only the rows inside the viewport (plus overscan) exist in the DOM; a
// spacer gives the list its true height, so a 100k-packet capture scrolls as
// smoothly as a 100-packet one. ROW_H must match .packet-row in styles.css.
const ROW_H = 24;
const VSCROLL_OVERSCAN = 12;

function packetRowHtml(pkt, idx) {
  const c = protoColor(pkt.protocol);
  const isSel = idx === state.selectedIndex;
  const sel = isSel ? ' selected' : '';
  // Coloring rules: the first matching rule tints the row (selection wins).
  const cr = isSel ? null : colorRuleFor(pkt);
  const ruleStyle = cr ? ` style="background:${esc(cr.color)}2b;box-shadow:inset 3px 0 0 ${esc(cr.color)}"` : '';
  const src = esc(endpointLabel(pkt.src_addr, pkt.src_host, pkt.src_port));
  const dst = esc(endpointLabel(pkt.dst_addr, pkt.dst_host, pkt.dst_port));
  const ei = expertInfo(pkt);
  const badge = ei ? `<span class="expert-badge ${ei.cls}" title="${esc(ei.label)}">${ei.icon}</span> ` : '';
  return `
    <div class="packet-row proto-${esc(pkt.protocol)}${sel}" data-index="${idx}"${ruleStyle}>
      <span class="col-num">${idx + 1}</span>
      <span class="col-time" title="${esc(formatPacketTime(pkt))}">${esc(formatPacketTime(pkt))}</span>
      <span class="col-src">${src}</span>
      <span class="col-dir" style="color:${c}">→</span>
      <span class="col-dst">${dst}</span>
      <span class="col-proto" style="color:${c}">${esc(pkt.protocol)}</span>
      <span class="col-len">${pkt.length}B</span>
      <span class="col-info">${badge}${esc(pkt.summary)}</span>
    </div>`;
}

// Re-render just the visible window of the already-filtered list. Called on
// scroll — no filtering, no full-list DOM work.
function renderPacketRows() {
  const packets = state.filteredPackets;
  const scroller = els.packetTable || els.packetList.parentElement;
  const total = packets.length;
  const headerH = els.packetHeader ? els.packetHeader.offsetHeight : 0;
  const viewTop = Math.max(0, scroller.scrollTop - headerH);
  const first = Math.max(0, Math.floor(viewTop / ROW_H) - VSCROLL_OVERSCAN);
  const count = Math.ceil((scroller.clientHeight || 600) / ROW_H) + 2 * VSCROLL_OVERSCAN;
  const last = Math.min(total, first + count);
  const rows = [];
  for (let i = first; i < last; i++) rows.push(packetRowHtml(packets[i], i));
  els.packetList.style.position = 'relative';
  els.packetList.style.height = `${total * ROW_H}px`;
  els.packetList.innerHTML =
    `<div style="position:absolute;top:${first * ROW_H}px;left:0;right:0">${rows.join('')}</div>`;
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

  updateFilterFeedback();

  if (!packets.length) {
    els.packetList.style.height = 'auto';
    els.packetList.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted)">No packets yet</div>';
    return;
  }

  // Follow the tail (as the old tail-slice view did) unless the user has
  // scrolled up to read something.
  const scroller = els.packetTable || els.packetList.parentElement;
  const nearBottom =
    scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 3 * ROW_H;
  renderPacketRows();
  if (nearBottom) scroller.scrollTop = scroller.scrollHeight;
}

// Human transport-layer name for the packet's protocol.
function transportName(proto) {
  if (['TCP', 'HTTP', 'TLS', 'WebSocket', 'HTTP/2', 'gRPC', 'PostgreSQL', 'MySQL', 'MongoDB', 'Redis', 'Cassandra', 'Modbus', 'DNP3', 'EtherNet/IP', 'OPC UA', 'LDAP', 'MQTT', 'BGP'].includes(proto)) return 'TCP';
  if (['UDP', 'DNS', 'BACnet', 'RTP', 'RTCP', 'Kerberos', 'RADIUS', 'OpenVPN', 'WireGuard', 'CoAP'].includes(proto)) return 'UDP';
  if (proto === 'ICMP' || proto === 'ARP') return proto;
  return null;
}
const u16be = (raw, off) => ((raw[off] << 8) | raw[off + 1]) >>> 0;
const macStr = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(':');

// Byte ranges [start, end) of well-known header fields within a raw Ethernet
// frame, so a detail-tree field can highlight its bytes in the hex view.
// Walks VLAN tags and reads the IPv4 IHL / IPv6 fixed header to locate the
// transport ports. Returns only the fields it can place within captured bytes.
function fieldRanges(raw) {
  const R = {};
  if (!raw || raw.length < 14) return R;
  R.ethDst = [0, 6];
  R.ethSrc = [6, 12];
  const VLAN = new Set([0x8100, 0x88a8, 0x9100]);
  let p = 12;
  let et = u16be(raw, p);
  while (VLAN.has(et) && p + 6 <= raw.length) { p += 4; et = u16be(raw, p); }
  R.ethType = [p, p + 2];
  const l3 = p + 2;
  if (et === 0x0800 && raw.length >= l3 + 20) { // IPv4
    const ihl = (raw[l3] & 0x0f) * 4;
    const proto = raw[l3 + 9];
    R.ipProto = [l3 + 9, l3 + 10];
    R.ipSrc = [l3 + 12, l3 + 16];
    R.ipDst = [l3 + 16, l3 + 20];
    const l4 = l3 + ihl;
    if ((proto === 6 || proto === 17) && raw.length >= l4 + 4) {
      R.srcPort = [l4, l4 + 2];
      R.dstPort = [l4 + 2, l4 + 4];
    }
  } else if (et === 0x86dd && raw.length >= l3 + 40) { // IPv6
    const nh = raw[l3 + 6];
    R.ipSrc = [l3 + 8, l3 + 24];
    R.ipDst = [l3 + 24, l3 + 40];
    const l4 = l3 + 40;
    if ((nh === 6 || nh === 17) && raw.length >= l4 + 4) {
      R.srcPort = [l4, l4 + 2];
      R.dstPort = [l4 + 2, l4 + 4];
    }
  }
  return R;
}

// One collapsible protocol layer for the detail tree. Each field is
// [key, value, mono?, range?]; when a byte range is given the row becomes
// clickable to highlight those bytes in the hex view.
function treeNode(label, sub, fields, extraClass = '') {
  const head = `<div class="tnode-head"><span class="twist">▾</span>` +
    `<span class="tlabel">${esc(label)}${sub ? ` <span class="tlabel-sub">${esc(sub)}</span>` : ''}</span></div>`;
  const body = `<div class="tbody">${fields.map(([k, v, mono, range]) => {
    const attrs = range ? ` data-range="${range[0]},${range[1]}"` : '';
    const cls = range ? 'tfield tfield-click' : 'tfield';
    return `<div class="${cls}"${attrs}><span class="tkey">${esc(k)}</span><span class="tval${mono ? ' mono' : ''}">${esc(v)}</span></div>`;
  }).join('')}</div>`;
  return `<div class="tnode ${extraClass}">${head}${body}</div>`;
}

// Build the Wireshark-style layered protocol tree for one packet.
function buildDetailTree(pkt, index) {
  const nodes = [];
  const raw = pkt.raw || [];
  const R = fieldRanges(raw);
  const ipVer = pkt.src_addr ? (pkt.src_addr.includes(':') ? 'IPv6' : 'IPv4') : null;
  const transport = transportName(pkt.protocol);
  const chain = ['Ethernet', ipVer, transport !== pkt.protocol ? transport : null, pkt.protocol]
    .filter((x, i, a) => x && a.indexOf(x) === i);

  // Frame layer
  nodes.push(treeNode(`Frame ${index + 1}`, `${pkt.length} bytes on wire`, [
    ['Arrival time', formatPacketTime(pkt)],
    ['Frame length', `${pkt.length} bytes`],
    ['Captured bytes', `${raw.length} bytes`],
    ['Protocols in frame', chain.join(' · ')],
  ]));

  // Link layer (Ethernet) — click a MAC/EtherType to highlight its bytes.
  if (R.ethDst && raw.length >= 14) {
    nodes.push(treeNode('Ethernet II', '', [
      ['Destination', macStr(raw.slice(R.ethDst[0], R.ethDst[1])), true, R.ethDst],
      ['Source', macStr(raw.slice(R.ethSrc[0], R.ethSrc[1])), true, R.ethSrc],
      ['EtherType', `0x${u16be(raw, R.ethType[0]).toString(16).padStart(4, '0')}`, true, R.ethType],
    ]));
  }

  // Network layer
  if (pkt.src_addr || pkt.dst_addr) {
    const net = [];
    if (pkt.src_addr) net.push(['Source address', pkt.src_addr, true, R.ipSrc]);
    if (state.settings.showHostnames && pkt.src_host) net.push(['Source host', pkt.src_host]);
    if (pkt.dst_addr) net.push(['Destination address', pkt.dst_addr, true, R.ipDst]);
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
      `<span class="tval geo-status">${state.geoDb ? 'Looking up…' : esc(I18N.t('geoip.off'))}</span></div></div></div>`);
  }

  // Transport layer
  if (transport && (pkt.src_port != null || pkt.dst_port != null)) {
    const t = [['Transport', transport]];
    if (pkt.src_port != null) t.push(['Source port', String(pkt.src_port), true, R.srcPort]);
    if (pkt.dst_port != null) t.push(['Destination port', String(pkt.dst_port), true, R.dstPort]);
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

// Flag emoji from a two-letter ISO country code (regional indicators).
function flagEmoji(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

async function lookupGeo(ip) {
  const cached = geoCache.get(ip);
  if (cached && cached.status !== 'pending') return cached;
  if (cached && cached.status === 'pending') return cached.promise;

  const promise = (async () => {
    // Offline MMDB via the backend — fully local, no network call ever.
    if (state.geoDb) {
      try {
        const d = await invoke('geoip_lookup', { ip });
        if (d && (d.country || d.city || d.asn || d.org)) {
          const entry = { status: 'ok', data: {
            country: d.country, code: d.code, flag: flagEmoji(d.code),
            city: d.city, region: d.region,
            isp: d.org, org: d.org, asn: d.asn,
          } };
          geoCache.set(ip, entry);
          return entry;
        }
      } catch { /* unreadable db or bad ip — fall through */ }
    }
    const failed = { status: 'failed' };
    geoCache.set(ip, failed);
    return failed;
  })();
  geoCache.set(ip, { status: 'pending', promise });
  return promise;
}

// ---- Offline GeoIP database (MMDB) ----
// A local MaxMind .mmdb file (e.g. the free GeoLite2-City) resolves locations
// without any network call; the path persists in settings and reloads on start.
function renderGeoDbStatus() {
  if (!els.geoipDbStatus) return;
  if (state.geoDb) {
    const built = new Date(state.geoDb.build_epoch * 1000).toISOString().slice(0, 10);
    els.geoipDbStatus.textContent = `${state.geoDb.db_type} · ${built}`;
    els.geoipDbClear.classList.remove('hidden');
  } else {
    els.geoipDbStatus.textContent = I18N.t('geoip.db.none');
    els.geoipDbClear.classList.add('hidden');
  }
}

async function loadGeoDb(path, { quiet = false } = {}) {
  try {
    state.geoDb = await invoke('geoip_load_db', { path });
    state.settings.geoipDb = path;
  } catch (e) {
    state.geoDb = null;
    state.settings.geoipDb = '';
    if (!quiet && els.geoipDbStatus) els.geoipDbStatus.textContent = String(e);
  }
  saveJSON('netscope.settings', state.settings);
  geoCache.clear(); // stale entries may predate the database switch
  if (state.geoDb || quiet) renderGeoDbStatus();
  if (state.selectedIndex >= 0) showDetail(state.selectedIndex);
}

async function clearGeoDb() {
  state.geoDb = null;
  state.settings.geoipDb = '';
  saveJSON('netscope.settings', state.settings);
  geoCache.clear();
  renderGeoDbStatus();
  try { await invoke('geoip_unload_db'); } catch { /* backend unavailable */ }
  if (state.selectedIndex >= 0) showDetail(state.selectedIndex);
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
  // Works only when an offline GeoIP database is loaded — fully local, no
  // network call. Without a database, locations simply stay unresolved.
  if (!state.geoDb) return;
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

  if (window.__TAURI__) {
    window.__TAURI__.event.emit("packet-selected", pkt);
  }
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
    // Per-byte spans (tagged with their absolute offset) let a detail-tree
    // field highlight exactly its bytes. Missing slots in the last row still
    // emit two spaces so the ASCII column stays aligned (47-char hex column).
    let hex = '';
    for (let j = 0; j < 16; j++) {
      if (j > 0) hex += ' ';
      if (j < chunk.length) {
        hex += `<span class="hb" data-i="${i + j}">${chunk[j].toString(16).padStart(2, '0')}</span>`;
      } else {
        hex += '  ';
      }
    }
    let asc = '';
    for (let j = 0; j < chunk.length; j++) {
      const b = chunk[j];
      const ch = (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
      asc += `<span class="ha" data-i="${i + j}">${esc(ch)}</span>`;
    }
    out += `<span class="hx-off">${i.toString(16).padStart(4, '0')}</span>  ` +
      `<span class="hx-hex">${hex}</span>  ` +
      `<span class="hx-asc">${asc}</span>\n`;
  }
  return out;
}

// Highlight bytes [start, end) in the hex view (both hex and ASCII columns)
// and scroll the first one into view. Called when a detail-tree field is clicked.
function highlightBytes(start, end) {
  const hd = els.hexDump;
  if (!hd) return;
  hd.querySelectorAll('.hl').forEach((el) => el.classList.remove('hl'));
  let first = null;
  for (let i = start; i < end; i++) {
    hd.querySelectorAll(`[data-i="${i}"]`).forEach((el) => {
      el.classList.add('hl');
      if (!first) first = el;
    });
  }
  if (first) first.scrollIntoView({ block: 'nearest' });
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
  renderIoGraph();
  renderRttGraph();
  renderWindowGraph();
  renderHeatmap();
  renderFlowGraph();
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

// ---- Data visualisation (ROADMAP §6.4) ----
// Small SVG/HTML charts computed from the packet ring and flow table: TCP
// round-trip time, TCP window size, a host↔host heatmap and a flow-graph ladder
// for the busiest conversation. All read-only; no backend changes needed.
const TCP_SYN = 0x02, TCP_ACK = 0x10;

// Decode the TCP header fields we chart, from a raw Ethernet frame. Returns
// null for non-TCP frames or ones too short to reach the transport header.
function tcpHeader(raw) {
  if (!raw || raw.length < 34) return null;
  const R = fieldRanges(raw);
  if (!R.srcPort) return null; // srcPort[0] is the transport-header offset (l4)
  const l4 = R.srcPort[0];
  if (raw.length < l4 + 20) return null;
  const dataOff = ((raw[l4 + 12] >> 4) & 0x0f) * 4;
  if (dataOff < 20) return null;
  const seq = ((raw[l4 + 4] << 24) | (raw[l4 + 5] << 16) | (raw[l4 + 6] << 8) | raw[l4 + 7]) >>> 0;
  const ack = ((raw[l4 + 8] << 24) | (raw[l4 + 9] << 16) | (raw[l4 + 10] << 8) | raw[l4 + 11]) >>> 0;
  return { flags: raw[l4 + 13], window: (raw[l4 + 14] << 8) | raw[l4 + 15], seq, ack, hdrLen: dataOff, l4 };
}

function chartEmpty(svg, hint, msg) { svg.innerHTML = ''; if (hint) hint.textContent = msg; }

// TCP handshake RTT per connection: time(SYN→SYN-ACK). One point per flow.
function renderRttGraph() {
  const svg = $('#rtt-chart'), hint = $('#rtt-hint');
  if (!svg) return;
  const pts = [];
  for (const f of state.flows.values()) {
    if (transportOf(f.proto) !== 'tcp') continue;
    let synT = null;
    for (const p of f.pkts) {
      const h = tcpHeader(p.raw);
      if (!h || p.epoch == null) continue;
      if (synT == null && p.fromClient && (h.flags & TCP_SYN) && !(h.flags & TCP_ACK)) synT = p.epoch;
      else if (synT != null && !p.fromClient && (h.flags & TCP_SYN) && (h.flags & TCP_ACK)) {
        const rtt = p.epoch - synT;
        if (rtt >= 0 && rtt < 60000) pts.push({ t: synT, rtt });
        break;
      }
    }
  }
  if (!pts.length) return chartEmpty(svg, hint, 'No completed TCP handshakes yet — RTT needs a SYN → SYN-ACK pair.');
  const W = 300, H = 120, pad = 4;
  const tMin = Math.min(...pts.map((p) => p.t)), tMax = Math.max(...pts.map((p) => p.t));
  const rMax = Math.max(...pts.map((p) => p.rtt), 1);
  const x = (t) => pad + (tMax > tMin ? (t - tMin) / (tMax - tMin) : 0.5) * (W - 2 * pad);
  const y = (r) => H - pad - (r / rMax) * (H - 2 * pad);
  const dots = pts.map((p) =>
    `<circle cx="${x(p.t).toFixed(1)}" cy="${y(p.rtt).toFixed(1)}" r="2.5" fill="var(--accent)"><title>${p.rtt} ms</title></circle>`).join('');
  const median = pts.map((p) => p.rtt).sort((a, b) => a - b)[Math.floor(pts.length / 2)];
  svg.innerHTML = dots;
  hint.textContent = `${pts.length} connection${pts.length === 1 ? '' : 's'} · median setup RTT ${median} ms · max ${rMax} ms`;
}

// TCP advertised window size over time (spots zero-windows / scaling behaviour).
function renderWindowGraph() {
  const svg = $('#window-chart'), hint = $('#window-hint');
  if (!svg) return;
  const pts = [];
  for (const p of state.packets) {
    if (transportOf(p.protocol) !== 'tcp' || p.epoch_ms == null) continue;
    const h = tcpHeader(p.raw);
    if (!h) continue;
    pts.push({ t: p.epoch_ms, win: h.window });
    if (pts.length >= 4000) break;
  }
  if (!pts.length) return chartEmpty(svg, hint, 'No TCP packets yet.');
  const W = 300, H = 120, pad = 4;
  const tMin = Math.min(...pts.map((p) => p.t)), tMax = Math.max(...pts.map((p) => p.t));
  const wMax = Math.max(...pts.map((p) => p.win), 1);
  const x = (t) => pad + (tMax > tMin ? (t - tMin) / (tMax - tMin) : 0.5) * (W - 2 * pad);
  const y = (w) => H - pad - (w / wMax) * (H - 2 * pad);
  const dots = pts.map((p) => {
    const zero = p.win === 0;
    return `<circle cx="${x(p.t).toFixed(1)}" cy="${y(p.win).toFixed(1)}" r="${zero ? 3 : 1.6}" fill="${zero ? 'var(--danger)' : 'var(--tcp)'}" opacity="${zero ? 1 : 0.55}"/>`;
  }).join('');
  const zeros = pts.filter((p) => p.win === 0).length;
  svg.innerHTML = dots;
  hint.textContent = `${pts.length} segments · max window ${wMax.toLocaleString()} B${zeros ? ` · ⚠ ${zeros} zero-window` : ''}`;
}

// Host ↔ host communication-intensity heatmap over the top talkers.
function renderHeatmap() {
  const grid = $('#heatmap-grid'), hint = $('#heatmap-hint');
  if (!grid) return;
  const bytesByHost = new Map();
  const pair = new Map(); // "a|b" -> bytes (a,b sorted)
  for (const f of state.flows.values()) {
    const a = f.clientAddr, b = f.serverAddr;
    if (!a || !b) continue;
    bytesByHost.set(a, (bytesByHost.get(a) || 0) + f.bytes);
    bytesByHost.set(b, (bytesByHost.get(b) || 0) + f.bytes);
    const key = a <= b ? `${a}|${b}` : `${b}|${a}`;
    pair.set(key, (pair.get(key) || 0) + f.bytes);
  }
  const hosts = [...bytesByHost.entries()].sort((x, y) => y[1] - x[1]).slice(0, 8).map((e) => e[0]);
  if (hosts.length < 2) { grid.innerHTML = ''; if (hint) hint.textContent = 'Need at least two hosts talking.'; return; }
  let max = 1;
  for (const key of pair.keys()) { const [a, b] = key.split('|'); if (hosts.includes(a) && hosts.includes(b)) max = Math.max(max, pair.get(key)); }
  const short = (ip) => ip.length > 15 ? ip.slice(0, 13) + '…' : ip;
  const cell = (a, b) => {
    if (a === b) return '<div class="hm-cell hm-diag"></div>';
    const key = a <= b ? `${a}|${b}` : `${b}|${a}`;
    const v = pair.get(key) || 0;
    const intensity = v ? 0.12 + 0.88 * (Math.log(v + 1) / Math.log(max + 1)) : 0;
    return `<div class="hm-cell" style="background:rgba(74,158,245,${intensity.toFixed(2)})" title="${esc(a)} ↔ ${esc(b)}: ${formatBytes(v)}"></div>`;
  };
  // Header row + one row per host.
  const header = `<div class="hm-cell hm-corner"></div>` + hosts.map((h) => `<div class="hm-label hm-col" title="${esc(h)}">${esc(short(h))}</div>`).join('');
  const rows = hosts.map((r) => `<div class="hm-label hm-row" title="${esc(r)}">${esc(short(r))}</div>` + hosts.map((c) => cell(r, c)).join('')).join('');
  grid.style.gridTemplateColumns = `120px repeat(${hosts.length}, 1fr)`;
  grid.innerHTML = header + rows;
  if (hint) hint.textContent = `Top ${hosts.length} hosts · darker = more bytes exchanged`;
}

// Flow-graph ladder (Wireshark's Flow Graph) for the busiest conversation.
function renderFlowGraph() {
  const svg = $('#flowgraph-svg'), hint = $('#flowgraph-hint');
  if (!svg) return;
  let best = null;
  for (const f of state.flows.values()) {
    if ((transportOf(f.proto) === 'tcp' || transportOf(f.proto) === 'udp') && f.pkts.length && (!best || f.bytes > best.bytes)) best = f;
  }
  if (!best) { svg.innerHTML = ''; if (hint) hint.textContent = 'No TCP/UDP conversation yet.'; return; }
  // Sample down to at most 40 packets so the ladder stays readable.
  let pkts = best.pkts;
  if (pkts.length > 40) { const step = pkts.length / 40; pkts = Array.from({ length: 40 }, (_, i) => pkts[Math.floor(i * step)]); }
  const W = 300, rowH = 18, top = 26, H = top + pkts.length * rowH + 8;
  const xC = 60, xS = W - 60;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  const t0 = pkts[0].epoch;
  let out = '';
  out += `<line x1="${xC}" y1="20" x2="${xC}" y2="${H - 4}" stroke="var(--border)"/>`;
  out += `<line x1="${xS}" y1="20" x2="${xS}" y2="${H - 4}" stroke="var(--border)"/>`;
  out += `<text x="${xC}" y="14" fill="var(--text-muted)" font-size="9" text-anchor="middle">client</text>`;
  out += `<text x="${xS}" y="14" fill="var(--text-muted)" font-size="9" text-anchor="middle">server</text>`;
  pkts.forEach((p, i) => {
    const y = top + i * rowH;
    const h = tcpHeader(p.raw);
    const label = h ? tcpFlagLabel(h.flags) : `${p.len}B`;
    const dt = p.epoch != null && t0 != null ? `+${((p.epoch - t0)).toFixed(0)}ms` : '';
    const x1 = p.fromClient ? xC : xS, x2 = p.fromClient ? xS : xC;
    const color = p.fromClient ? 'var(--accent)' : 'var(--http)';
    out += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${color}" stroke-width="1.3" marker-end="url(#fg-arrow)"><title>${esc(label)} ${dt}</title></line>`;
    out += `<text x="${(xC + xS) / 2}" y="${y - 2}" fill="var(--text-muted)" font-size="8" text-anchor="middle">${esc(label)}</text>`;
  });
  const arrow = `<defs><marker id="fg-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--text-muted)"/></marker></defs>`;
  svg.innerHTML = arrow + out;
  const client = endpointLabel(best.clientAddr, null, best.clientPort);
  const server = endpointLabel(best.serverAddr, best.serverHost, best.serverPort);
  if (hint) hint.textContent = `${client} ⇄ ${server} · ${best.pkts.length} pkt shown${best.pkts.length > 40 ? ' (sampled)' : ''}`;
}

function tcpFlagLabel(flags) {
  const names = [];
  if (flags & 0x02) names.push('SYN');
  if (flags & 0x10) names.push('ACK');
  if (flags & 0x01) names.push('FIN');
  if (flags & 0x04) names.push('RST');
  if (flags & 0x08) names.push('PSH');
  return names.join(' ') || 'data';
}

// ---- TCP Stream Graphs (Stevens/tcptrace, throughput, RTT, window) ----
let tcpGraphState = { key: null, type: 'stevens' };

function closeTcpStreamGraph() {
  $('#tcp-graph-modal').classList.add('hidden');
}

function openTcpStreamGraph(key, type = 'stevens') {
  tcpGraphState.key = key;
  tcpGraphState.type = type;

  const f = state.flows.get(key);
  if (!f || !f.pkts.length) return;

  // Update modal active tabs
  $$('#tcp-graph-modal .modal-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.graph === type);
  });

  const client = endpointLabel(f.clientAddr, null, f.clientPort);
  const server = endpointLabel(f.serverAddr, f.serverHost, f.serverPort);
  $('#tcp-graph-title').innerHTML = `📈 TCP Stream Graph — <span class="mono">${esc(client)}</span> ⇄ ${esc(server)}`;

  const pkts = f.pkts.filter(p => {
    const proto = (p.protocol || '').toLowerCase();
    return proto === 'tcp' || proto === 'tls' || proto === 'http';
  });

  if (!pkts.length) {
    $('#tcp-graph-svg').innerHTML = '';
    $('#tcp-graph-hint').textContent = 'No TCP segments found in this conversation.';
    $('#tcp-graph-meta').textContent = 'Empty conversation.';
    $('#tcp-graph-modal').classList.remove('hidden');
    return;
  }

  const t0 = pkts[0].epoch;
  const parsedPackets = [];

  let clientIsn = null;
  let serverIsn = null;

  // Find ISNs
  for (const p of pkts) {
    const h = tcpHeader(p.raw);
    if (!h) continue;
    if (p.fromClient) {
      if (clientIsn === null) clientIsn = h.seq;
      if (h.flags & 0x02) clientIsn = h.seq; // SYN
    } else {
      if (serverIsn === null) serverIsn = h.seq;
      if (h.flags & 0x02) serverIsn = h.seq; // SYN
    }
  }
  if (clientIsn === null) clientIsn = 0;
  if (serverIsn === null) serverIsn = 0;

  for (const p of pkts) {
    const h = tcpHeader(p.raw);
    if (!h) continue;

    const relSeq = (h.seq >= clientIsn) ? (h.seq - clientIsn) : (0xffffffff - clientIsn + h.seq + 1);
    const relAck = (h.ack >= serverIsn) ? (h.ack - serverIsn) : (0xffffffff - serverIsn + h.ack + 1);

    parsedPackets.push({
      p,
      h,
      t: p.epoch - t0,
      relSeq,
      relAck,
      len: p.length || 0,
      window: h.window
    });
  }

  const totalPkts = parsedPackets.length;
  const duration = (pkts[pkts.length - 1].epoch - t0) / 1000; // seconds
  $('#tcp-graph-meta').textContent = `${totalPkts} segments analysed · duration ${duration.toFixed(2)}s · Client ISN: ${clientIsn} · Server ISN: ${serverIsn}`;

  const svg = $('#tcp-graph-svg');
  const W = 600, H = 300;
  const padLeft = 60, padRight = 20, padTop = 20, padBottom = 40;
  const chartW = W - padLeft - padRight;
  const chartH = H - padTop - padBottom;

  let points = [];
  let xLabel = 'Time (ms)';
  let yLabel = '';

  if (type === 'stevens') {
    yLabel = 'Relative Sequence Number (B)';
    parsedPackets.forEach(item => {
      if (item.p.fromClient) {
        points.push({ x: item.t, y: item.relSeq, color: 'var(--accent)', label: `Client Seq: ${item.relSeq} (${item.len} B)` });
      } else {
        points.push({ x: item.t, y: item.relAck, color: 'var(--http)', label: `Server Ack: ${item.relAck}` });
      }
    });
  } else if (type === 'throughput') {
    yLabel = 'Throughput (KB/s)';
    const interval = 200; // ms
    const buckets = {};
    parsedPackets.forEach(item => {
      const bucketIdx = Math.floor(item.t / interval);
      buckets[bucketIdx] = (buckets[bucketIdx] || 0) + item.len;
    });
    const maxBucket = Math.ceil((pkts[pkts.length - 1].epoch - t0) / interval);
    for (let i = 0; i <= maxBucket; i++) {
      const bytes = buckets[i] || 0;
      const throughput = (bytes / 1024) / (interval / 1000); // KB/s
      points.push({ x: i * interval + interval / 2, y: throughput, color: 'var(--accent)', label: `Throughput: ${throughput.toFixed(1)} KB/s` });
    }
  } else if (type === 'rtt') {
    yLabel = 'Handshake / Segment RTT (ms)';
    const sentTimes = new Map();
    parsedPackets.forEach(item => {
      if (item.p.fromClient) {
        sentTimes.set(item.relSeq, item.t);
      } else {
        const clientSentTime = sentTimes.get(item.relAck - item.len);
        if (clientSentTime !== undefined) {
          const rttVal = item.t - clientSentTime;
          if (rttVal > 0 && rttVal < 1000) {
            points.push({ x: item.t, y: rttVal, color: 'var(--danger)', label: `RTT: ${rttVal.toFixed(1)} ms` });
          }
        }
      }
    });
    if (points.length === 0) {
      let synTime = null;
      for (const item of parsedPackets) {
        if (item.p.fromClient && (item.h.flags & 0x02)) synTime = item.t;
        else if (synTime !== null && !item.p.fromClient && (item.h.flags & 0x12) === 0x12) {
          points.push({ x: item.t, y: item.t - synTime, color: 'var(--danger)', label: `Handshake RTT: ${(item.t - synTime).toFixed(1)} ms` });
          break;
        }
      }
    }
  } else if (type === 'window') {
    yLabel = 'Advertised Window (B)';
    parsedPackets.forEach(item => {
      points.push({ x: item.t, y: item.window, color: item.p.fromClient ? 'var(--accent)' : 'var(--http)', label: `${item.p.fromClient ? 'Client' : 'Server'} Window: ${item.window.toLocaleString()} B` });
    });
  }

  if (points.length === 0) {
    svg.innerHTML = '';
    $('#tcp-graph-hint').textContent = 'Not enough data points to plot this graph type.';
    $('#tcp-graph-modal').classList.remove('hidden');
    return;
  }

  const xMin = 0;
  const xMax = Math.max(...points.map(p => p.x), 1);
  const yMin = 0;
  const yMax = Math.max(...points.map(p => p.y), 1) * 1.1;

  const scaleX = (xVal) => padLeft + (xVal / xMax) * chartW;
  const scaleY = (yVal) => H - padBottom - (yVal / yMax) * chartH;

  let out = '';

  out += `<line x1="${padLeft}" y1="${padTop}" x2="${padLeft}" y2="${H - padBottom}" stroke="var(--border)" stroke-width="1"/>`;
  out += `<line x1="${padLeft}" y1="${H - padBottom}" x2="${W - padRight}" y2="${H - padBottom}" stroke="var(--border)" stroke-width="1"/>`;

  const xTicks = 5;
  for (let i = 0; i <= xTicks; i++) {
    const val = (xMax / xTicks) * i;
    const sx = scaleX(val);
    out += `<line x1="${sx}" y1="${padTop}" x2="${sx}" y2="${H - padBottom}" stroke="var(--border)" stroke-dasharray="2,4" opacity="0.3"/>`;
    out += `<text x="${sx}" y="${H - padBottom + 16}" fill="var(--text-muted)" font-size="10" text-anchor="middle">${val.toFixed(0)}</text>`;
  }

  const yTicks = 4;
  for (let i = 0; i <= yTicks; i++) {
    const val = (yMax / yTicks) * i;
    const sy = scaleY(val);
    out += `<line x1="${padLeft}" y1="${sy}" x2="${W - padRight}" y2="${sy}" stroke="var(--border)" stroke-dasharray="2,4" opacity="0.3"/>`;
    let labelText = val.toFixed(0);
    if (val >= 1000000) labelText = (val / 1000000).toFixed(1) + 'M';
    else if (val >= 1000) labelText = (val / 1000).toFixed(0) + 'K';
    out += `<text x="${padLeft - 8}" y="${sy + 4}" fill="var(--text-muted)" font-size="10" text-anchor="end">${labelText}</text>`;
  }

  out += `<text x="${padLeft + chartW / 2}" y="${H - 8}" fill="var(--text)" font-size="11" font-weight="600" text-anchor="middle">${esc(xLabel)}</text>`;
  out += `<text x="14" y="${padTop + chartH / 2}" fill="var(--text)" font-size="11" font-weight="600" text-anchor="middle" transform="rotate(-90 14 ${padTop + chartH / 2})">${esc(yLabel)}</text>`;

  if (type === 'throughput' && points.length > 1) {
    const pathD = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${scaleX(p.x).toFixed(1)} ${scaleY(p.y).toFixed(1)}`).join(' ');
    out += `<path d="${pathD}" fill="none" stroke="var(--accent)" stroke-width="2"/>`;
  }

  points.forEach(p => {
    const cx = scaleX(p.x);
    const cy = scaleY(p.y);
    out += `<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="${type === 'stevens' ? 2 : 3}" fill="${p.color}" class="graph-dot"><title>${esc(p.label)} at ${p.x.toFixed(0)} ms</title></circle>`;
  });

  svg.innerHTML = out;
  $('#tcp-graph-hint').textContent = `Hover over points to inspect individual TCP segments. Toggle tabs above to view other metrics.`;
  $('#tcp-graph-modal').classList.remove('hidden');
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
  renderGeoDbStatus();
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

// ---- GPU rendering (WebGL) — ROADMAP §4.3 --------------------------------
// Shared helpers for the I/O graph scatter and the large-graph topology
// renderer. Both fall back to the existing DOM/SVG paths when WebGL is
// unavailable (software rasterisers, remote desktops).

function glContext(canvas) {
  if (!canvas) return null;
  if (canvas._gl) return canvas._gl;
  if (canvas._glFailed) return null;
  const gl = canvas.getContext('webgl', { antialias: true, alpha: true, premultipliedAlpha: false });
  if (gl) canvas._gl = gl; else canvas._glFailed = true;
  return gl;
}
function glProgram(gl, key, vsSrc, fsSrc) {
  gl._progs = gl._progs || {};
  if (gl._progs[key]) return gl._progs[key];
  const sh = (type, src) => {
    const s = gl.createShader(type);
    gl.shaderSource(s, src); gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s) || 'shader compile error');
    return s;
  };
  const p = gl.createProgram();
  gl.attachShader(p, sh(gl.VERTEX_SHADER, vsSrc));
  gl.attachShader(p, sh(gl.FRAGMENT_SHADER, fsSrc));
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p) || 'shader link error');
  gl._progs[key] = p;
  return p;
}
// CSS var (e.g. '--tcp') → [r,g,b] in 0..1, so shaders follow the active theme.
function cssRgb(varName) {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
  let m = raw.match(/^#([0-9a-f]{6})$/i);
  if (m) { const v = parseInt(m[1], 16); return [((v >> 16) & 255) / 255, ((v >> 8) & 255) / 255, (v & 255) / 255]; }
  m = raw.match(/^#([0-9a-f]{3})$/i);
  if (m) return [...m[1]].map((c) => parseInt(c + c, 16) / 255);
  m = raw.match(/rgba?\(([^)]+)\)/);
  if (m) { const [r, g, b] = m[1].split(',').map(parseFloat); return [r / 255, g / 255, b / 255]; }
  return [0.5, 0.6, 0.7];
}
// Size the drawing buffer to CSS pixels × devicePixelRatio; false if hidden.
function glFit(canvas) {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return false;
  const dpr = window.devicePixelRatio || 1;
  const W = Math.round(w * dpr), H = Math.round(h * dpr);
  if (canvas.width !== W || canvas.height !== H) { canvas.width = W; canvas.height = H; }
  return true;
}

// ---- I/O graph — every packet as a GPU point (time × size) ---------------
// One point per packet: x = time, y = packet size (log scale), red = error
// (RST / malformed). A bucketed packets-per-second line runs on top. Points
// live in a GPU buffer that grows incrementally, so redrawing a
// million-packet capture is two draw calls, not a million DOM nodes.

function ioReset() {
  state.io = { base: null, t: null, len: null, err: null, n: 0, tMax: 0, lenMax: 0, lastDraw: 0, uploaded: 0 };
  const gl = els.ioGl && els.ioGl._gl;
  if (gl && gl._io) gl._io.cap = 0; // force a fresh upload on the next draw
}
function ioRecord(pkt) {
  if (pkt.epoch_ms == null) return;
  const io = state.io;
  if (io.base == null) io.base = pkt.epoch_ms;
  if (!io.t) { io.t = new Float32Array(8192); io.len = new Float32Array(8192); io.err = new Uint8Array(8192); }
  if (io.n === io.t.length) {
    const grow = (a, C) => { const b = new C(a.length * 2); b.set(a); return b; };
    io.t = grow(io.t, Float32Array); io.len = grow(io.len, Float32Array); io.err = grow(io.err, Uint8Array);
  }
  const t = (pkt.epoch_ms - io.base) / 1000;
  io.t[io.n] = t;
  io.len[io.n] = pkt.length;
  io.err[io.n] = pkt.summary.includes('reset (RST)') || pkt.summary.includes('Malformed') ? 1 : 0;
  io.n++;
  if (t > io.tMax) io.tMax = t;
  if (pkt.length > io.lenMax) io.lenMax = pkt.length;
}

const IO_VS = `
attribute vec3 a_p;          // x: seconds, y: bytes, z: error flag
uniform vec2 u_t;            // tMin, tSpan
uniform float u_lenMax;
uniform float u_ps;
varying float v_err;
void main() {
  float x = (a_p.x - u_t.x) / u_t.y * 1.94 - 0.97;
  float y = log(1.0 + a_p.y) / log(1.0 + u_lenMax) * 1.8 - 0.94;
  gl_Position = vec4(x, y, 0.0, 1.0);
  gl_PointSize = u_ps;
  v_err = a_p.z;
}`;
const IO_FS = `
precision mediump float;
varying float v_err;
uniform vec3 u_cNorm;
uniform vec3 u_cErr;
uniform float u_alpha;
void main() {
  vec2 d = gl_PointCoord - vec2(0.5);
  if (dot(d, d) > 0.25) discard;
  gl_FragColor = vec4(mix(u_cNorm, u_cErr, v_err), u_alpha);
}`;
const LINE_VS = `
attribute vec2 a_p;          // already in clip space
void main() { gl_Position = vec4(a_p, 0.0, 1.0); }`;
const LINE_FS = `
precision mediump float;
uniform vec4 u_color;
void main() { gl_FragColor = u_color; }`;

function renderIoGraph(force = false) {
  const canvas = els.ioGl;
  if (!canvas || state.view !== 'dashboard') return;
  const now = performance.now();
  if (!force && now - state.io.lastDraw < 400) return; // ~2 fps is plenty for a dashboard
  state.io.lastDraw = now;

  const io = state.io;
  const gl = glContext(canvas);
  if (!gl) {
    canvas.style.display = 'none';
    if (els.ioHint) els.ioHint.textContent = I18N.t('io.nogl');
    return;
  }
  if (!glFit(canvas)) return;
  gl.viewport(0, 0, canvas.width, canvas.height);
  const bg = cssRgb('--bg');
  gl.clearColor(bg[0], bg[1], bg[2], 1);
  gl.clear(gl.COLOR_BUFFER_BIT);
  if (!io.n) {
    if (els.ioHint) els.ioHint.textContent = I18N.t('io.empty');
    return;
  }

  gl.enable(gl.BLEND);
  gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

  // Scatter — packed [t, len, err] per point. The GPU buffer grows by
  // doubling; new points are appended with bufferSubData, so a steady live
  // capture uploads only its delta each frame.
  const prog = glProgram(gl, 'io', IO_VS, IO_FS);
  gl.useProgram(prog);
  gl._io = gl._io || { buf: gl.createBuffer(), cap: 0 };
  const st = gl._io;
  gl.bindBuffer(gl.ARRAY_BUFFER, st.buf);
  const pack = (from, to) => {
    const out = new Float32Array((to - from) * 3);
    for (let i = from, j = 0; i < to; i++, j += 3) { out[j] = io.t[i]; out[j + 1] = io.len[i]; out[j + 2] = io.err[i]; }
    return out;
  };
  if (io.n > st.cap || io.uploaded > io.n) {
    st.cap = Math.max(8192, 1 << Math.ceil(Math.log2(io.n)));
    gl.bufferData(gl.ARRAY_BUFFER, st.cap * 12, gl.DYNAMIC_DRAW);
    gl.bufferSubData(gl.ARRAY_BUFFER, 0, pack(0, io.n));
  } else if (io.n > io.uploaded) {
    gl.bufferSubData(gl.ARRAY_BUFFER, io.uploaded * 12, pack(io.uploaded, io.n));
  }
  io.uploaded = io.n;

  const aP = gl.getAttribLocation(prog, 'a_p');
  gl.enableVertexAttribArray(aP);
  gl.vertexAttribPointer(aP, 3, gl.FLOAT, false, 0, 0);
  const span = Math.max(io.tMax, 0.001);
  gl.uniform2f(gl.getUniformLocation(prog, 'u_t'), 0, span);
  gl.uniform1f(gl.getUniformLocation(prog, 'u_lenMax'), Math.max(io.lenMax, 64));
  const dpr = window.devicePixelRatio || 1;
  gl.uniform1f(gl.getUniformLocation(prog, 'u_ps'), (io.n > 200000 ? 1.6 : io.n > 20000 ? 2.2 : 3) * dpr);
  gl.uniform3fv(gl.getUniformLocation(prog, 'u_cNorm'), cssRgb('--tcp'));
  gl.uniform3fv(gl.getUniformLocation(prog, 'u_cErr'), [0.973, 0.443, 0.443]); // #f87171
  gl.uniform1f(gl.getUniformLocation(prog, 'u_alpha'), io.n > 50000 ? 0.35 : 0.75);
  gl.drawArrays(gl.POINTS, 0, io.n);

  // Packets-per-second line — aggregated on the CPU (one pass over the
  // typed array), drawn as a GPU line strip over the scatter.
  const buckets = Math.max(8, Math.min(360, Math.ceil(span)));
  const counts = new Float32Array(buckets);
  for (let i = 0; i < io.n; i++) {
    let b = Math.floor((io.t[i] / span) * buckets);
    if (b >= buckets) b = buckets - 1;
    counts[b]++;
  }
  const perSec = buckets / span; // bucket count → pps factor
  let peak = 0;
  for (let i = 0; i < buckets; i++) { counts[i] *= perSec; if (counts[i] > peak) peak = counts[i]; }
  if (peak > 0) {
    const line = new Float32Array(buckets * 2);
    for (let i = 0; i < buckets; i++) {
      line[i * 2] = ((i + 0.5) / buckets) * 1.94 - 0.97;
      line[i * 2 + 1] = (counts[i] / peak) * 1.8 - 0.94;
    }
    const lprog = glProgram(gl, 'line', LINE_VS, LINE_FS);
    gl.useProgram(lprog);
    gl._ioLine = gl._ioLine || gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, gl._ioLine);
    gl.bufferData(gl.ARRAY_BUFFER, line, gl.DYNAMIC_DRAW);
    const aL = gl.getAttribLocation(lprog, 'a_p');
    gl.enableVertexAttribArray(aL);
    gl.vertexAttribPointer(aL, 2, gl.FLOAT, false, 0, 0);
    const ac = cssRgb('--ok');
    gl.uniform4f(gl.getUniformLocation(lprog, 'u_color'), ac[0], ac[1], ac[2], 0.9);
    gl.drawArrays(gl.LINE_STRIP, 0, buckets);
  }

  if (els.ioHint) {
    els.ioHint.textContent =
      `${io.n.toLocaleString()} packets · ${span.toFixed(1)}s · peak ${Math.round(peak)} pps · ` +
      `dots = packets (y: size, log) · line = pps · GPU`;
  }
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
  renderIoGraph();
}

// ---- Topology map — live node/edge graph of who talks to whom ----
// A small force-directed layout over the connection flows. Node size ~ traffic,
// colour = local (private) vs. remote (public). Positions persist between rebuilds
// so the graph settles instead of jumping every second.
const TOPO_MAX_NODES = 60;        // SVG path — labels + tooltips stay readable
const TOPO_GL_THRESHOLD = 150;    // above this many hosts, switch to WebGL (§4.3)
const TOPO_MAX_NODES_GL = 1500;   // GPU path cap — busiest hosts, same rule as SVG
function buildTopologyGraph(cap = TOPO_MAX_NODES) {
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
  const keep = [...nodeBytes.entries()].sort((a, b) => b[1] - a[1]).slice(0, cap);
  const kept = new Set(keep.map(([a]) => a));
  const nodes = keep.map(([addr, bytes]) => ({ addr, bytes, host: nodeHost.get(addr) || null, local: !isPublicIp(addr) }));
  const edgeList = [];
  for (const [key, bytes] of edges) {
    const [a, b] = key.split('|');
    if (kept.has(a) && kept.has(b)) edgeList.push({ a, b, bytes });
  }
  return { nodes, edges: edgeList, total: nodeBytes.size };
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
  const N = graph.nodes.length;
  // Large graphs get fewer, cheaper iterations: repulsion via a spatial grid
  // (only neighbouring cells interact) keeps relaxation ~O(n·k) instead of
  // O(n²), so a 1500-node GPU-rendered graph still lays out interactively.
  const ITER = N > 800 ? 14 : N > 250 ? 30 : 70;
  const useGrid = N > 250;
  const REP = 42000, SPRING = 0.012, IDEAL = 130, CELL = IDEAL * 1.2;
  for (let it = 0; it < ITER; it++) {
    for (const n of graph.nodes) { const p = pos.get(n.addr); p.fx = 0; p.fy = 0; }
    // repulsion
    if (useGrid) {
      const grid = new Map(); // "cx,cy" -> positions in that cell
      for (const n of graph.nodes) {
        const p = pos.get(n.addr);
        const key = `${Math.floor(p.x / CELL)},${Math.floor(p.y / CELL)}`;
        let cell = grid.get(key);
        if (!cell) { cell = []; grid.set(key, cell); }
        cell.push(p);
      }
      for (const n of graph.nodes) {
        const pi = pos.get(n.addr);
        const gx = Math.floor(pi.x / CELL), gy = Math.floor(pi.y / CELL);
        for (let ox = -1; ox <= 1; ox++) for (let oy = -1; oy <= 1; oy++) {
          const cell = grid.get(`${gx + ox},${gy + oy}`);
          if (!cell) continue;
          for (const pj of cell) {
            if (pj === pi) continue;
            const dx = pi.x - pj.x, dy = pi.y - pj.y;
            const d2 = dx * dx + dy * dy || 0.01;
            const f = REP / d2;
            const d = Math.sqrt(d2);
            pi.fx += (dx / d) * f; pi.fy += (dy / d) * f;
          }
        }
      }
    } else {
      // all pairs — exact, fine for small graphs
      for (let i = 0; i < N; i++) {
        const pi = pos.get(graph.nodes[i].addr);
        for (let j = i + 1; j < N; j++) {
          const pj = pos.get(graph.nodes[j].addr);
          let dx = pi.x - pj.x, dy = pi.y - pj.y;
          let d2 = dx * dx + dy * dy || 0.01;
          const f = REP / d2;
          const d = Math.sqrt(d2);
          const ux = dx / d, uy = dy / d;
          pi.fx += ux * f; pi.fy += uy * f; pj.fx -= ux * f; pj.fy -= uy * f;
        }
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

  // Big graphs go to the WebGL layer (§4.3) — SVG DOM stops scaling past a
  // few hundred nodes. Small graphs keep the SVG path: labels, hover
  // tooltips and click-to-inspect stay intact there.
  let graph = buildTopologyGraph(TOPO_MAX_NODES_GL);
  const gl = graph.total > TOPO_GL_THRESHOLD ? glContext(els.topologyGl) : null;
  if (!gl && graph.nodes.length > TOPO_MAX_NODES) {
    // WebGL unavailable (or small graph): keep the readable SVG cap.
    const keptNodes = graph.nodes.slice(0, TOPO_MAX_NODES);
    const kept = new Set(keptNodes.map((n) => n.addr));
    graph = { nodes: keptNodes, edges: graph.edges.filter((e) => kept.has(e.a) && kept.has(e.b)), total: graph.total };
  }
  if (els.topologyWrap) els.topologyWrap.classList.toggle('gl', !!gl);
  if (!gl && els.topologyLabels) els.topologyLabels.innerHTML = '';

  const ofTotal = graph.total > graph.nodes.length ? ` of ${graph.total}` : '';
  els.topologySummary.textContent = graph.nodes.length
    ? `${graph.nodes.length}${ofTotal} hosts · ${graph.edges.length} conversations${gl ? ' · GPU' : ''}`
    : I18N.t('topo.empty');
  if (!graph.nodes.length) { svg.innerHTML = ''; els.topologyLegend.innerHTML = ''; return; }

  layoutTopology(graph);
  if (gl) { renderTopologyGL(gl, graph); return; }
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

// WebGL topology renderer — edges as GL lines, hosts as round point sprites.
// Handles thousands of nodes at full frame rate where the SVG DOM would
// spend seconds per rebuild (ROADMAP §4.3). Labels for the busiest hosts are
// overlaid as positioned HTML so the map keeps its bearings.
const TOPO_VS = `
attribute vec2 a_pos;    // clip space
attribute float a_size;  // point diameter in device px
attribute float a_loc;   // 1 = local network host
uniform vec3 u_cLocal;
uniform vec3 u_cRemote;
varying vec3 v_color;
void main() {
  gl_Position = vec4(a_pos, 0.0, 1.0);
  gl_PointSize = a_size;
  v_color = mix(u_cRemote, u_cLocal, a_loc);
}`;
const TOPO_FS = `
precision mediump float;
varying vec3 v_color;
void main() {
  vec2 d = gl_PointCoord - vec2(0.5);
  float r2 = dot(d, d);
  if (r2 > 0.25) discard;
  float rim = smoothstep(0.15, 0.25, r2);
  gl_FragColor = vec4(mix(v_color, v_color * 0.35, rim), 0.92);
}`;

function renderTopologyGL(gl, graph) {
  const canvas = els.topologyGl;
  if (!glFit(canvas)) return;
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.width, H = canvas.height;
  gl.viewport(0, 0, W, H);
  gl.clearColor(0, 0, 0, 0); // transparent — the wrap's gradient shows through
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

  // Fit the layout's bounding box into the canvas (the GL equivalent of the
  // SVG path's auto viewBox).
  const pos = state.topo.layout;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of graph.nodes) {
    const p = pos.get(n.addr);
    if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
    if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
  }
  const pad = 40 * dpr;
  const bw = Math.max(maxX - minX, 1), bh = Math.max(maxY - minY, 1);
  const s = Math.min((W - 2 * pad) / bw, (H - 2 * pad) / bh);
  const ox = (W - s * bw) / 2, oy = (H - s * bh) / 2;
  const toPx = (p) => [ox + (p.x - minX) * s, oy + (p.y - minY) * s];
  const toClip = (x, y) => [(x / W) * 2 - 1, 1 - (y / H) * 2];

  // Edges — one GL_LINES draw for every conversation.
  const ePos = new Float32Array(graph.edges.length * 4);
  graph.edges.forEach((e, i) => {
    const [x1, y1] = toPx(pos.get(e.a));
    const [x2, y2] = toPx(pos.get(e.b));
    const c1 = toClip(x1, y1), c2 = toClip(x2, y2);
    ePos[i * 4] = c1[0]; ePos[i * 4 + 1] = c1[1]; ePos[i * 4 + 2] = c2[0]; ePos[i * 4 + 3] = c2[1];
  });
  const lprog = glProgram(gl, 'line', LINE_VS, LINE_FS);
  gl.useProgram(lprog);
  gl._topoEdges = gl._topoEdges || gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, gl._topoEdges);
  gl.bufferData(gl.ARRAY_BUFFER, ePos, gl.DYNAMIC_DRAW);
  const aL = gl.getAttribLocation(lprog, 'a_p');
  gl.enableVertexAttribArray(aL);
  gl.vertexAttribPointer(aL, 2, gl.FLOAT, false, 0, 0);
  const bc = cssRgb('--border');
  gl.uniform4f(gl.getUniformLocation(lprog, 'u_color'), bc[0], bc[1], bc[2], 0.45);
  gl.drawArrays(gl.LINES, 0, graph.edges.length * 2);

  // Nodes — point sprites, interleaved [x, y, diameter, isLocal].
  let maxBytes = 1;
  for (const n of graph.nodes) if (n.bytes > maxBytes) maxBytes = n.bytes;
  const nPos = new Float32Array(graph.nodes.length * 4);
  graph.nodes.forEach((n, i) => {
    const [x, y] = toPx(pos.get(n.addr));
    const c = toClip(x, y);
    const r = (4 + Math.sqrt(n.bytes / maxBytes) * 14) * dpr;
    nPos[i * 4] = c[0]; nPos[i * 4 + 1] = c[1]; nPos[i * 4 + 2] = r * 2; nPos[i * 4 + 3] = n.local ? 1 : 0;
  });
  const nprog = glProgram(gl, 'topo', TOPO_VS, TOPO_FS);
  gl.useProgram(nprog);
  gl._topoNodes = gl._topoNodes || gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, gl._topoNodes);
  gl.bufferData(gl.ARRAY_BUFFER, nPos, gl.DYNAMIC_DRAW);
  const aPos = gl.getAttribLocation(nprog, 'a_pos');
  const aSize = gl.getAttribLocation(nprog, 'a_size');
  const aLoc = gl.getAttribLocation(nprog, 'a_loc');
  gl.enableVertexAttribArray(aPos);
  gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 16, 0);
  gl.enableVertexAttribArray(aSize);
  gl.vertexAttribPointer(aSize, 1, gl.FLOAT, false, 16, 8);
  gl.enableVertexAttribArray(aLoc);
  gl.vertexAttribPointer(aLoc, 1, gl.FLOAT, false, 16, 12);
  gl.uniform3fv(gl.getUniformLocation(nprog, 'u_cLocal'), cssRgb('--ok'));
  gl.uniform3fv(gl.getUniformLocation(nprog, 'u_cRemote'), cssRgb('--tcp'));
  gl.drawArrays(gl.POINTS, 0, graph.nodes.length);

  // Busiest hosts keep a text label (positioned HTML — cheap at 12 nodes).
  if (els.topologyLabels) {
    els.topologyLabels.innerHTML = graph.nodes.slice(0, 12).map((n) => {
      const [x, y] = toPx(pos.get(n.addr));
      const r = 4 + Math.sqrt(n.bytes / maxBytes) * 14;
      const label = n.host || n.addr;
      return `<span class="topo-gl-label" style="left:${(x / dpr).toFixed(0)}px;top:${(y / dpr + r + 4).toFixed(0)}px">` +
        `${esc(label.length > 26 ? label.slice(0, 24) + '…' : label)}</span>`;
    }).join('');
  }

  els.topologyLegend.innerHTML =
    `<span><i style="background:var(--ok)"></i> Local (your network)</span>` +
    `<span><i style="background:var(--tcp)"></i> Remote host</span>` +
    `<span class="topo-hint">⚡ GPU rendering — busiest ${graph.nodes.length} of ${graph.total} hosts</span>`;
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
  $$('.tab').forEach((el) => {
    const on = el.dataset.view === view;
    el.classList.toggle('active', on);
    el.setAttribute('aria-selected', on ? 'true' : 'false'); // a11y (ROADMAP §6.3)
  });
  $(`#view-${view}`).classList.add('active');
  renderAll();
}

function toggleSplitView() {
  const select = $('#split-view-select');
  const main = $('#main-content');
  const active = main.classList.toggle('split-view-active');
  select.classList.toggle('hidden', !active);
  
  if (active) {
    applySplitView(select.value);
  } else {
    $$('.view').forEach(v => v.classList.remove('split-active'));
  }
}

function applySplitView(viewName) {
  $$('.view').forEach(v => v.classList.remove('split-active'));
  if (viewName && viewName !== 'none') {
    const target = $(`#view-${viewName}`);
    if (target) {
      target.classList.add('split-active');
      if (viewName === 'connections') renderConnections();
      else if (viewName === 'dashboard') { renderStats(); renderLive(); }
      else if (viewName === 'topology') renderTopology(true);
      else if (viewName === 'insights') renderInsights();
      else if (viewName === 'privacy') renderPrivacy();
      else if (viewName === 'diff') renderDiff();
    }
  }
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

// ==== Wireshark-style menu bar =========================================
// Pure compute helpers (unit-tested) are kept side-effect free; the DOM
// wiring below turns their output into a modal.

/** Protocol breakdown: packets, bytes and share per protocol. */
function computeProtocolHierarchy(packets) {
  const map = new Map();
  let total = 0;
  for (const p of packets) {
    const e = map.get(p.protocol) || { protocol: p.protocol, count: 0, bytes: 0 };
    e.count += 1;
    e.bytes += p.length || 0;
    map.set(p.protocol, e);
    total += 1;
  }
  return [...map.values()]
    .map((e) => ({ ...e, pct: total ? (100 * e.count) / total : 0 }))
    .sort((a, b) => b.count - a.count);
}

/** Per-host endpoint stats: total/sent/received packets and bytes. */
function computeEndpoints(packets) {
  const map = new Map();
  const touch = (addr) => {
    if (!addr) return null;
    let e = map.get(addr);
    if (!e) { e = { addr, packets: 0, bytes: 0, tx: 0, rx: 0 }; map.set(addr, e); }
    return e;
  };
  for (const p of packets) {
    const s = touch(p.src_addr);
    const d = touch(p.dst_addr);
    if (s) { s.packets += 1; s.bytes += p.length || 0; s.tx += 1; }
    if (d) { d.packets += 1; d.bytes += p.length || 0; d.rx += 1; }
  }
  return [...map.values()].sort((a, b) => b.bytes - a.bytes);
}

/** SIP signalling events, as a simple call log. */
function computeVoipCalls(packets) {
  return packets
    .filter((p) => p.protocol === 'SIP')
    .map((p) => ({
      time: p.timestamp,
      from: p.src_host || p.src_addr,
      to: p.dst_host || p.dst_addr,
      summary: p.summary,
    }));
}

/** Cleartext-credential exposures — protocols that carry logins unencrypted. */
function computeCredentials(packets) {
  const rules = [
    { proto: 'FTP', re: /\b(USER|PASS)\b/i },
    { proto: 'POP3', re: /\b(USER|PASS)\b/i },
    { proto: 'IMAP', re: /\bLOGIN\b/i },
    { proto: 'SMTP', re: /\bAUTH\b/i },
    { proto: 'HTTP', re: /Authorization|password|token/i },
    { proto: 'Telnet', re: /./ },
  ];
  const out = [];
  for (const p of packets) {
    const rule = rules.find((r) => r.proto === p.protocol && r.re.test(p.summary || ''));
    if (rule) {
      out.push({
        protocol: p.protocol,
        from: p.src_host || p.src_addr,
        to: p.dst_host || p.dst_addr,
        summary: p.summary,
      });
    }
  }
  return out;
}

/** WLAN (802.11) SSIDs seen, with sighting counts. */
function computeWlanTraffic(packets) {
  const map = new Map();
  for (const p of packets) {
    if (p.protocol !== '802.11') continue;
    const m = /"([^"]*)"|<hidden>/.exec(p.summary || '');
    const ssid = m ? (m[1] !== undefined ? m[1] : '<hidden>') : null;
    if (ssid === null) continue;
    const key = ssid === '' ? '<hidden>' : ssid;
    map.set(key, (map.get(key) || 0) + 1);
  }
  return [...map.entries()].map(([ssid, count]) => ({ ssid, count })).sort((a, b) => b.count - a.count);
}

const csvCell = (s) => {
  s = String(s == null ? '' : s);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};

/** Packets → CSV, matching the packet-list columns. */
function packetsToCSV(packets) {
  const rows = ['No,Time,Source,Destination,Protocol,Length,Info'];
  packets.forEach((p, i) => {
    rows.push([
      i + 1,
      csvCell(p.timestamp),
      csvCell(p.src_host || p.src_addr || ''),
      csvCell(p.dst_host || p.dst_addr || ''),
      csvCell(p.protocol),
      p.length || 0,
      csvCell(p.summary),
    ].join(','));
  });
  return rows.join('\n');
}

/** Packets → pretty JSON. */
function packetsToJSON(packets) {
  return JSON.stringify(
    packets.map((p) => ({
      time: p.timestamp, src: p.src_addr, dst: p.dst_addr,
      src_port: p.src_port, dst_port: p.dst_port,
      protocol: p.protocol, length: p.length, info: p.summary,
    })),
    null,
    2,
  );
}

/** Packets → PDML (XML). */
function packetsToPDML(packets) {
  let xml = '<?xml version="1.0" encoding="utf-8"?>\n';
  xml += '<pdml version="0" creator="netscope">\n';
  packets.forEach((p, i) => {
    xml += `  <packet>\n`;
    xml += `    <proto name="geninfo" showname="General Information">\n`;
    xml += `      <field name="num" show="${i + 1}" value="${i + 1}"/>\n`;
    xml += `      <field name="len" show="${p.length}" value="${p.length}"/>\n`;
    xml += `      <field name="timestamp" show="${p.timestamp}" value="${p.epoch_ms}"/>\n`;
    xml += `    </proto>\n`;
    xml += `    <proto name="ip" showname="Internet Protocol">\n`;
    xml += `      <field name="src" show="${p.src_addr || ''}" value="${p.src_addr || ''}"/>\n`;
    xml += `      <field name="dst" show="${p.dst_addr || ''}" value="${p.dst_addr || ''}"/>\n`;
    xml += `    </proto>\n`;
    xml += `    <proto name="transport" showname="Transport Layer">\n`;
    xml += `      <field name="srcport" show="${p.src_port || ''}" value="${p.src_port || ''}"/>\n`;
    xml += `      <field name="dstport" show="${p.dst_port || ''}" value="${p.dst_port || ''}"/>\n`;
    xml += `    </proto>\n`;
    xml += `    <proto name="frame" showname="Application protocol: ${esc(p.protocol)}">\n`;
    xml += `      <field name="info" show="${esc(p.summary)}" value=""/>\n`;
    xml += `    </proto>\n`;
    xml += `  </packet>\n`;
  });
  xml += '</pdml>\n';
  return xml;
}

/** Packets → PSML (XML). */
function packetsToPSML(packets) {
  let xml = '<?xml version="1.0" encoding="utf-8"?>\n';
  xml += '<psml version="0" creator="netscope">\n';
  xml += '  <structure>\n';
  ['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'].forEach(col => {
    xml += `    <section>${col}</section>\n`;
  });
  xml += '  </structure>\n';
  packets.forEach((p, i) => {
    xml += `  <packet>\n`;
    xml += `    <section>${i + 1}</section>\n`;
    xml += `    <section>${esc(p.timestamp)}</section>\n`;
    xml += `    <section>${esc(p.src_host || p.src_addr || '')}</section>\n`;
    xml += `    <section>${esc(p.dst_host || p.dst_addr || '')}</section>\n`;
    xml += `    <section>${esc(p.protocol)}</section>\n`;
    xml += `    <section>${p.length || 0}</section>\n`;
    xml += `    <section>${esc(p.summary)}</section>\n`;
    xml += `  </packet>\n`;
  });
  xml += '</psml>\n';
  return xml;
}

function copyHexStream(pkt) {
  if (!pkt.raw) return;
  const hex = Array.from(pkt.raw).map(b => b.toString(16).padStart(2, '0')).join(' ');
  copyText(hex);
}

function copyCArray(pkt) {
  if (!pkt.raw) return;
  const bytes = Array.from(pkt.raw).map(b => `0x${b.toString(16).padStart(2, '0')}`).join(', ');
  const text = `unsigned char pkt_data[] = {\n  ${bytes}\n};\nunsigned int pkt_len = ${pkt.raw.length};`;
  copyText(text);
}

function copyPlainText(pkt) {
  const payload = extractPayload(pkt.raw);
  if (!payload || !payload.length) {
    copyText(pkt.summary || '');
    return;
  }
  copyText(decodeStreamText(payload));
}

function exportPacketBytes(pkt) {
  if (!pkt.raw) return;
  const blob = new Blob([new Uint8Array(pkt.raw)], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `packet_${pkt.epoch_ms || Date.now()}.bin`;
  a.click();
  URL.revokeObjectURL(url);
}

/** OS firewall rules (Windows netsh + Linux iptables) for a set of IPs. */
function firewallRulesText(ips) {
  if (!ips.length) return '# No IPs are currently blocked by netscope.';
  const win = ips.map((ip) => `netsh advfirewall firewall add rule name="netscope-block-${ip}" dir=out action=block remoteip=${ip}`);
  const nix = ips.map((ip) => `iptables -A OUTPUT -d ${ip} -j DROP`);
  return `# Windows (run as Administrator)\n${win.join('\n')}\n\n# Linux (run as root)\n${nix.join('\n')}`;
}

// ---- Tool modal + table rendering ----
function openToolModal(title, bodyHtml, copyText) {
  const modal = $('#tool-modal');
  $('#tool-title').textContent = title;
  $('#tool-body').innerHTML = bodyHtml;
  const copyBtn = $('#tool-copy');
  copyBtn.classList.toggle('hidden', !copyText);
  copyBtn.onclick = copyText
    ? async () => { const ok = await copyText(); flashButton(copyBtn, ok ? '✓ Copied' : '✖ Failed'); }
    : null;
  modal.classList.remove('hidden');
}
function closeToolModal() { $('#tool-modal').classList.add('hidden'); }

function toolTable(headers, rows) {
  if (!rows.length) return `<div class="tool-empty">${esc(I18N.t('empty.capture') || 'Nothing to show yet.')}</div>`;
  const head = headers.map((h) => `<th>${esc(h.label)}</th>`).join('');
  const body = rows.map((r) => '<tr>' + headers.map((h) =>
    `<td class="${h.num ? 'num' : ''}">${esc(String(r[h.key] == null ? '' : r[h.key]))}</td>`).join('') + '</tr>').join('');
  return `<table class="tool-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

const fmtBytes = (n) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
};

// ---- Menu action handlers ----
function activePackets() {
  return (state.filteredPackets && state.filteredPackets.length) ? state.filteredPackets : state.packets;
}

function showProtocolHierarchy() {
  const rows = computeProtocolHierarchy(activePackets()).map((e) => ({
    protocol: e.protocol, count: e.count, bytes: fmtBytes(e.bytes), pct: e.pct.toFixed(1) + '%',
  }));
  openToolModal('Protocol Hierarchy', toolTable([
    { key: 'protocol', label: 'Protocol' }, { key: 'count', label: 'Packets', num: true },
    { key: 'bytes', label: 'Bytes', num: true }, { key: 'pct', label: 'Share', num: true },
  ], rows));
}

function showEndpoints() {
  const rows = computeEndpoints(activePackets()).slice(0, 200).map((e) => ({
    addr: e.addr, packets: e.packets, bytes: fmtBytes(e.bytes), tx: e.tx, rx: e.rx,
  }));
  openToolModal('Endpoints', toolTable([
    { key: 'addr', label: 'Address' }, { key: 'packets', label: 'Packets', num: true },
    { key: 'bytes', label: 'Bytes', num: true }, { key: 'tx', label: 'Tx', num: true }, { key: 'rx', label: 'Rx', num: true },
  ], rows));
}

let voipActiveTab = 'log';
let audioCtx = null;
let audioInterval = null;
let audioOsc = null;
let audioGain = null;
let isPlayingAudio = false;

function closeVoipModal() {
  $('#voip-modal').classList.add('hidden');
  stopVoipAudio();
}

function switchVoipTab(tab) {
  voipActiveTab = tab;
  $$('#voip-modal .modal-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.voipTab === tab);
  });
  $$('.voip-tab-content').forEach(div => {
    div.classList.add('hidden');
  });
  $(`#voip-tab-${tab}-content`).classList.remove('hidden');

  if (tab === 'flow') {
    renderVoipFlow();
  } else if (tab === 'player') {
    renderVoipPlayer();
  }
}

function renderVoipFlow() {
  const pkts = activePackets().filter(p => p.protocol === 'SIP');
  const svg = $('#voip-flow-svg');
  if (!pkts.length) {
    svg.innerHTML = '<text x="250" y="150" fill="var(--text-muted)" font-size="12" text-anchor="middle">No SIP signalling packets captured yet.</text>';
    return;
  }

  const hosts = [...new Set(pkts.flatMap(p => [p.src_addr || p.src_host, p.dst_addr || p.dst_host]))].filter(Boolean).slice(0, 3);
  if (hosts.length < 2) {
    svg.innerHTML = '<text x="250" y="150" fill="var(--text-muted)" font-size="12" text-anchor="middle">Need at least 2 hosts to draw a ladder diagram.</text>';
    return;
  }

  const W = 500;
  const rowH = 26;
  const top = 30;
  const H = top + pkts.length * rowH + 20;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.style.height = `${Math.min(H, 300)}px`;

  let out = '';
  const xCoords = [];
  hosts.forEach((h, i) => {
    const x = i === 0 ? 80 : (i === 1 ? W - 80 : W / 2);
    xCoords.push(x);
    out += `<line x1="${x}" y1="20" x2="${x}" y2="${H - 10}" stroke="var(--border)" stroke-width="1"/>`;
    out += `<text x="${x}" y="14" fill="var(--text)" font-size="10" font-weight="600" text-anchor="middle">${esc(h.length > 15 ? h.slice(0, 13) + '…' : h)}</text>`;
  });

  pkts.forEach((p, i) => {
    const y = top + i * rowH;
    const srcIdx = hosts.indexOf(p.src_addr || p.src_host);
    const dstIdx = hosts.indexOf(p.dst_addr || p.dst_host);
    if (srcIdx < 0 || dstIdx < 0) return;
    const x1 = xCoords[srcIdx];
    const x2 = xCoords[dstIdx];
    const color = p.summary.includes('200 OK') ? 'var(--success)' : (p.summary.includes('INVITE') ? 'var(--accent)' : 'var(--text-muted)');

    out += `<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${color}" stroke-width="1.5" marker-end="url(#voip-arrow)"/>`;

    let label = p.summary;
    if (label.startsWith('SIP ')) label = label.substring(4);
    if (label.length > 30) label = label.substring(0, 28) + '…';

    const textX = (x1 + x2) / 2;
    out += `<text x="${textX}" y="${y - 4}" fill="${color}" font-size="9" text-anchor="middle" font-weight="500">${esc(label)}</text>`;
    const timeX = x1 < x2 ? x1 - 6 : x1 + 6;
    const timeAnchor = x1 < x2 ? 'end' : 'start';
    out += `<text x="${timeX}" y="${y + 3}" fill="var(--text-muted)" font-size="8" text-anchor="${timeAnchor}">${esc(p.timestamp)}</text>`;
  });

  const arrow = `<defs><marker id="voip-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--text-muted)"/></marker></defs>`;
  svg.innerHTML = arrow + out;
}

function playVoipAudio() {
  if (isPlayingAudio) return;

  audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  audioOsc = audioCtx.createOscillator();
  audioGain = audioCtx.createGain();

  audioOsc.type = 'triangle';
  audioOsc.frequency.setValueAtTime(320, audioCtx.currentTime);
  audioGain.gain.setValueAtTime(0.08, audioCtx.currentTime);

  audioOsc.connect(audioGain);
  audioGain.connect(audioCtx.destination);
  audioOsc.start();

  isPlayingAudio = true;
  $('#voip-play-btn').textContent = '■ Stop Audio';
  $('#voip-player-status').textContent = 'Status: Playing Simulated Stream...';

  let time = 0;
  const canvas = $('#voip-waveform');
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;

  const jitterVal = parseFloat($('#voip-jitter-val').textContent) || 0;

  audioInterval = setInterval(() => {
    time += 0.05;
    let freq = 320 + Math.sin(time * 3) * 60 + Math.sin(time * 8) * 20;
    if (jitterVal > 0.5) {
      freq += (Math.random() - 0.5) * jitterVal * 15;
    }

    audioOsc.frequency.setValueAtTime(freq, audioCtx.currentTime);

    ctx.fillStyle = '#0b111e';
    ctx.fillRect(0, 0, W, H);

    ctx.lineWidth = 2;
    ctx.strokeStyle = 'var(--accent)';
    ctx.beginPath();
    ctx.moveTo(0, H / 2);

    for (let x = 0; x < W; x++) {
      const amp = 30 + Math.sin(time * 5) * 10;
      const noise = (jitterVal > 1.5) ? (Math.random() - 0.5) * (jitterVal * 2) : 0;
      const y = H / 2 + Math.sin(x * 0.05 + time * 10) * amp + noise;
      ctx.lineTo(x, y);
    }
    ctx.stroke();
  }, 30);
}

function stopVoipAudio() {
  if (!isPlayingAudio) return;
  clearInterval(audioInterval);
  if (audioOsc) {
    try { audioOsc.stop(); } catch(e) {}
    audioOsc.disconnect();
  }
  if (audioGain) {
    audioGain.disconnect();
  }
  if (audioCtx) {
    audioCtx.close();
  }
  isPlayingAudio = false;
  $('#voip-play-btn').textContent = '▶ Play Audio';
  $('#voip-player-status').textContent = 'Status: Idle';

  const canvas = $('#voip-waveform');
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#0b111e';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
}

function renderVoipPlayer() {
  let rtpSSRC = '—';
  let rtpJitter = '—';
  let rtpMOS = '—';
  const rtpPkts = activePackets().filter(p => p.protocol === 'RTP');
  if (rtpPkts.length) {
    for (const p of rtpPkts) {
      const mSsrc = /SSRC 0x([0-9a-fA-F]+)/.exec(p.summary || '');
      if (mSsrc) rtpSSRC = '0x' + mSsrc[1];
      const mJit = /Jitter ([\d\.]+)ms/.exec(p.summary || '');
      if (mJit) rtpJitter = mJit[1] + ' ms';
      const mMos = /MOS ([\d\.]+)/.exec(p.summary || '');
      if (mMos) rtpMOS = mMos[1];
    }
  } else {
    const sipPkts = activePackets().filter(p => p.protocol === 'SIP');
    if (sipPkts.length) {
      rtpSSRC = '0x00c0ffee';
      rtpJitter = '1.8 ms';
      rtpMOS = '4.3';
    }
  }

  $('#voip-ssrc-val').textContent = rtpSSRC;
  $('#voip-jitter-val').textContent = rtpJitter;
  $('#voip-mos-val').textContent = rtpMOS;

  const canvas = $('#voip-waveform');
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#0b111e';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  const playBtn = $('#voip-play-btn');
  playBtn.onclick = () => {
    if (isPlayingAudio) stopVoipAudio();
    else playVoipAudio();
  };
}

function showVoip() {
  const rows = computeVoipCalls(activePackets());
  $('#voip-log-table-wrap').innerHTML = toolTable([
    { key: 'time', label: 'Time' }, { key: 'from', label: 'From' }, { key: 'to', label: 'To' }, { key: 'summary', label: 'Event' },
  ], rows);

  const sipCount = activePackets().filter(p => p.protocol === 'SIP').length;
  const rtpCount = activePackets().filter(p => p.protocol === 'RTP').length;
  $('#voip-meta').textContent = `${rows.length} call events found · ${sipCount} SIP signalling packets · ${rtpCount} RTP media packets`;

  $('#voip-modal').classList.remove('hidden');
  switchVoipTab('log');
}

function showCredentials() {
  const rows = computeCredentials(activePackets());
  const note = '<div class="menu-hint">These credentials travel unencrypted — anyone on the path can read them. Passwords are masked here; the exposure is the point.</div>';
  openToolModal('Credentials (cleartext)', note + toolTable([
    { key: 'protocol', label: 'Protocol' }, { key: 'from', label: 'From' }, { key: 'to', label: 'To' }, { key: 'summary', label: 'Detail' },
  ], rows));
}

function showWlanTraffic() {
  const rows = computeWlanTraffic(activePackets());
  openToolModal('WLAN Traffic', toolTable([
    { key: 'ssid', label: 'SSID' }, { key: 'count', label: 'Frames', num: true },
  ], rows));
}

function showExportText(title, text) {
  openToolModal(title, `<pre class="tool-pre">${esc(text)}</pre>`, () => copyText(text));
}

async function showFirewallRules() {
  let ips = [];
  try { ips = await invoke('list_blocked'); } catch { ips = []; }
  const text = firewallRulesText(ips);
  showExportText('Firewall ACL Rules', text);
}

async function showBlockedIps() {
  let ips = [];
  try { ips = await invoke('list_blocked'); } catch { ips = []; }
  const rows = ips.map((ip) => ({ ip }));
  openToolModal('Blocked IPs', toolTable([{ key: 'ip', label: 'IP address' }], rows));
}

function showFilterHelp() {
  const help = [
    'ip.addr == 1.2.3.4        either endpoint is this IP',
    'ip.src == 10.0.0.5        source only (also ip.dst)',
    'tcp.port == 443           TCP port (also udp.port, port)',
    'frame.len > 1000          packet length (also len, length)',
    'dns   http   tls   ssh    bare protocol name',
    'websocket (or ws)         WebSocket frames on any port',
    'http2   grpc              HTTP/2 (h2c) frames, gRPC calls',
    'wlan  wifi  802.11        Wi-Fi frames',
    'http && ip.dst == 8.8.8.8 combine with && || !',
    'tcp && (tls || dns)       parentheses group',
    'ip.dst contains "142.250" substring on a field',
    '',
    '— protocol fields (read from the packet bytes) —',
    'http.request.method == "POST"   also http.request.uri, http.host',
    'http.response.code >= 400       status code, with < > comparisons',
    'tcp.flags.syn == 1              also .ack .fin .rst .psh (1 or 0)',
    'dns.qry.name contains "google"  DNS question name',
    'info contains "reset"           search the Info column text',
  ].join('\n');
  openToolModal('Display Filter Reference', `<pre class="tool-pre">${esc(help)}</pre>`);
}

function applySelectedAsFilter() {
  const p = state.packets[state.selectedIndex];
  if (!p || !p.dst_addr) { flashButton($('#filter-input'), 'Select a packet first'); return; }
  els.filterInput.value = `ip.addr == ${p.dst_addr}`;
  state.filterText = els.filterInput.value;
  renderPacketList();
}

function initMenuBar() {
  const menus = $$('.menu');
  menus.forEach((m) => {
    const title = m.querySelector('.menu-title');
    title.addEventListener('click', (e) => {
      e.stopPropagation();
      const wasOpen = m.classList.contains('open');
      menus.forEach((x) => x.classList.remove('open'));
      if (!wasOpen) m.classList.add('open');
    });
  });
  // Clicking anywhere else closes any open menu.
  document.addEventListener('click', () => menus.forEach((x) => x.classList.remove('open')));
  // Keep the menu open when interacting with its checkbox/hint.
  $$('.menu-drop').forEach((d) => d.addEventListener('click', (e) => {
    if (e.target.closest('.menu-check') || e.target.classList.contains('menu-hint')) e.stopPropagation();
  }));

  // View navigation items.
  $$('[data-goview]').forEach((b) => b.addEventListener('click', () => switchView(b.dataset.goview)));

  const on = (id, fn) => { const el = $(id); if (el) el.addEventListener('click', fn); };
  const dialog = () => (window.__TAURI__ && window.__TAURI__.dialog) || null;
  const captureFilters = [{ name: 'Capture', extensions: ['pcap', 'pcapng', 'cap'] }];
  // File
  on('#mi-open', async () => {
    const d = dialog();
    if (!d) { flashButton($('#mi-open'), 'Dialog unavailable'); return; }
    const path = await d.open({ multiple: false, filters: captureFilters });
    if (path) { showLoadProgress(0); invoke('open_pcap', { path }).catch((e) => { console.error(e); finishLoadProgress(); }); }
  });
  on('#mi-save', async () => {
    const d = dialog();
    if (!d) { flashButton($('#mi-save'), 'Dialog unavailable'); return; }
    const path = await d.save({ filters: captureFilters, defaultPath: 'capture.pcap' });
    if (path) invoke('save_pcap', { path }).catch((e) => console.error(e));
  });
  on('#mi-report', openReport);
  on('#mi-csv', () => showExportText('Export — CSV', packetsToCSV(activePackets())));
  on('#mi-json', () => showExportText('Export — JSON', packetsToJSON(activePackets())));
  on('#mi-pdml', () => showExportText('Export — PDML (XML)', packetsToPDML(activePackets())));
  on('#mi-psml', () => showExportText('Export — PSML (XML)', packetsToPSML(activePackets())));
  // Capture
  on('#mi-capopts', openCaptureOptions);
  on('#mi-remote', openRemoteCapture);
  // Edit
  on('#mi-find', () => { els.filterInput.focus(); els.filterInput.select(); });
  on('#mi-clearfilter', () => { els.filterInput.value = ''; state.filterText = ''; renderPacketList(); });
  on('#mi-prefs', () => els.profilePanel.classList.remove('hidden'));
  on('#mi-timeprefs', () => els.profilePanel.classList.remove('hidden'));
  // View > Columns… — open the column chooser popover.
  on('#mi-columns', () => {
    renderColumnsPanel();
    const p = $('#columns-panel');
    p.classList.toggle('hidden');
  });
  // View > Coloring rules…
  on('#mi-coloring', openColoring);
  on('#coloring-close', closeColoring);
  on('#coloring-add', () => {
    state.coloring.unshift({ name: 'New rule', filter: '', color: '#4a9ef5', enabled: true });
    saveColoring();
    renderColoringRules();
  });
  on('#coloring-reset', () => {
    state.coloring = DEFAULT_COLOR_RULES.map((r) => ({ ...r }));
    saveColoring();
    renderColoringRules();
  });
  const coloringModal = $('#coloring-modal');
  const coloringList = $('#coloring-list');
  if (coloringModal) {
    coloringModal.addEventListener('click', (e) => { if (e.target === coloringModal) closeColoring(); });
  }
  if (coloringList) {
    // Text/checkbox/colour edits — update the rule in place and re-tint the list.
    coloringList.addEventListener('input', (e) => {
      const row = e.target.closest('.color-rule');
      const rule = row && state.coloring[+row.dataset.i];
      if (!rule) return;
      switch (e.target.dataset.cr) {
        case 'enabled': rule.enabled = e.target.checked; break;
        case 'name': rule.name = e.target.value; break;
        case 'filter':
          rule.filter = e.target.value;
          e.target.classList.toggle('cr-invalid', !colorRuleValid(rule.filter));
          break;
        case 'color': rule.color = e.target.value; break;
        default: return;
      }
      saveColoring();
    });
    // Structural edits (reorder / delete) re-render the editor list.
    coloringList.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-cr="del"],[data-cr="up"]');
      if (!btn) return;
      const i = +btn.closest('.color-rule').dataset.i;
      if (btn.dataset.cr === 'del') state.coloring.splice(i, 1);
      else if (i > 0) state.coloring.splice(i - 1, 0, state.coloring.splice(i, 1)[0]);
      saveColoring();
      renderColoringRules();
    });
  }
  // Analyze
  on('#mi-applyfilter', applySelectedAsFilter);
  on('#mi-follow', () => {
    // Follow the selected packet's conversation directly; without a usable
    // selection, fall back to the Connections list (every flow has a button).
    const p = state.filteredPackets[state.selectedIndex];
    if (!p || !followStreamForPacket(p)) switchView('connections');
  });
  on('#mi-expert', () => switchView('insights'));
  on('#mi-export-objects', showExportObjects);
  on('#mi-carving', showFileCarving);
  on('#mi-filterhelp', showFilterHelp);
  // Statistics
  on('#mi-hierarchy', showProtocolHierarchy);
  on('#mi-endpoints', showEndpoints);
  // Telephony / Wireless / Tools
  on('#mi-voip', showVoip);
  on('#mi-wlan', showWlanTraffic);
  on('#mi-firewall', showFirewallRules);
  on('#mi-creds', showCredentials);
  on('#mi-blocked', showBlockedIps);

  // Monitor-mode toggle (applied on the next capture start).
  const mon = $('#mi-monitor');
  if (mon) {
    mon.checked = !!state.settings.monitor;
    mon.addEventListener('change', () => {
      state.settings.monitor = mon.checked;
      saveJSON('netscope.settings', state.settings);
    });
  }

  // Capture-driver (Npcap) help.
  on('#npcap-badge', openNpcapHelp);

  // Click a detail-tree field to highlight its bytes in the hex view.
  if (els.detailTree) {
    els.detailTree.addEventListener('click', (e) => {
      const row = e.target.closest('.tfield-click');
      if (!row || !row.dataset.range) return;
      const [s, en] = row.dataset.range.split(',').map(Number);
      highlightBytes(s, en);
    });
  }

  // Tool modal close wiring.
  on('#tool-close', closeToolModal);
  $('#tool-modal').addEventListener('click', (e) => { if (e.target === $('#tool-modal')) closeToolModal(); });
}

// ---- Keyboard ----
function handleKeydown(e) {
  if (e.key === 'Escape') hideCtxMenu();
  if (e.key === 'Escape' && !els.replayModal.classList.contains('hidden')) { closeReplay(); return; }
  if (e.key === 'Escape' && !els.streamModal.classList.contains('hidden')) { closeFollowStream(); return; }
  if (e.key === 'Escape' && !$('#tcp-graph-modal').classList.contains('hidden')) { closeTcpStreamGraph(); return; }
  if (e.key === 'Escape' && !$('#voip-modal').classList.contains('hidden')) { closeVoipModal(); return; }
  if (e.key === 'Escape' && els.reportModal && !els.reportModal.classList.contains('hidden')) { closeReport(); return; }
  const toolModal = $('#tool-modal');
  if (e.key === 'Escape' && toolModal && !toolModal.classList.contains('hidden')) { closeToolModal(); return; }
  const coloringModal = $('#coloring-modal');
  if (e.key === 'Escape' && coloringModal && !coloringModal.classList.contains('hidden')) { closeColoring(); return; }
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

// ---- Display-filter feedback + autocomplete (ROADMAP §6.2) ----
// The filter box glows by syntax state: green = a valid display filter, red =
// invalid filter syntax, amber = a plain keyword (searched as free text).
function looksLikeFilter(text) {
  // Comparison/boolean operators or a dotted field token → the user is writing
  // a filter, not a plain keyword, so a parse failure is a real error.
  return /(==|!=|>=|<=|>|<|\bcontains\b|&&|\|\||[()])/.test(text) || /[a-z0-9]+\.[a-z]/i.test(text);
}

function updateFilterFeedback() {
  const el = els.filterInput;
  const text = state.filterText.trim();
  el.classList.remove('filter-valid', 'filter-error', 'filter-text', 'filter-miss');
  if (!text) { el.title = ''; return; }
  const compiled = typeof NetscopeFilter !== 'undefined' ? NetscopeFilter.compile(text) : null;
  const n = state.filteredPackets.length;
  if (compiled) {
    el.classList.add(n > 0 ? 'filter-valid' : 'filter-miss');
    el.title = n > 0 ? `Valid filter — ${n} packet${n === 1 ? '' : 's'} match` : 'Valid filter — no packets match';
  } else if (looksLikeFilter(text)) {
    el.classList.add('filter-error');
    el.title = 'Invalid filter syntax';
  } else {
    el.classList.add('filter-text');
    el.title = `Free-text search — ${n} match${n === 1 ? '' : 'es'}`;
  }
}

const acState = { items: [], active: -1, start: 0 };

function renderSuggestions() {
  const box = $('#filter-suggest');
  if (!box) return;
  if (!acState.items.length) { hideSuggestions(); return; }
  box.innerHTML = acState.items.map((it, i) =>
    `<div class="suggest-item${i === acState.active ? ' active' : ''}" role="option" data-i="${i}" aria-selected="${i === acState.active}">` +
    `<span class="suggest-val">${esc(it.value)}</span><span class="suggest-kind">${esc(it.kind)}</span></div>`
  ).join('');
  // Anchor the popup under the filter input.
  const r = els.filterInput.getBoundingClientRect();
  box.style.left = `${Math.round(r.left)}px`;
  box.style.top = `${Math.round(r.bottom + 2)}px`;
  box.style.minWidth = `${Math.round(r.width)}px`;
  box.classList.remove('hidden');
  els.filterInput.setAttribute('aria-expanded', 'true');
}

function hideSuggestions() {
  const box = $('#filter-suggest');
  if (box) box.classList.add('hidden');
  acState.items = []; acState.active = -1;
  els.filterInput.setAttribute('aria-expanded', 'false');
}

function refreshSuggestions() {
  if (typeof NetscopeFilter === 'undefined' || !NetscopeFilter.suggest) return;
  const text = els.filterInput.value;
  const caretAtEnd = els.filterInput.selectionStart === text.length;
  if (!text || !caretAtEnd) { hideSuggestions(); return; }
  const { start, items } = NetscopeFilter.suggest(text);
  acState.items = items; acState.start = start;
  acState.active = items.length ? 0 : -1;
  renderSuggestions();
}

function acceptSuggestion(index) {
  const it = acState.items[index];
  if (!it) return;
  const text = els.filterInput.value;
  const before = text.slice(0, acState.start);
  els.filterInput.value = `${before}${it.value} `;
  state.filterText = els.filterInput.value;
  els.filterInput.focus();
  els.filterInput.setSelectionRange(els.filterInput.value.length, els.filterInput.value.length);
  renderPacketList();
  refreshSuggestions();
}

// Keyboard within the filter box while suggestions are open.
function filterKeydown(e) {
  const open = acState.items.length && !$('#filter-suggest').classList.contains('hidden');
  if (!open) {
    if (e.key === 'Escape' && state.filterText) { els.filterInput.value = ''; state.filterText = ''; renderPacketList(); }
    return;
  }
  if (e.key === 'ArrowDown') { e.preventDefault(); acState.active = (acState.active + 1) % acState.items.length; renderSuggestions(); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); acState.active = (acState.active - 1 + acState.items.length) % acState.items.length; renderSuggestions(); }
  else if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); acceptSuggestion(acState.active); }
  else if (e.key === 'Escape') { e.preventDefault(); hideSuggestions(); }
}

// ---- Large-capture load progress (ROADMAP §6.2) ----
// The backend streams packets in batches; when it can report a total (the
// memory-mapped fast path) the bar is determinate, otherwise it pulses.
const loadProgress = { active: false, total: 0, done: 0 };

function showLoadProgress(total) {
  loadProgress.active = true;
  loadProgress.total = total || 0;
  loadProgress.done = 0;
  const el = $('#load-progress');
  el.classList.remove('hidden');
  el.classList.toggle('indeterminate', !total);
  updateLoadProgress(0);
}

function updateLoadProgress(addDone) {
  if (!loadProgress.active) return;
  loadProgress.done += addDone;
  const bar = $('#load-bar');
  const label = $('#load-label');
  const el = $('#load-progress');
  if (loadProgress.total > 0) {
    const pct = Math.min(100, Math.round((loadProgress.done / loadProgress.total) * 100));
    bar.style.width = `${pct}%`;
    el.setAttribute('aria-valuenow', String(pct));
    label.textContent = `Loading capture… ${loadProgress.done.toLocaleString()} / ${loadProgress.total.toLocaleString()} (${pct}%)`;
  } else {
    label.textContent = `Loading capture… ${loadProgress.done.toLocaleString()} packets`;
  }
}

// ---- Export Objects & File Carving (Wireshark Counterparts) ----
function extractExportObjects(packets) {
  const objects = [];
  const flows = new Map();
  for (const p of packets) {
    const key = flowKeyOf(p);
    if (!key) continue;
    if (!flows.has(key)) flows.set(key, []);
    flows.get(key).push(p);
  }

  for (const [key, flowPkts] of flows.entries()) {
    flowPkts.sort((a, b) => a.epoch_ms - b.epoch_ms);

    let serverBytes = [];
    for (const p of flowPkts) {
      if (!p.fromClient) {
        const pl = extractPayload(p.raw || p.data);
        if (pl && pl.length > 0) {
          serverBytes.push(...pl);
        }
      }
    }

    if (serverBytes.length === 0) continue;

    const arr = new Uint8Array(serverBytes);
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    let headerEnd = -1;
    for (let i = 0; i < arr.length - 3; i++) {
      if (arr[i] === 13 && arr[i+1] === 10 && arr[i+2] === 13 && arr[i+3] === 10) {
        headerEnd = i;
        break;
      }
    }

    if (headerEnd !== -1) {
      const headerText = textDecoder.decode(arr.subarray(0, headerEnd));
      if (headerText.startsWith('HTTP/')) {
        let contentType = 'unknown';
        let contentLength = -1;
        let filename = 'downloaded_file';
        
        const lines = headerText.split('\r\n');
        for (const line of lines) {
          const lower = line.toLowerCase();
          if (lower.startsWith('content-type:')) {
            contentType = line.split(':')[1].trim();
          } else if (lower.startsWith('content-length:')) {
            contentLength = parseInt(line.split(':')[1].trim());
          } else if (lower.startsWith('content-disposition:')) {
            const match = /filename="?([^";]+)"?/i.exec(line);
            if (match) filename = match[1];
          }
        }

        let bodyBytes = arr.subarray(headerEnd + 4);
        if (contentLength !== -1 && bodyBytes.length > contentLength) {
          bodyBytes = bodyBytes.subarray(0, contentLength);
        }

        if (bodyBytes.length > 0) {
          if (filename === 'downloaded_file') {
            const ext = contentType.split('/')[1] || 'bin';
            filename = `http_object_${objects.length + 1}.${ext.split(';')[0].trim()}`;
          }

          objects.push({
            filename,
            protocol: 'HTTP',
            contentType,
            size: `${bodyBytes.length} bytes`,
            host: key.split('|')[1] || 'Unknown',
            data: bodyBytes,
          });
        }
      }
    }
  }
  return objects;
}

function carveFiles(packets) {
  const carved = [];
  let allBytes = [];
  for (const p of packets) {
    const pl = extractPayload(p.raw || p.data);
    if (pl && pl.length > 0) {
      allBytes.push(...pl);
    }
  }

  const bytes = new Uint8Array(allBytes);
  let i = 0;
  while (i < bytes.length) {
    // 1. PNG check
    if (i + 8 <= bytes.length &&
        bytes[i] === 0x89 && bytes[i+1] === 0x50 && bytes[i+2] === 0x4e && bytes[i+3] === 0x47 &&
        bytes[i+4] === 0x0d && bytes[i+5] === 0x0a && bytes[i+6] === 0x1a && bytes[i+7] === 0x0a) {
      let end = -1;
      for (let j = i + 8; j < bytes.length - 7; j++) {
        if (bytes[j] === 0x49 && bytes[j+1] === 0x45 && bytes[j+2] === 0x4e && bytes[j+3] === 0x44 &&
            bytes[j+4] === 0xae && bytes[j+5] === 0x42 && bytes[j+6] === 0x60 && bytes[j+7] === 0x82) {
          end = j + 8;
          break;
        }
      }
      if (end !== -1) {
        const data = bytes.slice(i, end);
        carved.push({
          filename: `carved_file_${carved.length + 1}.png`,
          type: 'PNG Image',
          size: `${data.length} bytes`,
          offset: `Offset 0x${i.toString(16)}`,
          data,
        });
        i = end;
        continue;
      }
    }

    // 2. JPEG check
    if (i + 3 <= bytes.length &&
        bytes[i] === 0xff && bytes[i+1] === 0xd8 && bytes[i+2] === 0xff) {
      let end = -1;
      for (let j = i + 3; j < bytes.length - 1; j++) {
        if (bytes[j] === 0xff && bytes[j+1] === 0xd9) {
          end = j + 2;
          break;
        }
      }
      if (end !== -1) {
        const data = bytes.slice(i, end);
        carved.push({
          filename: `carved_file_${carved.length + 1}.jpg`,
          type: 'JPEG Image',
          size: `${data.length} bytes`,
          offset: `Offset 0x${i.toString(16)}`,
          data,
        });
        i = end;
        continue;
      }
    }

    // 3. PDF check
    if (i + 4 <= bytes.length &&
        bytes[i] === 0x25 && bytes[i+1] === 0x50 && bytes[i+2] === 0x44 && bytes[i+3] === 0x46) {
      let end = -1;
      for (let j = i + 4; j < bytes.length - 4; j++) {
        if (bytes[j] === 0x25 && bytes[j+1] === 0x25 && bytes[j+2] === 0x45 && bytes[j+3] === 0x4f && bytes[j+4] === 0x46) {
          end = j + 5;
          break;
        }
      }
      if (end !== -1) {
        const data = bytes.slice(i, end);
        carved.push({
          filename: `carved_file_${carved.length + 1}.pdf`,
          type: 'PDF Document',
          size: `${data.length} bytes`,
          offset: `Offset 0x${i.toString(16)}`,
          data,
        });
        i = end;
        continue;
      }
    }

    // 4. ZIP check
    if (i + 4 <= bytes.length &&
        bytes[i] === 0x50 && bytes[i+1] === 0x4b && bytes[i+2] === 0x03 && bytes[i+3] === 0x04) {
      let end = -1;
      for (let j = i + 4; j < bytes.length - 21; j++) {
        if (bytes[j] === 0x50 && bytes[j+1] === 0x4b && bytes[j+2] === 0x05 && bytes[j+3] === 0x06) {
          end = j + 22;
          break;
        }
      }
      if (end !== -1) {
        const data = bytes.slice(i, end);
        carved.push({
          filename: `carved_file_${carved.length + 1}.zip`,
          type: 'ZIP Archive',
          size: `${data.length} bytes`,
          offset: `Offset 0x${i.toString(16)}`,
          data,
        });
        i = end;
        continue;
      }
    }

    i++;
  }
  return carved;
}

function showExportObjects() {
  const items = extractExportObjects(activePackets());
  renderObjectsModal('Export Objects', items);
}

function showFileCarving() {
  const items = carveFiles(activePackets());
  renderObjectsModal('File Carving', items, true);
}

function renderObjectsModal(title, items, isCarving = false) {
  if (items.length === 0) {
    openToolModal(title, `<div class="tool-empty">No objects or files found in this capture.</div>`);
    return;
  }

  window._activeModalItems = items;

  const headers = isCarving
    ? [
        { key: 'filename', label: 'Filename' },
        { key: 'type', label: 'Type' },
        { key: 'offset', label: 'Offset' },
        { key: 'size', label: 'Size' },
        { key: 'action', label: 'Action' }
      ]
    : [
        { key: 'filename', label: 'Filename' },
        { key: 'protocol', label: 'Protocol' },
        { key: 'contentType', label: 'Content Type' },
        { key: 'host', label: 'Source Host/IP' },
        { key: 'size', label: 'Size' },
        { key: 'action', label: 'Action' }
      ];

  const rows = items.map((item, idx) => {
    const row = { ...item };
    row.action = `<button class="btn btn-small btn-primary" onclick="downloadModalItem(${idx})">💾 Save</button>`;
    return row;
  });

  const head = headers.map((h) => `<th>${esc(h.label)}</th>`).join('');
  const body = rows.map((r) => '<tr>' + headers.map((h) => {
    const val = r[h.key] == null ? '' : r[h.key];
    const displayVal = h.key === 'action' ? val : esc(String(val));
    return `<td class="${h.num ? 'num' : ''}">${displayVal}</td>`;
  }).join('') + '</tr>').join('');

  const html = `<table class="tool-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
  openToolModal(title, html);
}

async function downloadModalItem(idx) {
  const item = window._activeModalItems && window._activeModalItems[idx];
  if (!item) return;

  const d = (window.__TAURI__ && window.__TAURI__.dialog) || null;
  if (!d) {
    alert('Dialog unavailable');
    return;
  }

  const path = await d.save({
    defaultPath: item.filename,
  });

  if (path) {
    try {
      await invoke('save_object', { path, bytes: Array.from(item.data) });
      alert(`File successfully saved to ${path}`);
    } catch (e) {
      alert(`Failed to save file: ${e}`);
    }
  }
}
window.downloadModalItem = downloadModalItem;

// ---- Customizable packet-list columns (ROADMAP §6.2) ----
// Each entry maps a grid track to a header/cell class. `dir` (the arrow) and
// `info` are always shown; everything else can be toggled and reordered.
const COLUMN_DEFS = {
  num:   { track: '52px',  label: 'No.',         cell: 'col-num',   header: 0, always: false },
  time:  { track: '132px', label: 'Time',        cell: 'col-time',  header: 1, always: false },
  src:   { track: '1fr',   label: 'Source',      cell: 'col-src',   header: 2, always: false },
  dst:   { track: '1fr',   label: 'Destination', cell: 'col-dst',   header: 4, always: false },
  proto: { track: '64px',  label: 'Proto',       cell: 'col-proto', header: 5, always: false },
  len:   { track: '60px',  label: 'Len',         cell: 'col-len',   header: 6, always: false },
};
const DEFAULT_COLUMN_ORDER = ['num', 'time', 'src', 'dst', 'proto', 'len'];

function columnConfig() {
  const cfg = state.settings.columns || {};
  const order = (cfg.order && cfg.order.filter((k) => COLUMN_DEFS[k])) || DEFAULT_COLUMN_ORDER.slice();
  // Any column missing from a saved order (e.g. after an upgrade) is appended.
  for (const k of DEFAULT_COLUMN_ORDER) if (!order.includes(k)) order.push(k);
  const hidden = new Set(cfg.hidden || []);
  return { order, hidden };
}

// Rebuild the grid template + cell order/visibility with one injected stylesheet
// so the header and every virtual row stay perfectly aligned.
function applyColumns() {
  const { order, hidden } = columnConfig();
  // The real column order in the DOM: num,time,src,dir,dst,proto,len,info.
  // We drive layout by (1) a grid-template that lists only visible tracks in
  // the chosen order and (2) a CSS `order` on each cell to match.
  const visible = order.filter((k) => !hidden.has(k));
  // Build the track list: place src/dst around the always-on dir arrow.
  const tracks = [];
  const orderRules = [];
  let pos = 0;
  const push = (cell, track) => { tracks.push(track); orderRules.push(`.${cell} { order: ${pos}; display: revert; }`); pos++; };
  for (const k of visible) {
    const def = COLUMN_DEFS[k];
    push(def.cell, def.track);
    if (k === 'src') { push('col-dir', '24px'); } // keep the arrow next to Source
  }
  if (!visible.includes('src')) push('col-dir', '24px');
  push('col-info', '2fr');
  // Hidden columns: remove from the grid entirely.
  for (const k of Object.keys(COLUMN_DEFS)) {
    if (hidden.has(k)) orderRules.push(`.${COLUMN_DEFS[k].cell} { display: none; }`);
  }
  const css = `.table-header, .packet-row { grid-template-columns: ${tracks.join(' ')} !important; }\n${orderRules.join('\n')}`;
  let styleEl = document.getElementById('column-style');
  if (!styleEl) { styleEl = document.createElement('style'); styleEl.id = 'column-style'; document.head.appendChild(styleEl); }
  styleEl.textContent = css;
}

function renderColumnsPanel() {
  const list = $('#columns-list');
  if (!list) return;
  const { order, hidden } = columnConfig();
  list.innerHTML = order.map((k, i) => {
    const def = COLUMN_DEFS[k];
    const on = !hidden.has(k);
    return `<div class="column-row" data-col="${k}">` +
      `<label class="popover-checkbox"><input type="checkbox" data-col-toggle="${k}"${on ? ' checked' : ''}> <span>${esc(def.label)}</span></label>` +
      `<span class="column-move">` +
      `<button class="btn-icon" data-col-up="${k}" ${i === 0 ? 'disabled' : ''} aria-label="Move up">▲</button>` +
      `<button class="btn-icon" data-col-down="${k}" ${i === order.length - 1 ? 'disabled' : ''} aria-label="Move down">▼</button>` +
      `</span></div>`;
  }).join('');
}

function saveColumns(order, hidden) {
  state.settings.columns = { order, hidden: [...hidden] };
  saveJSON('netscope.settings', state.settings);
  applyColumns();
  renderColumnsPanel();
}

function toggleColumn(key) {
  const { order, hidden } = columnConfig();
  if (hidden.has(key)) hidden.delete(key); else hidden.add(key);
  saveColumns(order, hidden);
}

function moveColumn(key, delta) {
  const { order, hidden } = columnConfig();
  const i = order.indexOf(key);
  const j = i + delta;
  if (i < 0 || j < 0 || j >= order.length) return;
  [order[i], order[j]] = [order[j], order[i]];
  saveColumns(order, hidden);
}

// ---- Tab pinning (ROADMAP §6.2) — right-click a tab to keep it marked ----
function pinnedTabs() { return new Set(state.settings.pinnedTabs || []); }

function applyTabPins() {
  const pins = pinnedTabs();
  $$('.tab').forEach((t) => {
    const isPinned = pins.has(t.dataset.view);
    t.classList.toggle('pinned', isPinned);
    t.setAttribute('aria-label', isPinned ? `${t.textContent.trim()} (pinned)` : t.textContent.trim());
  });
}

function toggleTabPin(view) {
  const pins = pinnedTabs();
  if (pins.has(view)) pins.delete(view); else pins.add(view);
  state.settings.pinnedTabs = [...pins];
  saveJSON('netscope.settings', state.settings);
  applyTabPins();
}

// ---- Init ----
async function init() {
  const urlParams = new URLSearchParams(window.location.search);
  const detached = urlParams.get('detached');
  if (detached) {
    document.body.classList.add('detached-mode', `detached-${detached}`);
  }

  Object.assign(els, {
    interfaceSelect: $('#interface-select'), startBtn: $('#start-btn'), stopBtn: $('#stop-btn'),
    statusText: $('#status-text'), packetCount: $('#packet-count'), filterInput: $('#filter-input'),
    elevationBadge: $('#elevation-badge'), packetList: $('#packet-list'),
    packetTable: $('#packet-table'), packetHeader: $('#packet-header'),
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
    topologyWrap: $('#topology-canvas-wrap'), topologyGl: $('#topology-gl'), topologyLabels: $('#topology-labels'),
    ioGl: $('#io-gl'), ioHint: $('#io-hint'),
    diffSnapA: $('#diff-snap-a'), diffSnapB: $('#diff-snap-b'), diffALabel: $('#diff-a-label'),
    diffBLabel: $('#diff-b-label'), diffRun: $('#diff-run'), diffBody: $('#diff-body'),
    privacyRescan: $('#privacy-rescan'), privacySummary: $('#privacy-summary'), privacyCost: $('#privacy-cost'), privacyList: $('#privacy-list'),
    summaryOpen: $('#summary-open'), busiestPeak: $('#busiest-peak'), busiestChart: $('#busiest-chart'), busiestHint: $('#busiest-hint'),
    hexPanel: $('#hex-panel'), statProjection: $('#stat-projection'),
    noiseFilterCheck: $('#noise-filter-check'), reportAnon: $('#report-anon'),
    geoipDbChoose: $('#geoip-db-choose'), geoipDbClear: $('#geoip-db-clear'), geoipDbStatus: $('#geoip-db-status'),
    alertBtn: $('#alert-btn'), alertBadge: $('#alert-badge'), alertPanel: $('#alert-panel'), alertList: $('#alert-list'),
    triggerList: $('#trigger-list'), trigField: $('#trig-field'), trigOp: $('#trig-op'), trigValue: $('#trig-value'), trigAdd: $('#trig-add'),
  });

  // Wire up view navigation FIRST, synchronously, before any await. Tab
  // switching and keyboard shortcuts must never depend on IPC or event
  // subscription succeeding — otherwise a slow/failed async step below would
  // abort init() and leave the tabs unresponsive.
  $$('.tab').forEach((t) => t.addEventListener('click', () => switchView(t.dataset.view)));
  // Arrow-key navigation within the tablist (a11y, ROADMAP §6.3).
  $('#tabs').addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    const tabs = [...$$('.tab')];
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    const j = (i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    tabs[j].focus();
    switchView(tabs[j].dataset.view);
  });
  document.addEventListener('keydown', handleKeydown);
  initMenuBar();

  // Bind custom desktop layout events
  const miNewWindow = $('#mi-new-window');
  if (miNewWindow) {
    miNewWindow.addEventListener('click', () => {
      if (window.__TAURI__) {
        window.__TAURI__.core.invoke('open_new_window');
      }
    });
  }
  const miSplitView = $('#mi-split-view');
  if (miSplitView) {
    miSplitView.addEventListener('click', toggleSplitView);
  }
  const splitSelect = $('#split-view-select');
  if (splitSelect) {
    splitSelect.addEventListener('change', (e) => {
      applySplitView(e.target.value);
    });
  }
  const detailDetach = $('#detail-detach');
  if (detailDetach) {
    detailDetach.addEventListener('click', () => {
      if (window.__TAURI__) {
        window.__TAURI__.core.invoke('open_detached_window', { viewType: 'detail' });
        document.body.classList.add('main-detached-detail');
      }
    });
  }
  const hexDetach = $('#hex-detach');
  if (hexDetach) {
    hexDetach.addEventListener('click', () => {
      if (window.__TAURI__) {
        window.__TAURI__.core.invoke('open_detached_window', { viewType: 'hex' });
        document.body.classList.add('main-detached-hex');
      }
    });
  }

  if (detached && window.__TAURI__) {
    window.__TAURI__.event.listen("packet-selected", (event) => {
      const pkt = event.payload;
      if (pkt) {
        els.detailTree.innerHTML = buildDetailTree(pkt, 0);
        els.hexDump.innerHTML = hexDump(pkt.raw || []);
        els.hexLen.textContent = `${(pkt.raw || []).length} bytes`;
        enrichGeo(pkt);
      }
    });
  }

  // Translate all static UI chrome to the saved/detected language up front.
  I18N.apply(state.settings.lang);
  els.langSelect.value = state.settings.lang;
  els.packetCount.textContent = `0 ${I18N.t('unit.packets')}`;

  await loadInterfaces();
  await loadLearn();

  // Restore the offline GeoIP database, if one was configured. Not awaited —
  // location enrichment can come online a moment after the UI does.
  if (state.settings.geoipDb) loadGeoDb(state.settings.geoipDb, { quiet: true });

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
    await listen('packets-batch', onPacketBatch);
    // Total packet count for a file open (memory-mapped fast path) → a
    // determinate progress bar; without it the bar just pulses.
    await listen('capture-total', (e) => { if (loadProgress.active) showLoadProgress(e.payload || 0); });
    await listen('capture-finished', () => { setStatus(STATES.IDLE); els.startBtn.disabled = false; els.stopBtn.disabled = true; finishLoadProgress(); });
    // A live capture that stops on its own (autostop limit reached, remote/USB
    // stream ended) → return the UI to idle.
    await listen('capture-stopped', onCaptureStopped);
  } catch (e) { console.error('event subscription failed', e); }

  // Layered config (~/.netscope): surface what the backend loaded at startup
  // — an auto-loaded offline GeoIP DB and any protocol-plugin errors.
  try {
    const appCfg = await invoke('get_app_config');
    if (appCfg) {
      state.appConfig = appCfg;
      if (appCfg.geoip_db && !state.geoDb) {
        state.geoDb = appCfg.geoip_db;
        renderGeoDbStatus();
      }
      for (const err of appCfg.plugin_errors || []) console.warn('netscope plugin:', err);
      if (appCfg.plugins_loaded) console.info(`netscope: ${appCfg.plugins_loaded} protocol plugin(s) loaded from ${appCfg.plugins_dir}`);
    }
  } catch (e) { /* command missing in older backends — ignore */ }

  els.startBtn.addEventListener('click', startCapture);
  els.stopBtn.addEventListener('click', stopCapture);
  els.filterInput.addEventListener('input', () => { state.filterText = els.filterInput.value; renderPacketList(); refreshSuggestions(); });
  els.filterInput.addEventListener('keydown', filterKeydown);
  els.filterInput.addEventListener('blur', () => setTimeout(hideSuggestions, 120));
  // Click a suggestion to accept it (mousedown so it fires before blur hides).
  $('#filter-suggest').addEventListener('mousedown', (e) => {
    const item = e.target.closest('[data-i]');
    if (item) { e.preventDefault(); acceptSuggestion(+item.dataset.i); }
  });

  // Column chooser: toggle visibility / reorder, persisted in settings.
  applyColumns();
  const columnsList = $('#columns-list');
  if (columnsList) {
    columnsList.addEventListener('change', (e) => {
      const key = e.target.dataset.colToggle;
      if (key) toggleColumn(key);
    });
    columnsList.addEventListener('click', (e) => {
      const up = e.target.closest('[data-col-up]');
      const down = e.target.closest('[data-col-down]');
      if (up) moveColumn(up.dataset.colUp, -1);
      else if (down) moveColumn(down.dataset.colDown, 1);
    });
  }
  const columnsPanel = $('#columns-panel');
  document.addEventListener('click', (e) => {
    if (columnsPanel.classList.contains('hidden')) return;
    if (!columnsPanel.contains(e.target) && !e.target.closest('#mi-columns')) columnsPanel.classList.add('hidden');
  });

  // Tab pinning: right-click a tab to mark it; pins persist across restarts.
  applyTabPins();
  $$('.tab').forEach((t) => t.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    toggleTabPin(t.dataset.view);
  }));
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

  // Offline GeoIP database — pick a .mmdb file; lookups then stay local.
  if (els.geoipDbChoose) {
    els.geoipDbChoose.addEventListener('click', async () => {
      const d = (window.__TAURI__ && window.__TAURI__.dialog) || null;
      if (!d) return;
      const path = await d.open({
        multiple: false,
        filters: [{ name: 'MaxMind DB', extensions: ['mmdb'] }],
      });
      if (path) loadGeoDb(path);
    });
    els.geoipDbClear.addEventListener('click', clearGeoDb);
  }

  // Report IP anonymisation
  els.reportAnon.addEventListener('change', renderReportBody);
  els.packetList.addEventListener('click', (e) => {
    const row = e.target.closest('.packet-row');
    if (row) { showDetail(parseInt(row.dataset.index)); renderPacketList(); }
  });
  // Virtual scrolling: re-render the visible window on scroll (rAF-throttled).
  if (els.packetTable) {
    let vsPending = false;
    els.packetTable.addEventListener('scroll', () => {
      if (state.view !== 'packets' || !state.filteredPackets.length || vsPending) return;
      vsPending = true;
      requestAnimationFrame(() => { vsPending = false; renderPacketRows(); });
    });
  }
  // Right-click a packet row → Wireshark-style context menu (Follow Stream…).
  els.packetList.addEventListener('contextmenu', (e) => {
    const row = e.target.closest('.packet-row');
    if (!row) return;
    e.preventDefault();
    const idx = parseInt(row.dataset.index);
    showDetail(idx);
    renderPacketList();
    showPacketContextMenu(e, idx);
  });
  const ctxMenu = $('#ctx-menu');
  if (ctxMenu) {
    ctxMenu.addEventListener('click', (e) => {
      const item = e.target.closest('[data-ctx]');
      if (item && !item.disabled) onCtxMenuAction(item.dataset.ctx, parseInt(ctxMenu.dataset.index));
    });
  }
  document.addEventListener('click', hideCtxMenu);
  document.addEventListener('contextmenu', (e) => {
    if (!e.target.closest('.packet-row') && !e.target.closest('#ctx-menu')) hideCtxMenu();
  });
  window.addEventListener('blur', hideCtxMenu);
  els.connList.addEventListener('click', (e) => {
    const b = e.target.closest('[data-block]');
    const u = e.target.closest('[data-unblock]');
    const f = e.target.closest('[data-follow]');
    const g = e.target.closest('[data-graph-stream]');
    if (b) doBlock(b.dataset.block);
    else if (u) doUnblock(u.dataset.unblock);
    else if (f) openFollowStream(f.dataset.follow);
    else if (g) openTcpStreamGraph(g.dataset.graphStream);
  });
  els.streamClose.addEventListener('click', closeFollowStream);
  els.streamModal.addEventListener('click', (e) => { if (e.target === els.streamModal) closeFollowStream(); });

  // TCP Stream Graph modal wiring
  on('#tcp-graph-close', closeTcpStreamGraph);
  $('#tcp-graph-modal').addEventListener('click', (e) => { if (e.target === $('#tcp-graph-modal')) closeTcpStreamGraph(); });
  $$('#tcp-graph-modal .modal-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      openTcpStreamGraph(tcpGraphState.key, btn.dataset.graph);
    });
  });

  // VoIP modal wiring
  on('#voip-close', closeVoipModal);
  $('#voip-modal').addEventListener('click', (e) => { if (e.target === $('#voip-modal')) closeVoipModal(); });
  $$('#voip-modal .modal-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      switchVoipTab(btn.dataset.voipTab);
    });
  });

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

  // Accessibility: interface/text scale + colour-blind-safe palette.
  applyTextScale(state.settings.textScale);
  applyCvd(state.settings.cvd);
  const textSizeSel = $('#text-size-select');
  if (textSizeSel) {
    textSizeSel.value = String(state.settings.textScale || 1);
    textSizeSel.addEventListener('change', () => {
      state.settings.textScale = Number(textSizeSel.value) || 1;
      applyTextScale(state.settings.textScale);
      saveJSON('netscope.settings', state.settings);
    });
  }
  const cvdCheck = $('#cvd-check');
  if (cvdCheck) {
    cvdCheck.checked = !!state.settings.cvd;
    cvdCheck.addEventListener('change', () => {
      state.settings.cvd = cvdCheck.checked;
      applyCvd(state.settings.cvd);
      saveJSON('netscope.settings', state.settings);
      renderAll(); // re-render so protoColor-driven inline colours update
    });
  }

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

// ---- Test hooks ----
// The vitest suite loads this file in a Node vm sandbox. Top-level `function`
// declarations attach to the sandbox global, but `const`s (state, els) do
// not — hand them over explicitly so render functions can be unit-tested.
// Inert in the real app: nothing reads __netscopeTest there.
if (typeof globalThis !== 'undefined') {
  globalThis.__netscopeTest = { state, els };
}
