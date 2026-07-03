// netscope Desktop — Frontend
// Uses window.__TAURI__ for IPC (gracefully falls back when not in Tauri)

const PROTOCOL_COLORS = {
  TCP: '#4a9ef5',
  UDP: '#45d1c5',
  DNS: '#a78bfa',
  HTTP: '#34d399',
  TLS: '#6ee7b7',
  ICMP: '#fbbf24',
  ARP: '#9ca3af',
};

const STATES = { IDLE: 'Idle', CAPTURING: 'Capturing', PAUSED: 'Paused' };

let state = {
  view: 'packets',
  packets: [],
  filteredPackets: [],
  selectedIndex: -1,
  detailExpanded: false,
  showHex: false,
  filterText: '',
  status: STATES.IDLE,
  packetCount: 0,
  stats: {
    totalPackets: 0,
    totalBytes: 0,
    perProtocol: {},
    bandwidth: 0,
    topTalkersSent: [],
    topTalkersReceived: [],
    topDomains: [],
  },
  interfaces: [],
};

// ---- Tauri IPC helpers ----
async function tauriInvoke(cmd, args = {}) {
  try {
    if (window.__TAURI__) {
      return await window.__TAURI__.core.invoke(cmd, args);
    }
    console.warn(`[mock] invoke ${cmd}`, args);
    return null;
  } catch (e) {
    console.error(`invoke ${cmd}:`, e);
    throw e;
  }
}

async function tauriListen(event, handler) {
  try {
    if (window.__TAURI__) {
      return await window.__TAURI__.event.listen(event, handler);
    }
    console.warn(`[mock] listen ${event}`);
  } catch (e) {
    console.error(`listen ${event}:`, e);
  }
}

// ---- DOM refs ----
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const els = {
  interfaceSelect: $('#interface-select'),
  startBtn: $('#start-btn'),
  stopBtn: $('#stop-btn'),
  statusText: $('#status-text'),
  packetCount: $('#packet-count'),
  filterInput: $('#filter-input'),
  packetList: $('#packet-list'),
  detailPanel: $('#detail-panel'),
  detailContent: $('#detail-content'),
  detailClose: $('#detail-close'),
  hexDump: $('#hex-dump'),
  hexToggle: $('#hex-toggle'),
  statTotalPackets: $('#stat-total-packets'),
  statTotalBytes: $('#stat-total-bytes'),
  statBandwidth: $('#stat-bandwidth'),
  protoBars: $('#proto-bars'),
  talkerList: $('#talker-list'),
  dnsList: $('#dns-list'),
};

// ---- Interface listing ----
async function loadInterfaces() {
  try {
    const ifaces = await tauriInvoke('list_interfaces');
    if (ifaces && ifaces.length > 0) {
      state.interfaces = ifaces;
      els.interfaceSelect.innerHTML = ifaces
        .map((d) => `<option value="${d.name}">${d.name} — ${d.description || ''}</option>`)
        .join('');
      els.interfaceSelect.disabled = false;
    } else {
      els.interfaceSelect.innerHTML = '<option>No interfaces found</option>';
    }
  } catch (e) {
    els.interfaceSelect.innerHTML = '<option>Error loading interfaces</option>';
  }
}

// ---- Capture control ----
async function startCapture() {
  const iface = els.interfaceSelect.value;
  const filter = els.filterInput.value || null;
  try {
    await tauriInvoke('start_capture', { interface: iface, filter });
    setStatus(STATES.CAPTURING);
    els.startBtn.disabled = true;
    els.stopBtn.disabled = false;
    els.filterInput.disabled = true;
  } catch (e) {
    console.error('Start capture failed:', e);
  }
}

async function stopCapture() {
  try {
    await tauriInvoke('stop_capture');
    setStatus(STATES.IDLE);
    els.startBtn.disabled = false;
    els.stopBtn.disabled = true;
    els.filterInput.disabled = false;
  } catch (e) {
    console.error('Stop capture failed:', e);
  }
}

function setStatus(s) {
  state.status = s;
  els.statusText.textContent = `● ${s}`;
  els.statusText.className = s === STATES.CAPTURING ? 'status-capturing' : s === STATES.PAUSED ? 'status-paused' : 'status-idle';
}

// ---- Packet rendering ----
function renderPacketRow(pkt, index) {
  const protoColor = PROTOCOL_COLORS[pkt.protocol] || '#f87171';
  const selected = index === state.selectedIndex ? ' selected' : '';
  const dir = pkt.src_addr && pkt.dst_addr ? '\u2192' : '';

  return `
    <div class="packet-row${selected}" data-index="${index}" data-protocol="${pkt.protocol}">
      <span class="col-num">${index + 1}</span>
      <span class="col-time">${pkt.timestamp || ''}</span>
      <span class="col-src">${pkt.src_addr || ''}</span>
      <span class="col-dir" style="color:${protoColor}">${dir}</span>
      <span class="col-dst">${pkt.dst_addr || ''}</span>
      <span class="col-proto" style="color:${protoColor};font-weight:600">${pkt.protocol}</span>
      <span class="col-len">${pkt.length}B</span>
      <span class="col-info">${pkt.summary}</span>
    </div>`;
}

function renderPacketList() {
  const packets = state.filterText
    ? state.packets.filter((p) => matchesFilter(p, state.filterText))
    : state.packets;

  state.filteredPackets = packets;

  if (packets.length === 0) {
    els.packetList.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted)">No packets</div>';
    return;
  }

  const start = Math.max(0, packets.length - 500);
  const visible = packets.slice(start);

  els.packetList.innerHTML = visible
    .map((pkt, i) => renderPacketRow(pkt, start + i))
    .join('');

  // Highlight selected
  if (state.selectedIndex >= 0) {
    const sel = els.packetList.querySelector(`.packet-row[data-index="${state.selectedIndex}"]`);
    if (sel) sel.scrollIntoView({ block: 'nearest' });
  }
}

function matchesFilter(pkt, text) {
  const lower = text.toLowerCase();
  return (
    pkt.summary.toLowerCase().includes(lower) ||
    pkt.protocol.toLowerCase().includes(lower) ||
    (pkt.src_addr && pkt.src_addr.includes(lower)) ||
    (pkt.dst_addr && pkt.dst_addr.includes(lower))
  );
}

// ---- Detail panel ----
function showDetail(index) {
  const pkt = state.filteredPackets[index];
  if (!pkt) return;

  state.selectedIndex = index;
  state.detailExpanded = true;
  els.detailPanel.classList.remove('hidden');

  const protoColor = PROTOCOL_COLORS[pkt.protocol] || '#f87171';

  els.detailContent.innerHTML = `
    <div class="detail-field">
      <span class="detail-label">Protocol:</span>
      <span style="color:${protoColor};font-weight:600">${pkt.protocol}</span>
    </div>
    <div class="detail-field">
      <span class="detail-label">Summary:</span>
      <span style="font-weight:600">${pkt.summary}</span>
    </div>
    <div class="detail-field">
      <span class="detail-label">Source:</span>
      <span>${pkt.src_addr || '?'}${pkt.src_port ? ':' + pkt.src_port : ''}</span>
    </div>
    <div class="detail-field">
      <span class="detail-label">Destination:</span>
      <span>${pkt.dst_addr || '?'}${pkt.dst_port ? ':' + pkt.dst_port : ''}</span>
    </div>
    <div class="detail-field">
      <span class="detail-label">Length:</span>
      <span>${pkt.length} bytes</span>
    </div>
    <div class="detail-field">
      <span class="detail-label">Timestamp:</span>
      <span>${pkt.timestamp || ''}</span>
    </div>
  `;

  // Hex dump
  state.showHex = false;
  els.hexDump.classList.add('hidden');
  renderHexDump(pkt);
}

function hideDetail() {
  state.detailExpanded = false;
  state.selectedIndex = -1;
  els.detailPanel.classList.add('hidden');
}

function renderHexDump(pkt) {
  // We'd need raw data — for now, placeholder
  if (state.showHex) {
    els.hexDump.classList.remove('hidden');
    // In a full implementation, the raw packet data would be sent from the backend
    els.hexDump.textContent = '(Raw packet data not available in desktop app yet)';
  } else {
    els.hexDump.classList.add('hidden');
  }
}

// ---- Stats rendering ----
function renderStats() {
  const s = state.stats;
  els.statTotalPackets.textContent = s.totalPackets.toLocaleString();
  els.statTotalBytes.textContent = formatBytes(s.totalBytes);
  els.statBandwidth.textContent = `${(s.bandwidth / 1000).toFixed(1)} KB/s`;

  // Protocol distribution
  const protocols = Object.entries(s.perProtocol).sort((a, b) => b[1].total_packets - a[1].total_packets);
  const maxPkts = protocols.length > 0 ? protocols[0][1].total_packets : 1;

  els.protoBars.innerHTML = protocols
    .map(([proto, stats]) => {
      const color = PROTOCOL_COLORS[proto] || '#f87171';
      const pct = s.totalPackets > 0 ? ((stats.total_packets / s.totalPackets) * 100).toFixed(1) : '0';
      const barPct = (stats.total_packets / maxPkts) * 100;
      return `
        <div class="proto-bar-row">
          <span class="proto-label" style="color:${color}">${proto}</span>
          <div class="proto-bar-bg">
            <div class="proto-bar-fill" style="width:${barPct}%;background:${color}"></div>
          </div>
          <span class="proto-pct">${pct}%</span>
        </div>`;
    })
    .join('') || '<div style="color:var(--text-muted);font-size:12px">No data</div>';

  // Top talkers (sent)
  const talkers = s.topTalkersSent || [];
  els.talkerList.innerHTML = talkers
    .slice(0, 8)
    .map(([ip, bytes]) => `
      <div class="talker-item">
        <span class="talker-ip">${ip}</span>
        <span class="talker-bytes">${formatBytes(bytes)}</span>
      </div>`)
    .join('') || '<div style="color:var(--text-muted);font-size:12px">No data</div>';

  // DNS domains
  const domains = s.topDomains || [];
  els.dnsList.innerHTML = domains
    .slice(0, 10)
    .map(([domain, count]) => `
      <div class="dns-item">
        <span class="dns-domain">${domain}</span>
        <span class="dns-count">${count}</span>
      </div>`)
    .join('') || '<div style="color:var(--text-muted);font-size:12px">No domains</div>';
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ---- Stats update from packet events ----
function updateStats(pkt) {
  const s = state.stats;
  s.totalPackets++;
  s.totalBytes += pkt.length;

  if (!s.perProtocol[pkt.protocol]) {
    s.perProtocol[pkt.protocol] = { total_packets: 0, total_bytes: 0 };
  }
  s.perProtocol[pkt.protocol].total_packets++;
  s.perProtocol[pkt.protocol].total_bytes += pkt.length;

  // Track sent bytes by IP
  if (pkt.src_addr) {
    const existing = s.topTalkersSent.find(([ip]) => ip === pkt.src_addr);
    if (existing) existing[1] += pkt.length;
    else s.topTalkersSent.push([pkt.src_addr, pkt.length]);
  }

  // Track DNS domains from summaries
  if (pkt.protocol === 'DNS') {
    const domain = extractDomain(pkt.summary);
    if (domain) {
      if (!s.topDomains.find(([d]) => d === domain)) {
        s.topDomains.push([domain, 0]);
      }
      const entry = s.topDomains.find(([d]) => d === domain);
      entry[1]++;
    }
  }

  // Sort top talkers
  s.topTalkersSent.sort((a, b) => b[1] - a[1]);
  s.topTalkersSent = s.topTalkersSent.slice(0, 10);
  s.topDomains.sort((a, b) => b[1] - a[1]);
  s.topDomains = s.topDomains.slice(0, 10);
}

function extractDomain(summary) {
  const m = summary.match(/DNS (?:Query|Response) — (\S+)/);
  return m ? m[1] : null;
}

// ---- Packet event handler ----
function onPacket(event) {
  const pkt = event.payload;
  state.packets.push(pkt);
  if (state.packets.length > 10000) state.packets.shift();

  state.packetCount++;
  els.packetCount.textContent = `${state.packetCount} packets`;

  updateStats(pkt);
  renderPacketList();
  renderStats();
}

// ---- View switching ----
function switchView(view) {
  state.view = view;
  $$('.view').forEach((el) => el.classList.remove('active'));
  const target = $(`#view-${view}`);
  if (target) target.classList.add('active');
}

// ---- Keyboard shortcuts ----
function handleKeydown(e) {
  const key = e.key;

  if (key === 'Tab') {
    e.preventDefault();
    const views = ['packets', 'dashboard'];
    const idx = views.indexOf(state.view);
    switchView(views[(idx + 1) % views.length]);
    return;
  }

  if (state.view === 'packets') {
    if (key === 'ArrowDown' || key === 'j') {
      e.preventDefault();
      const idx = Math.min(state.selectedIndex + 1, state.filteredPackets.length - 1);
      showDetail(idx);
      renderPacketList();
    } else if (key === 'ArrowUp' || key === 'k') {
      e.preventDefault();
      const idx = Math.max(state.selectedIndex - 1, 0);
      showDetail(idx);
      renderPacketList();
    } else if (key === 'Enter') {
      e.preventDefault();
      if (state.selectedIndex >= 0) {
        if (state.detailExpanded && !els.detailPanel.classList.contains('hidden')) {
          hideDetail();
        } else {
          showDetail(state.selectedIndex);
        }
      }
    } else if (key === 'h') {
      state.showHex = !state.showHex;
      const pkt = state.filteredPackets[state.selectedIndex];
      if (pkt) renderHexDump(pkt);
    } else if (key === 'Escape') {
      hideDetail();
    }
  }

  if (key === '?' && !e.ctrlKey && !e.metaKey) {
    // Simple help — could show a modal
  }
}

// ---- Init ----
async function init() {
  await loadInterfaces();

  // Listen for Tauri events
  await tauriListen('packet', onPacket);
  await tauriListen('capture-finished', () => {
    setStatus(STATES.IDLE);
    els.startBtn.disabled = false;
  });

  // Event listeners
  els.startBtn.addEventListener('click', startCapture);
  els.stopBtn.addEventListener('click', stopCapture);

  els.filterInput.addEventListener('input', () => {
    state.filterText = els.filterInput.value;
    renderPacketList();
  });

  els.packetList.addEventListener('click', (e) => {
    const row = e.target.closest('.packet-row');
    if (row) {
      const idx = parseInt(row.dataset.index);
      showDetail(idx);
      renderPacketList();
    }
  });

  els.detailClose.addEventListener('click', hideDetail);

  els.hexToggle.addEventListener('click', () => {
    state.showHex = !state.showHex;
    const pkt = state.filteredPackets[state.selectedIndex];
    if (pkt) renderHexDump(pkt);
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', handleKeydown);

  // Initial render
  renderPacketList();
  renderStats();
}

document.addEventListener('DOMContentLoaded', init);
