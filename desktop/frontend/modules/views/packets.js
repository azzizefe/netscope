// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
// netscope Desktop — Packets View Module
// Handles virtual scrolling, packet list rendering, and protocol detail trees.

// Shared application scope. These modules were split out of app.js but never
// received its bindings, so every function here that touched `els`, `state` or
// a helper threw ReferenceError at runtime. The cycle with app.js is safe:
// the imports are only dereferenced inside function bodies, long after both
// modules have finished evaluating.
import { $, beautifyPayload, colorRuleFor, decodeStreamText, els, endpointLabel, enrichGeo, esc, expertInfo, extractPayload, formatPacketTime, guessProtocol, isNoise, isPublicIp, matchesFilter, protoColor, semanticEvents, state, updateFilterFeedback } from '../../app.js';

const ROW_H = 24;
const VSCROLL_OVERSCAN = 12;

export function packetRowHtml(pkt, idx) {
  const c = protoColor(pkt.protocol);
  const isSel = idx === state.selectedIndex;
  const sel = isSel ? ' selected' : '';
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
window.packetRowHtml = packetRowHtml;

export function renderPacketRows() {
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
window.renderPacketRows = renderPacketRows;

export function renderPacketList() {
  let packets;
  if (state.filterText) {
    const compiled = typeof NetscopeFilter !== 'undefined'
      ? NetscopeFilter.compile(state.filterText)
      : null;
    packets = compiled
      ? NetscopeFilter.matchesBatch(compiled, state.packets)
      : state.packets.filter((p) => matchesFilter(p, state.filterText));
  } else {
    packets = state.packets;
  }
  if (state.settings.noiseFilter) packets = packets.filter((p) => !isNoise(p));
  state.filteredPackets = packets;

  // Restore selection: if a packet was selected, find its new index in the
  // rebuilt filteredPackets array. When the selected packet was evicted (shift),
  // clear the detail pane so the UI never shows stale data or out-of-bounds.
  if (state.selectedPacket) {
    const newIdx = packets.indexOf(state.selectedPacket);
    if (newIdx >= 0) {
      state.selectedIndex = newIdx;
    } else {
      state.selectedIndex = -1;
      state.selectedPacket = null;
      const detailContainer = typeof $ !== 'undefined' ? $('#view-packets') : null;
      if (detailContainer) detailContainer.classList.remove('with-detail');
    }
  }

  updateFilterFeedback();

  if (!packets.length) {
    els.packetList.style.height = 'auto';
    els.packetList.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted)">No packets yet</div>';
    return;
  }

  const scroller = els.packetTable || els.packetList.parentElement;
  const nearBottom =
    scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 3 * ROW_H;
  renderPacketRows();
  if (nearBottom) scroller.scrollTop = scroller.scrollHeight;
}
window.renderPacketList = renderPacketList;

export function transportName(proto) {
  if (['TCP', 'HTTP', 'TLS', 'WebSocket', 'HTTP/2', 'gRPC', 'PostgreSQL', 'MySQL', 'MongoDB', 'Redis', 'Cassandra', 'Modbus', 'DNP3', 'EtherNet/IP', 'OPC UA', 'LDAP', 'MQTT', 'BGP'].includes(proto)) return 'TCP';
  if (['UDP', 'DNS', 'BACnet', 'RTP', 'RTCP', 'Kerberos', 'RADIUS', 'OpenVPN', 'WireGuard', 'CoAP'].includes(proto)) return 'UDP';
  if (proto === 'ICMP' || proto === 'ARP') return proto;
  return null;
}
window.transportName = transportName;

const u16be = (raw, off) => ((raw[off] << 8) | raw[off + 1]) >>> 0;
const macStr = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(':');

export function fieldRanges(raw) {
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
window.fieldRanges = fieldRanges;

export function treeNode(label, sub, fields, extraClass = '') {
  const head = `<div class="tnode-head"><span class="twist">▾</span>` +
    `<span class="tlabel">${esc(label)}${sub ? ` <span class="tlabel-sub">${esc(sub)}</span>` : ''}</span></div>`;
  const body = `<div class="tbody">${fields.map(([k, v, mono, range]) => {
    const attrs = range ? ` data-range="${range[0]},${range[1]}"` : '';
    const cls = range ? 'tfield tfield-click' : 'tfield';
    return `<div class="${cls}"${attrs}><span class="tkey">${esc(k)}</span><span class="tval${mono ? ' mono' : ''}">${esc(v)}</span></div>`;
  }).join('')}</div>`;
  return `<div class="tnode ${extraClass}">${head}${body}</div>`;
}
window.treeNode = treeNode;

export function buildDetailTree(pkt, index) {
  const nodes = [];
  const raw = pkt.raw || [];
  const R = fieldRanges(raw);
  const ipVer = pkt.src_addr ? (pkt.src_addr.includes(':') ? 'IPv6' : 'IPv4') : null;
  const transport = transportName(pkt.protocol);
  const chain = ['Ethernet', ipVer, transport !== pkt.protocol ? transport : null, pkt.protocol]
    .filter((x, i, a) => x && a.indexOf(x) === i);

  nodes.push(treeNode(`Frame ${index + 1}`, `${pkt.length} bytes on wire`, [
    ['Arrival time', formatPacketTime(pkt)],
    ['Frame length', `${pkt.length} bytes`],
    ['Captured bytes', `${raw.length} bytes`],
    ['Protocols in frame', chain.join(' · ')],
  ]));

  if (R.ethDst && raw.length >= 14) {
    nodes.push(treeNode('Ethernet II', '', [
      ['Destination', macStr(raw.slice(R.ethDst[0], R.ethDst[1])), true, R.ethDst],
      ['Source', macStr(raw.slice(R.ethSrc[0], R.ethSrc[1])), true, R.ethSrc],
      ['EtherType', `0x${u16be(raw, R.ethType[0]).toString(16).padStart(4, '0')}`, true, R.ethType],
    ]));
  }

  if (pkt.src_addr || pkt.dst_addr) {
    const net = [];
    if (pkt.src_addr) net.push(['Source address', pkt.src_addr, true, R.ipSrc]);
    if (state.settings.showHostnames && pkt.src_host) net.push(['Source host', pkt.src_host]);
    if (pkt.dst_addr) net.push(['Destination address', pkt.dst_addr, true, R.ipDst]);
    if (state.settings.showHostnames && pkt.dst_host) net.push(['Destination host', pkt.dst_host]);
    nodes.push(treeNode(`Internet Protocol ${ipVer ? `(${ipVer})` : ''}`.trim(),
      pkt.src_addr && pkt.dst_addr ? `${pkt.src_addr} → ${pkt.dst_addr}` : '', net));
  }

  for (const [role, ip] of [['Destination', pkt.dst_addr], ['Source', pkt.src_addr]]) {
    if (!isPublicIp(ip)) continue;
    nodes.push(`<div class="tnode tnode-geo geo-node" data-ip="${esc(ip)}" data-role="${role}">` +
      `<div class="tnode-head"><span class="twist">▾</span>` +
      `<span class="tlabel">🌍 ${role} location <span class="tlabel-sub">${esc(ip)}</span></span></div>` +
      `<div class="tbody"><div class="tfield"><span class="tkey">Location</span>` +
      `<span class="tval geo-status">${state.geoDb ? 'Looking up…' : esc(I18N.t('geoip.off'))}</span></div></div></div>`);
  }

  if (transport && (pkt.src_port != null || pkt.dst_port != null)) {
    const t = [['Transport', transport]];
    if (pkt.src_port != null) t.push(['Source port', String(pkt.src_port), true, R.srcPort]);
    if (pkt.dst_port != null) t.push(['Destination port', String(pkt.dst_port), true, R.dstPort]);
    nodes.push(treeNode(transport,
      `${pkt.src_port ?? '?'} → ${pkt.dst_port ?? '?'}`, t));
  }

  nodes.push(treeNode(pkt.protocol, 'application data', [
    ['Protocol', pkt.protocol],
    ['Info', pkt.summary || '—'],
  ]));

  const ei = expertInfo(pkt);
  if (ei) {
    nodes.push(`<div class="tnode tnode-expert ${ei.cls}"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">${ei.icon} Expert Info</span></div>` +
      `<div class="tbody"><div class="tfield"><span class="tkey">Notice</span><span class="tval">${esc(ei.label)}</span></div></div></div>`);
  }

  if (pkt.protocol === 'Unknown' || (['TCP', 'UDP'].includes(pkt.protocol) && (pkt.raw || []).length > 42)) {
    const g = guessProtocol(pkt);
    if (g) {
      const pct = Math.round(g.confidence * 100);
      nodes.push(`<div class="tnode tnode-guess"><div class="tnode-head">` +
        `<span class="twist">▾</span><span class="tlabel">🔮 Protocol guess <span class="tlabel-sub">${esc(g.label)} · ${pct}% confidence</span></span></div>` +
        `<div class="tbody">${g.reasons.map((r) => `<div class="tfield"><span class="tkey">•</span><span class="tval">${esc(r)}</span></div>`).join('')}</div></div>`);
    }
  }

  const events = semanticEvents(pkt);
  if (events.length) {
    nodes.push(`<div class="tnode tnode-semantic"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">🧩 What happened</span></div>` +
      `<div class="tbody">${events.map((e) => `<div class="tfield"><span class="tkey">${e.icon}</span><span class="tval">${esc(e.text)}</span></div>`).join('')}</div></div>`);
  }

  const beauty = beautifyPayload(pkt.raw && pkt.raw.length ? decodeStreamText(extractPayload(pkt.raw) || []) : '');
  if (beauty) {
    nodes.push(`<div class="tnode tnode-beauty"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">✨ Payload (${beauty.kind}) <span class="tlabel-sub">beautified</span></span></div>` +
      `<div class="tbody jt-root">${beauty.html}</div></div>`);
  }

  if (pkt.explanation) {
    nodes.push(`<div class="tnode tnode-explain"><div class="tnode-head">` +
      `<span class="twist">▾</span><span class="tlabel">ℹ What is this?</span></div>` +
      `<div class="tbody">${esc(pkt.explanation)}</div></div>`);
  }
  return nodes.join('');
}
window.buildDetailTree = buildDetailTree;

export function showDetail(index) {
  const pkt = state.filteredPackets[index];
  if (!pkt) return;
  state.selectedIndex = index;
  state.selectedPacket = pkt;
  $('#view-packets').classList.add('with-detail');
  els.detailTree.innerHTML = buildDetailTree(pkt, index);
  els.hexDump.innerHTML = hexDump(pkt.raw || []);
  els.hexLen.textContent = `${(pkt.raw || []).length} bytes`;
  enrichGeo(pkt);

  if (window.__TAURI__) {
    window.__TAURI__.event.emit("packet-selected", pkt);
  }
}
window.showDetail = showDetail;

export function hideDetail() {
  state.selectedIndex = -1;
  state.selectedPacket = null;
  $('#view-packets').classList.remove('with-detail');
  renderPacketList();
}
window.hideDetail = hideDetail;

export function hexDump(bytes) {
  if (!bytes.length) return '<span class="hx-off">(no data)</span>';
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
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
window.hexDump = hexDump;

export function highlightBytes(start, end) {
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
window.highlightBytes = highlightBytes;
