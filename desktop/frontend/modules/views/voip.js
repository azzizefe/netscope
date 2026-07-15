// netscope Desktop — VoIP and RTP View Module
// Handles VoIP SIP Flow ladders and RTP audio player simulations.

let voipActiveTab = 'log';
let audioCtx = null;
let audioInterval = null;
let audioOsc = null;
let audioGain = null;
let isPlayingAudio = false;

export function closeVoipModal() {
  $('#voip-modal').classList.add('hidden');
  stopVoipAudio();
}
window.closeVoipModal = closeVoipModal;

export function switchVoipTab(tab) {
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
window.switchVoipTab = switchVoipTab;

export function renderVoipFlow() {
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
window.renderVoipFlow = renderVoipFlow;

export function playVoipAudio() {
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
window.playVoipAudio = playVoipAudio;

export function stopVoipAudio() {
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
window.stopVoipAudio = stopVoipAudio;

export function renderVoipPlayer() {
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
window.renderVoipPlayer = renderVoipPlayer;

export function showVoip() {
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
window.showVoip = showVoip;
