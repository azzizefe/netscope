// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! Desktop Frontend — SIEM Differentiation & Analyst Command Center View Module.

import { esc, els, state, STATES } from '../../app.js';
import { invoke } from '../api.js';

/** Put a filter in the app's own filter box and show the result.
 *
 * Setting `.value` alone changes nothing — app.js applies the filter from the
 * element's `input` event, so dispatch one rather than reaching into its
 * internals. The tab is clicked for the same reason: `switchView` is not
 * exported, but its button is right there and already wired.
 */
function applyFilter(text) {
  const input = els.filterInput || document.querySelector('#filter-input');
  if (!input) return;
  input.value = text;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  const packetsTab = document.querySelector('.tab[data-view="packets"]');
  if (packetsTab) packetsTab.click();
}

export function renderSiemView(container) {
  if (!container) return;

  container.innerHTML = `
    <div class="siem-dashboard-wrap">
      <!-- Top Banner -->
      <div class="siem-header">
        <div class="siem-title-block">
          <h2>🔬 netscope — Explanatory SIEM & Analyst Command Center</h2>
          <p class="siem-subtitle">"Every SIEM can tell you what happened. netscope tells you why it matters."</p>
        </div>
        <div class="siem-header-actions">
          <button id="siem-refresh-btn" class="btn btn-small btn-primary">↻ Reload</button>
        </div>
      </div>

      <div class="siem-notice">
        <strong>What is live here:</strong> the saved filters, the pivot generator and the
        protocol lessons run against netscope's own filter and education engines — clicking
        one applies it to the packets you captured. The capability matrix and the value-prop
        cards are product claims, not measurements of your network.
      </div>

      <!-- Tab Navigation inside SIEM View -->
      <div class="siem-subtabs">
        <button class="siem-subtab active" data-siem-subtab="command-center">🎯 Analyst Command Center</button>
        <button class="siem-subtab" data-siem-subtab="matrix">📊 Capability Matrix</button>
        <button class="siem-subtab" data-siem-subtab="usps">💎 6 Unique Value Props</button>
        <button class="siem-subtab" data-siem-subtab="education">🎓 Built-in Education & Triage</button>
        <button class="siem-subtab" data-siem-subtab="metrics">📈 Quality & Effectiveness Metrics</button>
        <button class="siem-subtab" data-siem-subtab="exclusive">⚡ 10 Exclusive Features</button>
      </div>

      <!-- Subtab Panels -->
      <div class="siem-subcontent">
        <!-- 1. Analyst Command Center Panel -->
        <div id="siem-panel-command-center" class="siem-panel active">
          <div class="siem-card">
            <h3>Unified Search & Query Bar</h3>
            <div class="siem-search-row">
              <input type="text" id="siem-unified-input" class="siem-search-input" placeholder='e.g. smb && ip.addr == 10.0.5.18' value="">
              <button id="siem-search-btn" class="btn btn-primary">🔍 Search</button>
            </div>
            <div id="siem-autocomplete-list" class="siem-autocomplete-chips"></div>
          </div>

          <div class="siem-grid-2">
            <div class="siem-card">
              <h3>⚡ Saved Filter Templates (Presets)</h3>
              <div id="siem-presets-list" class="siem-presets-grid"></div>
            </div>
            <div class="siem-card">
              <h3>🔍 Search Result Match Explanation</h3>
              <div id="siem-explain-box" class="siem-explain-card">
                <div class="explain-title">Rule-based Match Verification</div>
                <p id="siem-explain-text">Run a search to see how it was interpreted.</p>
              </div>
            </div>
          </div>

          <div class="siem-card">
            <h3>🔗 1-Click Pivot Generator</h3>
            <div class="siem-pivot-row">
              <select id="siem-pivot-type" class="siem-select">
                <option value="IP">Pivot by IP (ip.addr)</option>
                <option value="USER">Pivot by NTLM user (ntlm.user)</option>
                <option value="JA4">Pivot by JA4 fingerprint (ja4)</option>
                <option value="DNS">Pivot by queried domain (dns.qry.name)</option>
                <option value="SNI">Pivot by TLS SNI host (tls.sni)</option>
              </select>
              <input type="text" id="siem-pivot-val" class="siem-input" value="" placeholder="e.g. 192.168.1.10">
              <button id="siem-pivot-btn" class="btn">Apply pivot</button>
            </div>
            <div id="siem-pivot-result" class="siem-code-box"></div>
          </div>
        </div>

        <!-- 2. Capability Matrix Panel -->
        <div id="siem-panel-matrix" class="siem-panel">
          <div class="siem-card">
            <h3>Competitor Capability Matrix (§3.1)</h3>
            <p class="siem-nodata">
              netscope's column describes this codebase. The other columns are a
              feature-presence reading of each product's public documentation, not a
              benchmark run here — cells we cannot substantiate are left as “—”.
            </p>
            <div class="siem-table-wrap">
              <table class="siem-table">
                <thead>
                  <tr>
                    <th>Capability / Feature</th>
                    <th>netscope</th>
                    <th>Splunk ES</th>
                    <th>Elastic Sec</th>
                    <th>QRadar</th>
                    <th>Sentinel</th>
                    <th>Graylog</th>
                    <th>Wazuh</th>
                  </tr>
                </thead>
                <tbody id="siem-matrix-body">
                  <!-- Filled via JS -->
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- 3. USPs Panel -->
        <div id="siem-panel-usps" class="siem-panel">
          <div id="siem-usps-grid" class="siem-grid-3"></div>
        </div>

        <!-- 4. Education & Triage Panel -->
        <div id="siem-panel-education" class="siem-panel">
          <div class="siem-grid-2">
            <div class="siem-card">
              <h3>Protocol Education & Exploit Scenario Generator</h3>
              <div class="siem-form-row">
                <select id="siem-edu-proto" class="siem-select">
                  <option value="SMB">SMB (Server Message Block)</option>
                  <option value="DNS">DNS (Domain Name System)</option>
                  <option value="HTTP">HTTP / HTTPS</option>
                  <option value="TLS">TLS 1.3 / Post-Quantum</option>
                  <option value="TCP">TCP / Handshake</option>
                </select>
                <button id="siem-edu-load-btn" class="btn btn-primary">Load Education Package</button>
              </div>
              <div id="siem-edu-content" class="siem-edu-card"></div>
            </div>

            <div class="siem-card">
              <h3>🏆 Analyst Gamification & Triage Performance</h3>
              <div id="siem-gamification-box"></div>
            </div>
          </div>
        </div>

        <!-- 5. Quality & Metrics Panel -->
        <div id="siem-panel-metrics" class="siem-panel">
          <div id="siem-metrics-grid" class="siem-grid-4"></div>
        </div>

        <!-- 6. Exclusive 10 Features Panel -->
        <div id="siem-panel-exclusive" class="siem-panel">
          <div id="siem-exclusive-grid" class="siem-grid-2"></div>
        </div>
      </div>
    </div>
  `;

  bindEvents(container);
  loadData();
}

function bindEvents(container) {
  // Subtab switching
  const tabs = container.querySelectorAll('.siem-subtab');
  tabs.forEach(t => {
    t.addEventListener('click', () => {
      tabs.forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      const target = t.dataset.siemSubtab;
      container.querySelectorAll('.siem-panel').forEach(p => p.classList.remove('active'));
      const activePanel = container.querySelector(`#siem-panel-${target}`);
      if (activePanel) activePanel.classList.add('active');
    });
  });

  // Pivot Button
  const pivotBtn = container.querySelector('#siem-pivot-btn');
  if (pivotBtn) {
    pivotBtn.addEventListener('click', () => {
      const ptype = container.querySelector('#siem-pivot-type').value;
      const pval = container.querySelector('#siem-pivot-val').value.trim();
      if (!pval) return;
      // Field names and quoting must match the real filter grammar. This built
      // `ip.src == '10.0.1.47'` with single quotes, which the lexer rejects
      // outright, and referenced `user.name`, `dns.query` and `smb.share` —
      // none of which exist as fields. Every pivot it produced failed to parse.
      const q = `"${pval.replace(/"/g, '')}"`;
      let filterStr = `ip.addr == ${pval}`;
      if (ptype === 'USER') filterStr = `ntlm.user == ${q}`;
      if (ptype === 'JA4') filterStr = `ja4 == ${q}`;
      if (ptype === 'DNS') filterStr = `dns.qry.name contains ${q}`;
      if (ptype === 'SNI') filterStr = `tls.sni contains ${q}`;

      container.querySelector('#siem-pivot-result').innerHTML = `
        <div class="pivot-code"><strong>Filter:</strong> <code>${esc(filterStr)}</code></div>
        <div class="pivot-desc">Applied to the packets in this session.</div>
      `;
      applyFilter(filterStr);
    });
  }

  // Search — this button had no listener at all, so it did nothing when
  // clicked. It now runs the query through the same filter the packet list
  // uses, and reports a syntax error instead of implying a match.
  const searchBtn = container.querySelector('#siem-search-btn');
  const searchInput = container.querySelector('#siem-unified-input');
  const explain = container.querySelector('#siem-explain-text');
  const runSearch = () => {
    const q = (searchInput?.value || '').trim();
    if (!q) return;
    applyFilter(q);
    if (explain) {
      const matched = state.filteredPackets ? state.filteredPackets.length : 0;
      explain.textContent = `Applied "${q}" to the packet list — ${matched} of ${state.packets.length} packets match. `
        + 'Anything the filter grammar does not recognise falls back to a plain substring search.';
    }
  };
  if (searchBtn) searchBtn.addEventListener('click', runSearch);
  if (searchInput) {
    searchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(); });
  }

  // Load Edu button
  const eduBtn = container.querySelector('#siem-edu-load-btn');
  if (eduBtn) {
    eduBtn.addEventListener('click', () => {
      const proto = container.querySelector('#siem-edu-proto').value;
      renderEduPackage(container, proto);
    });
  }

  // Refresh button
  const refreshBtn = container.querySelector('#siem-refresh-btn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadData);
  }
}

function loadData() {
  const container = document.querySelector('#view-siem');
  if (!container) return;

  renderPresets(container);
  renderAutocomplete(container);
  renderMatrix(container);
  renderUsps(container);
  renderEduPackage(container, "SMB");
  renderGamification(container);
  renderMetrics(container);
  renderExclusiveFeatures(container);
}

/// Every filter here must parse in netscope's display-filter language.
///
/// The list this replaced was written in a syntax the tool does not have —
/// `ip.dst in 10.0.5.0/24`, `time between 22:00-06:00`, `protocol == 'RDP'`,
/// `anomaly_score > 75.0`, `smb_signing == false`. None of it parses (single
/// quotes are not string delimiters either), so every "saved filter" produced
/// an error when a user tried it. These use real fields, and clicking one runs
/// it. See `filter.rs` for the field list.
function renderPresets(container) {
  const presets = [
    { name: "RDP — lateral movement", filter: 'rdp || tcp.port == 3389', cat: "Lateral Movement" },
    { name: "SMB file share access", filter: 'smb', cat: "Lateral Movement" },
    { name: "Kerberos authentication", filter: 'kerberos', cat: "Credential Access" },
    { name: "Cleartext web traffic", filter: 'http', cat: "Exposure" },
    { name: "Long DNS names (tunneling)", filter: 'dns && frame.len > 200', cat: "Exfiltration" },
    { name: "Connection resets", filter: 'tcp.flags.rst == 1', cat: "Recon / Instability" },
    { name: "Server errors", filter: 'http.response.code >= 500', cat: "Service Health" },
    { name: "NTLM logons", filter: 'ntlm.user contains ""', cat: "Credential Access" },
  ];

  const grid = container.querySelector('#siem-presets-list');
  if (!grid) return;
  grid.innerHTML = presets.map((p, i) => `
    <button class="preset-card" data-preset="${i}" title="Apply this filter">
      <div class="preset-cat">${esc(p.cat)}</div>
      <div class="preset-name">${esc(p.name)}</div>
      <code class="preset-filter">${esc(p.filter)}</code>
    </button>
  `).join('');
  grid.querySelectorAll('.preset-card').forEach((btn) => {
    btn.addEventListener('click', () => applyFilter(presets[Number(btn.dataset.preset)].filter));
  });
}

/** Clickable example queries, in the syntax the filter box really accepts.
 *
 * These were chips reading `10.0.1.47`, `FIN-DB-01`, `T1021.002 (SMB Shares)` —
 * invented hosts from an imaginary network, which look like findings from the
 * reader's own capture.
 */
function renderAutocomplete(container) {
  const examples = ['dns', 'tls', 'http.response.code >= 400', 'tcp.flags.rst == 1', 'ja4 contains "t13d"'];
  const list = container.querySelector('#siem-autocomplete-list');
  if (!list) return;
  list.innerHTML = examples
    .map((c) => `<button class="chip" data-q="${esc(c)}" title="Apply this filter">${esc(c)}</button>`)
    .join('');
  list.querySelectorAll('.chip').forEach((chip) => {
    chip.addEventListener('click', () => applyFilter(chip.dataset.q));
  });
}

function renderMatrix(container) {
  const rows = [
    { feature: "Protokol dissector sayısı", netscope: "✅ 590", splunk: "—", elastic: "—", qradar: "—", sentinel: "—", graylog: "—", wazuh: "—" },
    { feature: "Application-layer parsing", netscope: "✅ DNS, HTTP/2, SMB, Kerberos, Modbus", splunk: "⚠️ HTTP", elastic: "⚠️ HTTP", qradar: "⚠️ HTTP", sentinel: "⚠️ HTTP", graylog: "❌", wazuh: "❌" },
    { feature: "TLS fingerprint (JA3/JA4)", netscope: "✅ Built-in", splunk: "❌ Plugin", elastic: "❌ Plugin", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "PQC protocol detection", netscope: "✅ 22 algos", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "ICS/SCADA (Modbus/DNP3)", netscope: "✅ 20+ protocols", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "LLM / AI traffic analysis", netscope: "✅ OpenAI, Anthropic, tokens & cost", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "Otomatik MITRE ATT&CK", netscope: "✅ Every event", splunk: "⚠️ Rule required", elastic: "⚠️ Manual", qradar: "⚠️ Manual", sentinel: "⚠️ Partial", graylog: "❌", wazuh: "⚠️ Partial" },
    { feature: "Narrative attack chain", netscope: "✅ Auto-generated", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    // Throughput and install-size rows for the other products were invented
    // numbers ("Splunk 50k event/s", "QRadar 2GB+") that nobody here measured.
    // netscope's own figures stay because they are measurable from this repo:
    // the throughput bench and the shipped binary.
    { feature: "Event/saniye (tek node)", netscope: "✅ 100k+ (bench)", splunk: "—", elastic: "—", qradar: "—", sentinel: "—", graylog: "—", wazuh: "—" },
    { feature: "Binary boyutu", netscope: "✅ ~8 MB", splunk: "—", elastic: "—", qradar: "—", sentinel: "—", graylog: "—", wazuh: "—" },
  ];

  const tbody = container.querySelector('#siem-matrix-body');
  if (tbody) {
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td><strong>${esc(r.feature)}</strong></td>
        <td class="col-netscope">${esc(r.netscope)}</td>
        <td>${esc(r.splunk)}</td>
        <td>${esc(r.elastic)}</td>
        <td>${esc(r.qradar)}</td>
        <td>${esc(r.sentinel)}</td>
        <td>${esc(r.graylog)}</td>
        <td>${esc(r.wazuh)}</td>
      </tr>
    `).join('');
  }
}

function renderUsps(container) {
  const usps = [
    { title: "USP 1: Deep Packet Payload Parsing", desc: "Rakipler sadece IP/Port görür. netscope DNS sorgularını, HTTP yollarını, SMB dosya isimlerini ve JA4 fingerprint'lerini paket seviyesinde okur." },
    { title: "USP 2: 'Why This Matters' Explanations", desc: "Sadece ham alert 'Port scan' yerine; ne olduğu, MITRE ATT&CK bağlantısı, iş etkisi ve adım adım çözüm önerisi sunulur." },
    { title: "USP 3: AI / LLM Traffic Intelligence", desc: "OpenAI ve Anthropic trafiğini ayrıştırır. Prompt jetonu, yanıt jetonu, tahmini maliyet ve gecikmeyi canlı hesaplar." },
    { title: "USP 4: Post-Quantum Crypto (PQC) Ready", desc: "Geleceğe hazır: TLS el sıkışmalarında PQC algoritmalarını tespit eder ve TLS 1.2 istemcileri için hibrit şifre önerileri sunar." },
    { title: "USP 5: ICS / SCADA Industrial Visibility", desc: "Modbus TCP, DNP3 ve IEC-104 endüstriyel komut seviyesinde denetim. Sabotaj ve yetkisiz röle müdahalelerini yakalar." },
    { title: "USP 6: Rust-Native Performance", desc: "8 MB binary, 50 MB boşta RAM kullanımı ile ucuz bir mini PC üzerinde 100,000+ event/saniye işleme kapasitesi." },
  ];

  const grid = container.querySelector('#siem-usps-grid');
  if (grid) {
    grid.innerHTML = usps.map(u => `
      <div class="usp-card">
        <h4>${esc(u.title)}</h4>
        <p>${esc(u.desc)}</p>
      </div>
    `).join('');
  }
}

/** Real lessons from `education.rs`, not a template.
 *
 * This used to interpolate the protocol name into fixed paragraphs — "This
 * protocol is used for core network operations", "Attackers exploit SMB/DNS/TLS
 * for internal reconnaissance" — so every protocol produced the same advice and
 * none of it came from the tool. netscope ships 446 written lessons behind the
 * `get_lessons` command the Learn tab already uses; this reads those.
 */
async function renderEduPackage(container, proto) {
  const eduBox = container.querySelector('#siem-edu-content');
  if (!eduBox) return;

  try {
    const lessons = await invoke('get_lessons');
    const l = (lessons || []).find((x) => x.protocol === proto);
    if (!l) {
      eduBox.innerHTML = `<div class="edu-lesson"><p class="edu-summary">No lesson is written for ${esc(proto)} yet.</p></div>`;
      return;
    }
    eduBox.innerHTML = `
      <div class="edu-lesson">
        <h4>${esc(l.title)}</h4>
        <p class="edu-summary">${esc(l.summary)}</p>
        <div class="edu-section">
          <strong>How it works</strong>
          <p>${esc(l.body)}</p>
        </div>
        <div class="edu-section">
          <strong>What to look for in a capture</strong>
          <p>${esc(l.look_for)}</p>
        </div>
      </div>
    `;
  } catch (e) {
    // The backend is the only source for these; say so rather than inventing.
    eduBox.innerHTML = `<div class="edu-lesson"><p class="edu-summary">Lessons unavailable — the backend did not answer.</p></div>`;
    console.error('get_lessons failed', e);
  }
}

function renderGamification(container) {
  const box = container.querySelector('#siem-gamification-box');
  if (!box) return;

  // These read as measurements of the reader's own SOC, and were invented:
  // "142 Resolved Alerts", "96.5% Accuracy", "4.2 min Avg Resolution Time".
  // netscope has no alert lifecycle — nothing acknowledges, assigns or closes
  // an alert — so these are not "not wired up yet", they are not measurable at
  // all. Saying so is more useful than a number that cannot be true.
  box.innerHTML = `
    <div class="gami-card">
      <div class="gami-rank">Not tracked</div>
      <p class="siem-nodata">
        Analyst performance needs an alert lifecycle — acknowledge, assign, resolve —
        and netscope does not have one: it analyses captures, it does not run a case
        queue. Resolution times and accuracy rates would have to come from the SIEM or
        ticketing system you forward alerts to.
      </p>
    </div>
  `;
}

/** Numbers measured from the current session — nothing else.
 *
 * The grid this replaced reported "96.8% TP rate", "MTTA 2m 25s", "MTTR 6m 20s",
 * "Enrichment Completeness 99.4%" and so on, all hardcoded, in a panel titled
 * "Quality & Effectiveness Metrics". A reader would take those for their own
 * SOC's figures. netscope measures packets, not an alert queue, so this shows
 * what it actually knows and says plainly what it cannot know.
 */
function renderMetrics(container) {
  const s = state.stats || {};
  const protos = Object.keys(s.perProtocol || {});
  const bytes = s.totalBytes || 0;
  const mb = bytes / (1024 * 1024);
  const errPct = s.totalPackets ? ((s.errorPackets || 0) / s.totalPackets) * 100 : 0;

  const metrics = [
    { title: "Packets in session", val: (s.totalPackets || 0).toLocaleString(), desc: state.status === STATES.CAPTURING ? "Capturing now" : "Capture idle" },
    { title: "Bytes captured", val: mb >= 1 ? `${mb.toFixed(1)} MB` : `${(bytes / 1024).toFixed(1)} KB`, desc: "Sum of frame lengths" },
    { title: "Protocols seen", val: String(protos.length), desc: "Distinct protocols in this capture" },
    { title: "Flagged packets", val: `${errPct.toFixed(1)}%`, desc: "Resets and malformed frames" },
  ];

  const grid = container.querySelector('#siem-metrics-grid');
  if (!grid) return;
  grid.innerHTML = metrics.map(m => `
    <div class="metric-card">
      <div class="metric-title">${esc(m.title)}</div>
      <div class="metric-val">${esc(m.val)}</div>
      <div class="metric-desc">${esc(m.desc)}</div>
    </div>
  `).join('') + `
    <div class="metric-card metric-card-wide">
      <div class="metric-title">Not measured here</div>
      <p class="siem-nodata">
        Mean time to acknowledge/resolve, false-positive rate and analyst throughput
        describe an alert queue's lifecycle. netscope has no case queue, so it cannot
        produce them — they belong to whatever SIEM or ticketing system you forward
        findings to.
      </p>
    </div>
  `;
}

function renderExclusiveFeatures(container) {
  const features = [
    { title: "7.1 JA4 / JA3 C2 Hunt Engine", desc: "Identifies Cobalt Strike and C2 beacon fingerprints directly from TLS ClientHello packets." },
    { title: "7.2 Post-Quantum Migration Tracker", desc: "Reports which observed TLS servers negotiated post-quantum key exchange, and flags the ones that did not." },
    { title: "7.3 LLM Cost Leakage & Shadow AI", desc: "Identifies traffic to LLM APIs and estimates prompt/response token volume, to surface unsanctioned AI tool use." },
    { title: "7.4 Kerberos Attack Timeline", desc: "Parses TGT/ST tickets to detect Golden Ticket, Silver Ticket, and AS-REP Roasting attacks." },
    { title: "7.5 SMB File Access Audit", desc: "Reads the SMB file paths and account names seen on the wire, so share access can be audited without an endpoint agent." },
    { title: "7.6 DNS Exfiltration Detection", desc: "Detects DNS tunneling via query length (>120B), frequency, and entropy analysis." },
    { title: "7.7 Industrial Sabotage Inspection", desc: "Audits Modbus Write Single Coil (Coil 47 Emergency Stop Motor 3) for unauthorized PLC control." },
    { title: "7.8 TLS Certificate Expiry Predictor", desc: "Proactively alerts 14 days before critical TLS certificates expire." },
    { title: "7.9 Supply Chain & Tracker Risk", desc: "Detects 3rd party trackers from risky regions integrated into internal web apps." },
    { title: "7.10 Encrypted Traffic Analysis (ETA)", desc: "Detects malware in TLS traffic without decryption using packet timing and size distribution." },
  ];

  const grid = container.querySelector('#siem-exclusive-grid');
  if (grid) {
    grid.innerHTML = features.map(f => `
      <div class="exclusive-card">
        <h4>${esc(f.title)}</h4>
        <p>${esc(f.desc)}</p>
      </div>
    `).join('');
  }
}
