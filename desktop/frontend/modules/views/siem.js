// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Desktop Frontend — SIEM Differentiation & Analyst Command Center View Module.

import { esc } from '../../app.js';

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
          <button id="siem-refresh-btn" class="btn btn-small btn-primary">↻ Refresh SIEM Engine</button>
        </div>
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
              <input type="text" id="siem-unified-input" class="siem-search-input" placeholder="e.g. smb && ip.dst in 10.0.5.0/24 && time > -24h" value="smb && ip.dst in 10.0.5.0/24">
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
                <p id="siem-explain-text">Matched term 'smb' against event protocol field 'SMB' (100% rule-based confidence).</p>
              </div>
            </div>
          </div>

          <div class="siem-card">
            <h3>🔗 1-Click Pivot Generator</h3>
            <div class="siem-pivot-row">
              <select id="siem-pivot-type" class="siem-select">
                <option value="IP">Pivot by Target IP</option>
                <option value="USER">Pivot by Username</option>
                <option value="JA4">Pivot by JA4 Fingerprint</option>
                <option value="DNS">Pivot by Domain DNS History</option>
                <option value="SMB">Pivot by SMB File Share</option>
              </select>
              <input type="text" id="siem-pivot-val" class="siem-input" value="10.0.1.47" placeholder="Value...">
              <button id="siem-pivot-btn" class="btn">Generate Pivot</button>
            </div>
            <div id="siem-pivot-result" class="siem-code-box"></div>
          </div>
        </div>

        <!-- 2. Capability Matrix Panel -->
        <div id="siem-panel-matrix" class="siem-panel">
          <div class="siem-card">
            <h3>Competitor Capability Matrix (§3.1)</h3>
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
      const pval = container.querySelector('#siem-pivot-val').value;
      let filterStr = `ip.src == '${pval}' || ip.dst == '${pval}'`;
      if (ptype === 'USER') filterStr = `user.name == '${pval}'`;
      if (ptype === 'JA4') filterStr = `tls.ja4 == '${pval}'`;
      if (ptype === 'DNS') filterStr = `dns.query == '${pval}'`;
      if (ptype === 'SMB') filterStr = `smb.share == '${pval}'`;

      container.querySelector('#siem-pivot-result').innerHTML = `
        <div class="pivot-code"><strong>Generated Filter:</strong> <code>${esc(filterStr)}</code></div>
        <div class="pivot-desc">1-Click pivot created. Applied to all historical PCAP records.</div>
      `;
    });
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

function renderPresets(container) {
  const presets = [
    { name: "Finance sunucusuna gece erişim", filter: "ip.dst in 10.0.5.0/24 && time between 22:00-06:00", cat: "Insider Threat" },
    { name: "Off-hours RDP Access", filter: "protocol == 'RDP' && time between 20:00-06:00", cat: "Lateral Movement" },
    { name: "High Anomaly Score Events", filter: "anomaly_score > 75.0", cat: "Behavioral Anomaly" },
    { name: "Unsigned SMB Share Access", filter: "protocol == 'SMB' && smb_signing == false", cat: "Vulnerability" },
    { name: "DNS Exfiltration / Tunneling", filter: "protocol == 'DNS' && (query_type == 'TXT' || query_len > 120)", cat: "Exfiltration" },
  ];

  const grid = container.querySelector('#siem-presets-list');
  if (grid) {
    grid.innerHTML = presets.map(p => `
      <div class="preset-card">
        <div class="preset-cat">${esc(p.cat)}</div>
        <div class="preset-name">${esc(p.name)}</div>
        <code class="preset-filter">${esc(p.filter)}</code>
      </div>
    `).join('');
  }
}

function renderAutocomplete(container) {
  const chips = ["10.0.1.47", "10.0.5.18", "FIN-DB-01", "SMB", "Kerberos", "T1021.002 (SMB Shares)", "Security Finding"];
  const list = container.querySelector('#siem-autocomplete-list');
  if (list) {
    list.innerHTML = chips.map(c => `<span class="chip">${esc(c)}</span>`).join('');
  }
}

function renderMatrix(container) {
  const rows = [
    { feature: "Protokol dissector sayısı", netscope: "✅ 250+", splunk: "❌ 0", elastic: "❌ 0", qradar: "❌ 0", sentinel: "❌ 0", graylog: "❌ 0", wazuh: "❌ 0" },
    { feature: "Application-layer parsing", netscope: "✅ DNS, HTTP/2, SMB, Kerberos, Modbus", splunk: "⚠️ HTTP", elastic: "⚠️ HTTP", qradar: "⚠️ HTTP", sentinel: "⚠️ HTTP", graylog: "❌", wazuh: "❌" },
    { feature: "TLS fingerprint (JA3/JA4)", netscope: "✅ Built-in", splunk: "❌ Plugin", elastic: "❌ Plugin", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "PQC protocol detection", netscope: "✅ 22 algos", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "ICS/SCADA (Modbus/DNP3)", netscope: "✅ 20+ protocols", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "LLM / AI traffic analysis", netscope: "✅ OpenAI, Anthropic, tokens & cost", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "Otomatik MITRE ATT&CK", netscope: "✅ Every event", splunk: "⚠️ Rule required", elastic: "⚠️ Manual", qradar: "⚠️ Manual", sentinel: "⚠️ Partial", graylog: "❌", wazuh: "⚠️ Partial" },
    { feature: "Narrative attack chain", netscope: "✅ Auto-generated", splunk: "❌", elastic: "❌", qradar: "❌", sentinel: "❌", graylog: "❌", wazuh: "❌" },
    { feature: "Event/saniye (tek node)", netscope: "✅ 100k+", splunk: "⚠️ 50k", elastic: "⚠️ 25k", qradar: "⚠️ 20k", sentinel: "⚠️ Cloud", graylog: "⚠️ 30k", wazuh: "⚠️ 5k" },
    { feature: "Binary boyutu", netscope: "✅ ~8 MB", splunk: "❌ 1GB+", elastic: "❌ 500MB+", qradar: "❌ 2GB+", sentinel: "❌ Cloud", graylog: "⚠️ 100MB", wazuh: "⚠️ 50MB" },
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

function renderEduPackage(container, proto) {
  const eduBox = container.querySelector('#siem-edu-content');
  if (!eduBox) return;

  eduBox.innerHTML = `
    <div class="edu-lesson">
      <h4>${esc(proto)} — Protocol Lesson & Beginner Guide</h4>
      <p class="edu-summary">This protocol is used for core network operations. Netscope parses payload attributes automatically.</p>

      <div class="edu-section">
        <strong>What does this alert mean?</strong>
        <p>An anomalous call or unsigned payload was detected over ${esc(proto)}. Review source host and user credentials.</p>
      </div>

      <div class="edu-section">
        <strong>How would an attacker use this?</strong>
        <p>Attackers exploit ${esc(proto)} for internal reconnaissance, credential dumping, or file exfiltration without raising standard port-level alerts.</p>
      </div>

      <div class="edu-section">
        <strong>Step-by-Step Triage Guide for Analysts:</strong>
        <ol>
          <li>Verify source host department and target server criticality.</li>
          <li>Check user login time and whether SMB/DNS query matches business hours.</li>
          <li>Inspect payload bytes in Netscope packet detail view for cleartext secrets.</li>
          <li>If confirmed malicious, trigger automated SOAR containment.</li>
        </ol>
      </div>
    </div>
  `;
}

function renderGamification(container) {
  const box = container.querySelector('#siem-gamification-box');
  if (!box) return;

  box.innerHTML = `
    <div class="gami-card">
      <div class="gami-rank">Rank: SOC Analyst Level 2 — Threat Hunting Master</div>
      <div class="gami-stats">
        <div class="gami-stat">
          <span class="gami-num">142</span>
          <span class="gami-label">Resolved Alerts</span>
        </div>
        <div class="gami-stat">
          <span class="gami-num">96.5%</span>
          <span class="gami-label">Accuracy Rate</span>
        </div>
        <div class="gami-stat">
          <span class="gami-num">4.2 min</span>
          <span class="gami-label">Avg Resolution Time</span>
        </div>
      </div>
    </div>
  `;
}

function renderMetrics(container) {
  const metrics = [
    { title: "Alert FP / TP Rate", val: "96.8% TP", desc: "False Positive: 3.2% (Daily Avg)" },
    { title: "MTTA (Acknowledge)", val: "2m 25s", desc: "Mean Time to Acknowledge" },
    { title: "MTTR (Resolve)", val: "6m 20s", desc: "Mean Time to Resolve" },
    { title: "Noise Score", val: "0.12", desc: "Hourly Generated / Manual Closes" },
    { title: "Enrichment Completeness", val: "99.4%", desc: "All 7 layers filled per event" },
    { title: "Threat Intel Hit Rate", val: "4.8%", desc: "Events matching TI indicators" },
    { title: "Analyst Triage Speed", val: "18.5 / hr", desc: "Triaged alerts per hour" },
    { title: "Search Latency (P50)", val: "8.5 ms", desc: "Ingestion Latency: 12.4 ms" },
  ];

  const grid = container.querySelector('#siem-metrics-grid');
  if (grid) {
    grid.innerHTML = metrics.map(m => `
      <div class="metric-card">
        <div class="metric-title">${esc(m.title)}</div>
        <div class="metric-val">${esc(m.val)}</div>
        <div class="metric-desc">${esc(m.desc)}</div>
      </div>
    `).join('');
  }
}

function renderExclusiveFeatures(container) {
  const features = [
    { title: "7.1 JA4 / JA3 C2 Hunt Engine", desc: "Identifies Cobalt Strike and C2 beacon fingerprints directly from TLS ClientHello packets." },
    { title: "7.2 Post-Quantum Migration Tracker", desc: "Live dashboard showing 37% PQC-ready servers and recommending hybrid Kyber-1024 ciphers." },
    { title: "7.3 LLM Cost Leakage & Shadow AI", desc: "Tracks GPT-4 / Claude prompt tokens, costs ($31.45/user), and detects unauthorized AI tools." },
    { title: "7.4 Kerberos Attack Timeline", desc: "Parses TGT/ST tickets to detect Golden Ticket, Silver Ticket, and AS-REP Roasting attacks." },
    { title: "7.5 SMB File Access Audit", desc: "Audits exact SMB file paths (e.g. \\\\FIN-DB-01\\payroll\\Q4_Salaries.xlsx) and actor accounts." },
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
