// netscope — Wireshark-style display filter (WASM-based engine).
//
// Uses the compiled Rust filter engine (crates/core/src/filter.rs) over WebAssembly.

import { WasmFilter, matches_batch } from './wasm/netscope_wasm.js';

const NetscopeFilter = (() => {
  const KNOWN_PROTOS = new Set([
    'ip', 'ipv4', 'ipv6', 'tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'tls',
    'dhcp', 'ntp', 'mdns', 'snmp', 'quic', 'sip',
    'ssh', 'ftp', 'smtp', 'imap', 'pop3', 'telnet', 'rdp',
    'wlan', 'wifi', '802.11', 'websocket', 'ws', 'vxlan', 'http2', 'grpc',
  ]);

  const FIELDS = {
    'ip.addr': 'ipAny', 'ip.address': 'ipAny',
    'ip.src': 'ipSrc', 'ip.srcaddr': 'ipSrc',
    'ip.dst': 'ipDst', 'ip.dstaddr': 'ipDst',
    'port': 'portAny', 'tcp.port': 'tcpPort', 'udp.port': 'udpPort',
    'frame.len': 'frameLen', 'len': 'frameLen', 'length': 'frameLen',
    'tcp.flags.syn': 'tcpFlagSyn', 'tcp.flags.ack': 'tcpFlagAck',
    'tcp.flags.fin': 'tcpFlagFin', 'tcp.flags.rst': 'tcpFlagRst',
    'tcp.flags.reset': 'tcpFlagRst', 'tcp.flags.psh': 'tcpFlagPsh', 'tcp.flags.push': 'tcpFlagPsh',
    'http.request.method': 'httpMethod', 'http.method': 'httpMethod',
    'http.request.uri': 'httpUri', 'http.request.path': 'httpUri', 'http.uri': 'httpUri', 'http.path': 'httpUri',
    'http.host': 'httpHost',
    'http.response.code': 'httpRespCode', 'http.response.status': 'httpRespCode', 'http.status': 'httpRespCode',
    'dns.qry.name': 'dnsQryName', 'dns.query.name': 'dnsQryName', 'dns.name': 'dnsQryName',
    'info': 'info', 'frame.info': 'info', 'summary': 'info',
  };

  function compile(input) {
    try {
      const f = WasmFilter.compile(input);
      if (!f) return null;
      return {
        _wasmFilter: f,
        matches: (pkt) => f.matches(pkt),
      };
    } catch {
      return null;
    }
  }

  function matchesBatch(compiled, packets) {
    if (!compiled || !compiled._wasmFilter) return packets;
    const flags = matches_batch(compiled._wasmFilter, packets);
    return packets.filter((_, idx) => flags[idx] === 1);
  }

  // ---- Autocomplete (ROADMAP §6.2) ----
  const OPERATORS = ['==', '!=', '>', '<', '>=', '<=', 'contains'];
  const BOOLEANS = ['&&', '||', 'and', 'or', 'not'];

  function valuesFor(fieldWord) {
    switch (FIELDS[fieldWord.toLowerCase()]) {
      case 'tcpPort': case 'udpPort': case 'portAny':
        return ['80', '443', '53', '22', '3389', '8080', '123', '3306', '5432'];
      case 'httpMethod': return ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];
      case 'httpRespCode': return ['200', '301', '400', '401', '403', '404', '429', '500', '502', '503'];
      case 'frameLen': return ['0', '60', '100', '500', '1000', '1500'];
      case 'tcpFlagSyn': case 'tcpFlagAck': case 'tcpFlagFin': case 'tcpFlagRst': case 'tcpFlagPsh':
        return ['0', '1'];
      default: return [];
    }
  }

  const isOperator = (w) => OPERATORS.includes(w) || /^(contains)$/i.test(w);
  const isField = (w) => FIELDS[(w || '').toLowerCase()] !== undefined;

  function suggest(text) {
    const endsWithSpace = text === '' || /\s$/.test(text);
    const rawParts = text.split(/\s+/).filter(Boolean);
    const active = endsWithSpace ? '' : (rawParts[rawParts.length - 1] || '');
    const completed = endsWithSpace ? rawParts : rawParts.slice(0, -1);
    const ctx = completed[completed.length - 1] || '';
    const start = text.length - active.length;
    const prefix = active.toLowerCase();
    const take = (arr, kind) => arr
      .filter((v) => v.toLowerCase().startsWith(prefix))
      .slice(0, 10)
      .map((value) => ({ value, kind }));

    let items;
    if (isField(ctx) && (active === '' || isOperator(active) || !isField(active))) {
      items = take(OPERATORS, 'operator');
    } else if (isOperator(ctx)) {
      const field = completed[completed.length - 2] || '';
      items = take(valuesFor(field), 'value');
    } else {
      const boolLike = (w) => BOOLEANS.includes(w.toLowerCase()) || w === '(';
      const bools = completed.length && !boolLike(ctx) ? take(BOOLEANS, 'operator') : [];
      const fields = take(Object.keys(FIELDS), 'field');
      const protos = take([...KNOWN_PROTOS], 'protocol');
      items = [...bools, ...fields, ...protos];
    }
    const seen = new Set();
    items = items.filter((it) => (seen.has(it.value) ? false : seen.add(it.value))).slice(0, 12);
    return { start, items };
  }

  return { compile, matchesBatch, suggest };
})();

if (typeof globalThis !== 'undefined') {
  globalThis.NetscopeFilter = NetscopeFilter;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NetscopeFilter;
}

export default NetscopeFilter;
