// netscope — Wireshark-style display filter (browser mirror of core::filter).
//
// Parses expressions like `ip.addr == 1.2.3.4 && tcp.port == 443`, `dns`,
// `frame.len > 1000` and evaluates them against a frontend packet object
// ({ protocol, src_addr, dst_addr, src_port, dst_port, length }).
//
// `NetscopeFilter.compile(text)` returns { matches(pkt) } on success, or `null`
// when the text isn't valid filter syntax — the caller then falls back to a
// plain substring search, so free-text typing keeps working.
//
// This is intentionally kept in lockstep with crates/core/src/filter.rs; the
// two share the same grammar, field names and semantics.
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

  // TCP flag bit masks (byte 13 of the TCP header).
  const TCP_FLAG_MASK = { tcpFlagFin: 0x01, tcpFlagSyn: 0x02, tcpFlagRst: 0x04, tcpFlagPsh: 0x08, tcpFlagAck: 0x10 };

  // ---- Lexer ----
  const isWordChar = (c) => /[A-Za-z0-9._:-]/.test(c);

  function lex(input) {
    const toks = [];
    let i = 0;
    while (i < input.length) {
      const c = input[i];
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { i++; continue; }
      if (c === '(') { toks.push({ t: '(' }); i++; continue; }
      if (c === ')') { toks.push({ t: ')' }); i++; continue; }
      if (c === '&') { i += input[i + 1] === '&' ? 2 : 1; toks.push({ t: 'and' }); continue; }
      if (c === '|') { i += input[i + 1] === '|' ? 2 : 1; toks.push({ t: 'or' }); continue; }
      if (c === '=') { i += input[i + 1] === '=' ? 2 : 1; toks.push({ t: 'cmp', op: '==' }); continue; }
      if (c === '!') {
        if (input[i + 1] === '=') { toks.push({ t: 'cmp', op: '!=' }); i += 2; }
        else { toks.push({ t: 'not' }); i++; }
        continue;
      }
      if (c === '>') {
        if (input[i + 1] === '=') { toks.push({ t: 'cmp', op: '>=' }); i += 2; }
        else { toks.push({ t: 'cmp', op: '>' }); i++; }
        continue;
      }
      if (c === '<') {
        if (input[i + 1] === '=') { toks.push({ t: 'cmp', op: '<=' }); i += 2; }
        else { toks.push({ t: 'cmp', op: '<' }); i++; }
        continue;
      }
      if (c === '"') {
        let j = i + 1;
        while (j < input.length && input[j] !== '"') j++;
        if (j >= input.length) throw new Error('unterminated string');
        toks.push({ t: 'value', kind: 'text', v: input.slice(i + 1, j) });
        i = j + 1;
        continue;
      }
      if (isWordChar(c)) {
        let j = i;
        while (j < input.length && isWordChar(input[j])) j++;
        toks.push(classifyWord(input.slice(i, j)));
        i = j;
        continue;
      }
      throw new Error(`unexpected character '${c}'`);
    }
    return toks;
  }

  function classifyWord(word) {
    const lower = word.toLowerCase();
    if (lower === 'and') return { t: 'and' };
    if (lower === 'or') return { t: 'or' };
    if (lower === 'not') return { t: 'not' };
    if (lower === 'contains') return { t: 'cmp', op: 'contains' };
    if (/^\d+$/.test(word)) return { t: 'value', kind: 'num', v: Number(word) };
    return { t: 'word', v: word };
  }

  // ---- Parser (precedence: or < and < not < primary) ----
  function parse(input) {
    const toks = lex(input);
    if (toks.length === 0) throw new Error('empty filter');
    const state = { toks, pos: 0 };
    const ast = parseOr(state);
    if (state.pos !== toks.length) throw new Error('trailing tokens');
    return ast;
  }

  const peek = (s) => s.toks[s.pos];

  function parseOr(s) {
    let left = parseAnd(s);
    while (peek(s) && peek(s).t === 'or') { s.pos++; left = { t: 'or', a: left, b: parseAnd(s) }; }
    return left;
  }
  function parseAnd(s) {
    let left = parseNot(s);
    while (peek(s) && peek(s).t === 'and') { s.pos++; left = { t: 'and', a: left, b: parseNot(s) }; }
    return left;
  }
  function parseNot(s) {
    if (peek(s) && peek(s).t === 'not') { s.pos++; return { t: 'not', e: parseNot(s) }; }
    return parsePrimary(s);
  }
  function parsePrimary(s) {
    const tok = s.toks[s.pos++];
    if (!tok) throw new Error('unexpected end of filter');
    if (tok.t === '(') {
      const inner = parseOr(s);
      const close = s.toks[s.pos++];
      if (!close || close.t !== ')') throw new Error("expected ')'");
      return inner;
    }
    if (tok.t === 'word') return parseWord(s, tok.v);
    throw new Error(`unexpected token ${tok.t}`);
  }
  function parseWord(s, word) {
    const nxt = peek(s);
    if (nxt && nxt.t === 'cmp') {
      const field = FIELDS[word.toLowerCase()];
      if (!field) throw new Error(`unknown field '${word}'`);
      s.pos++;
      const value = parseValue(s);
      return { t: 'cmp', field, op: nxt.op, value };
    }
    const lower = word.toLowerCase();
    if (KNOWN_PROTOS.has(lower)) return { t: 'proto', name: lower };
    throw new Error(`unknown protocol '${word}'`);
  }
  function parseValue(s) {
    const tok = s.toks[s.pos++];
    if (!tok) throw new Error('expected a value after operator');
    if (tok.t === 'value') return { kind: tok.kind, v: tok.v };
    if (tok.t === 'word') return { kind: 'text', v: tok.v };
    throw new Error('expected a value after operator');
  }

  // ---- Evaluator ----
  function transportOf(proto) {
    const p = (proto || '').toUpperCase();
    if (['TCP', 'HTTP', 'TLS', 'SSH', 'FTP', 'SMTP', 'IMAP', 'POP3', 'TELNET', 'RDP', 'WEBSOCKET', 'HTTP/2', 'GRPC'].includes(p)) return 'tcp';
    if (['UDP', 'DNS', 'DHCP', 'NTP', 'MDNS', 'SNMP', 'QUIC', 'SIP', 'VXLAN'].includes(p)) return 'udp';
    if (p === 'ICMP') return 'icmp';
    if (p === 'ARP') return 'arp';
    return 'other';
  }

  function protoMatches(pkt, name) {
    const transport = transportOf(pkt.protocol);
    switch (name) {
      case 'ip': return !!(pkt.src_addr || pkt.dst_addr);
      case 'ipv4': return isV4(pkt.src_addr) || isV4(pkt.dst_addr);
      case 'ipv6': return isV6(pkt.src_addr) || isV6(pkt.dst_addr);
      case 'tcp': return transport === 'tcp';
      case 'udp': return transport === 'udp';
      case 'icmp': return transport === 'icmp';
      case 'arp': return transport === 'arp';
      case 'wlan': case 'wifi': return pkt.protocol === '802.11';
      case 'ws': return (pkt.protocol || '').toLowerCase() === 'websocket';
      // Display name is "HTTP/2", which never lexes as a bare word.
      case 'http2': return pkt.protocol === 'HTTP/2';
      default: return (pkt.protocol || '').toLowerCase() === name;
    }
  }
  const isV4 = (a) => !!a && a.includes('.') && !a.includes(':');
  const isV6 = (a) => !!a && a.includes(':');

  function evalNode(node, pkt) {
    switch (node.t) {
      case 'or': return evalNode(node.a, pkt) || evalNode(node.b, pkt);
      case 'and': return evalNode(node.a, pkt) && evalNode(node.b, pkt);
      case 'not': return !evalNode(node.e, pkt);
      case 'proto': return protoMatches(pkt, node.name);
      case 'cmp': return evalCmp(pkt, node.field, node.op, node.value);
      default: return false;
    }
  }

  function evalCmp(pkt, field, op, value) {
    switch (field) {
      case 'ipAny': return cmpAddrAny(pkt.src_addr, pkt.dst_addr, op, value);
      case 'ipSrc': return cmpAddrOne(pkt.src_addr, op, value);
      case 'ipDst': return cmpAddrOne(pkt.dst_addr, op, value);
      case 'portAny': return cmpPortAny(pkt, null, op, value);
      case 'tcpPort': return cmpPortAny(pkt, 'tcp', op, value);
      case 'udpPort': return cmpPortAny(pkt, 'udp', op, value);
      case 'frameLen': return cmpNum(pkt.length, op, value);
      case 'tcpFlagSyn': case 'tcpFlagAck': case 'tcpFlagFin': case 'tcpFlagRst': case 'tcpFlagPsh':
        return cmpNum(tcpFlagValue(pkt, TCP_FLAG_MASK[field]), op, value);
      case 'httpMethod': { const r = httpRequestParts(pkt); return cmpText(r && r.method, op, value); }
      case 'httpUri': { const r = httpRequestParts(pkt); return cmpText(r && r.uri, op, value); }
      case 'httpHost': return cmpText(httpHost(pkt), op, value);
      case 'httpRespCode': return cmpNum(httpResponseCode(pkt), op, value);
      case 'dnsQryName': return cmpText(dnsQryName(pkt), op, value);
      case 'info': return cmpText(pkt.summary, op, value);
      default: return false;
    }
  }

  // ---- Frame-derived fields (mirrors core::filter's frame_meta helpers) ----
  // Walk Ethernet (+ VLAN tags) → IPv4/IPv6 → TCP/UDP over pkt.raw. Packets
  // whose bytes don't reach the requested layer just don't have the field.
  function frameMeta(raw) {
    if (!raw || raw.length < 14) return null;
    let off = 12;
    let et = (raw[off] << 8) | raw[off + 1];
    while (et === 0x8100 || et === 0x88a8 || et === 0x9100) {
      off += 4;
      if (off + 2 > raw.length) return null;
      et = (raw[off] << 8) | raw[off + 1];
    }
    const l3 = off + 2;
    let ipProto, l4;
    if (et === 0x0800) { // IPv4
      if (raw.length < l3 + 20) return null;
      const ihl = (raw[l3] & 0x0f) * 4;
      if (ihl < 20) return null;
      ipProto = raw[l3 + 9];
      l4 = l3 + ihl;
    } else if (et === 0x86dd) { // IPv6 fixed header (extension headers not walked)
      if (raw.length < l3 + 40) return null;
      ipProto = raw[l3 + 6];
      l4 = l3 + 40;
    } else {
      return null;
    }
    if (ipProto === 6) { // TCP
      if (raw.length < l4 + 20) return null;
      const doff = ((raw[l4 + 12] >> 4) & 0x0f) * 4;
      if (doff < 20) return null;
      return { ipProto, tcpFlags: raw[l4 + 13], payload: raw.slice(Math.min(l4 + doff, raw.length)) };
    }
    if (ipProto === 17) { // UDP
      if (raw.length < l4 + 8) return null;
      return { ipProto, tcpFlags: null, payload: raw.slice(l4 + 8) };
    }
    return { ipProto, tcpFlags: null, payload: [] };
  }

  function tcpFlagValue(pkt, mask) {
    const m = frameMeta(pkt.raw);
    if (!m || m.tcpFlags == null) return null;
    return (m.tcpFlags & mask) !== 0 ? 1 : 0;
  }

  const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE']);

  // First ~2 KiB of the TCP payload as text — enough for the request/status
  // line and headers without decoding large bodies.
  function httpHead(pkt) {
    const m = frameMeta(pkt.raw);
    if (!m || m.ipProto !== 6 || !m.payload.length) return null;
    let s = '';
    const n = Math.min(m.payload.length, 2048);
    for (let i = 0; i < n; i++) s += String.fromCharCode(m.payload[i]);
    return s;
  }

  function httpRequestParts(pkt) {
    const head = httpHead(pkt);
    if (!head) return null;
    const line = head.split(/\r?\n/, 1)[0];
    const parts = line.split(/\s+/);
    if (parts.length < 3 || !parts[2].startsWith('HTTP/') || !HTTP_METHODS.has(parts[0])) return null;
    return { method: parts[0], uri: parts[1] };
  }

  function httpResponseCode(pkt) {
    const head = httpHead(pkt);
    if (!head) return null;
    const parts = head.split(/\r?\n/, 1)[0].split(/\s+/);
    if (!parts[0] || !parts[0].startsWith('HTTP/')) return null;
    const code = Number(parts[1]);
    return Number.isInteger(code) ? code : null;
  }

  function httpHost(pkt) {
    if (!httpRequestParts(pkt)) return null; // Host is a request-side field
    const lines = httpHead(pkt).split(/\r?\n/);
    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') break; // blank line ends the headers
      const m = lines[i].match(/^host:\s*(.*)$/i);
      if (m) return m[1].trim();
    }
    return null;
  }

  // First question name of a DNS/mDNS message, dotted (`example.com`).
  function dnsQryName(pkt) {
    const proto = (pkt.protocol || '').toUpperCase();
    if (proto !== 'DNS' && proto !== 'MDNS') return null;
    const m = frameMeta(pkt.raw);
    if (!m || m.ipProto !== 17) return null;
    const p = m.payload;
    if (p.length < 13) return null;
    if (((p[4] << 8) | p[5]) === 0) return null; // QDCOUNT
    let i = 12, out = '';
    for (;;) {
      const len = p[i];
      if (len == null) return null;
      if (len === 0) break;
      if ((len & 0xc0) !== 0) return null; // compression pointer
      i += 1;
      if (i + len > p.length) return null;
      let label = '';
      for (let j = 0; j < len; j++) label += String.fromCharCode(p[i + j]);
      out += (out ? '.' : '') + label;
      i += len;
      if (out.length > 255) return null;
    }
    return out || null;
  }

  // Case-insensitive text comparison for protocol string fields.
  function cmpText(field, op, value) {
    if (field == null) return false;
    const f = String(field).toLowerCase();
    const v = valueText(value).toLowerCase();
    if (op === '==') return f === v;
    if (op === '!=') return f !== v;
    if (op === 'contains') return f.includes(v);
    return false; // ordering on text is undefined
  }

  const valueText = (value) => String(value.v);

  function cmpAddrOne(addr, op, value) {
    if (!addr) return false;
    if (op === 'contains') return addr.includes(valueText(value));
    const target = valueText(value);
    if (op === '==') return addr === target;
    if (op === '!=') return addr !== target;
    return false; // ordering on addresses is undefined
  }
  function cmpAddrAny(src, dst, op, value) {
    if (op === '!=') return cmpAddrOne(src, '!=', value) && cmpAddrOne(dst, '!=', value);
    return cmpAddrOne(src, op, value) || cmpAddrOne(dst, op, value);
  }
  function cmpPortAny(pkt, wantTransport, op, value) {
    if (wantTransport && transportOf(pkt.protocol) !== wantTransport) return false;
    const src = pkt.src_port;
    const dst = pkt.dst_port;
    if (op === '!=') return cmpNum(src, '!=', value) && cmpNum(dst, '!=', value);
    return cmpNum(src, op, value) || cmpNum(dst, op, value);
  }
  function cmpNum(field, op, value) {
    if (field === null || field === undefined) return false;
    if (op === 'contains') return String(field).includes(valueText(value));
    if (value.kind !== 'num') return false;
    const v = value.v;
    switch (op) {
      case '==': return field === v;
      case '!=': return field !== v;
      case '>': return field > v;
      case '<': return field < v;
      case '>=': return field >= v;
      case '<=': return field <= v;
      default: return false;
    }
  }

  function compile(input) {
    try {
      const ast = parse(input);
      return { matches: (pkt) => evalNode(ast, pkt) };
    } catch {
      return null;
    }
  }

  // ---- Autocomplete (ROADMAP §6.2) ----
  // Suggests field names, operators and values for the token at the end of the
  // input, using the same field/protocol tables the evaluator does so the
  // completions can only ever produce valid filters.
  const OPERATORS = ['==', '!=', '>', '<', '>=', '<=', 'contains'];
  const BOOLEANS = ['&&', '||', 'and', 'or', 'not'];

  // A few sensible values per field kind — enough to complete the common cases
  // without pretending to know every possible value.
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

  // Returns `{ start, items }` where `start` is the index in `text` where the
  // active token begins and `items` is `[{ value, kind }]`. `kind` is one of
  // 'field' | 'protocol' | 'operator' | 'value', for display + styling.
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
      // A field is complete — offer operators next.
      items = take(OPERATORS, 'operator');
    } else if (isOperator(ctx)) {
      // An operator is complete — offer values for the field before it.
      const field = completed[completed.length - 2] || '';
      items = take(valuesFor(field), 'value');
    } else {
      // Start of a term. After a complete predicate the grammar wants a boolean
      // next, so lead with those; otherwise offer field names + protocols.
      const boolLike = (w) => BOOLEANS.includes(w.toLowerCase()) || w === '(';
      const bools = completed.length && !boolLike(ctx) ? take(BOOLEANS, 'operator') : [];
      const fields = take(Object.keys(FIELDS), 'field');
      const protos = take([...KNOWN_PROTOS], 'protocol');
      items = [...bools, ...fields, ...protos];
    }
    // De-duplicate by value, keep order, cap the list.
    const seen = new Set();
    items = items.filter((it) => (seen.has(it.value) ? false : seen.add(it.value))).slice(0, 12);
    return { start, items };
  }

  return { compile, suggest };
})();

// Expose on the global object so a separate classic script (app.js) and the
// Node vm test harness can both reach it — a top-level `const` alone isn't a
// property of the global object.
if (typeof globalThis !== 'undefined') {
  globalThis.NetscopeFilter = NetscopeFilter;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NetscopeFilter;
}
