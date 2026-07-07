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
    'wlan', 'wifi', '802.11',
  ]);

  const FIELDS = {
    'ip.addr': 'ipAny', 'ip.address': 'ipAny',
    'ip.src': 'ipSrc', 'ip.srcaddr': 'ipSrc',
    'ip.dst': 'ipDst', 'ip.dstaddr': 'ipDst',
    'port': 'portAny', 'tcp.port': 'tcpPort', 'udp.port': 'udpPort',
    'frame.len': 'frameLen', 'len': 'frameLen', 'length': 'frameLen',
  };

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
    if (['TCP', 'HTTP', 'TLS', 'SSH', 'FTP', 'SMTP', 'IMAP', 'POP3', 'TELNET', 'RDP'].includes(p)) return 'tcp';
    if (['UDP', 'DNS', 'DHCP', 'NTP', 'MDNS', 'SNMP', 'QUIC', 'SIP'].includes(p)) return 'udp';
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
      default: return false;
    }
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

  return { compile };
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
