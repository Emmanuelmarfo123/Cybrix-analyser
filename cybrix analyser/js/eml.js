/*
 * eml.js — reads a REAL email file (.eml) or a pasted "raw source", entirely in the browser.
 *
 * Plain-English summary:
 *   Every email is stored in a standard text format called MIME. It contains:
 *     - headers  (From, Reply-To, Authentication-Results… the "envelope")
 *     - one or more "parts" (a plain-text version, an HTML version, attachments)
 *   Parts are often encoded (base64, quoted-printable) so they survive email transport.
 *   This file decodes all of that, then builds the text the analyser understands:
 *     headers + readable body + a list of real link destinations + attachment names.
 *
 *   Attachments are NEVER opened or decoded, only their names and types are read.
 *   Nothing here sends data anywhere.
 */
(function (root) {
  'use strict';
  const P = root.PEA;

  // ── Decoding helpers ────────────────────────────────────────────────────────
  function bytesToString(bytes, charset) {
    let cs = (charset || 'utf-8').toLowerCase().replace(/^"|"$/g, '');
    if (cs === 'us-ascii' || cs === 'ascii') cs = 'utf-8';
    try { return new TextDecoder(cs).decode(bytes); } catch (e) { return new TextDecoder('utf-8').decode(bytes); }
  }
  function base64ToBytes(s) {
    const clean = s.replace(/[^A-Za-z0-9+/=]/g, '');
    try { const bin = atob(clean.replace(/=+$/, '').padEnd(Math.ceil(clean.replace(/=+$/, '').length / 4) * 4, '=')); return Uint8Array.from(bin, c => c.charCodeAt(0)); }
    catch (e) { return new Uint8Array(0); }
  }
  function qpToBytes(s) {
    s = s.replace(/=\r?\n/g, ''); // soft line breaks
    const out = [];
    const enc = new TextEncoder();
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '=' && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
      else { const code = c.charCodeAt(0); if (code < 128) out.push(code); else out.push(...enc.encode(c)); }
    }
    return new Uint8Array(out);
  }
  function decodeBody(body, encoding, charset) {
    const enc = (encoding || '').toLowerCase().trim();
    if (enc === 'base64') return bytesToString(base64ToBytes(body), charset);
    if (enc === 'quoted-printable') return bytesToString(qpToBytes(body), charset);
    return body;
  }

  /** "=?UTF-8?B?UGF5UGFs?=" → "PayPal"  (RFC 2047 encoded words in headers) */
  function decodeWords(s) {
    if (!s) return s;
    return s.replace(/(\?=)\s+(=\?)/g, '$1$2').replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, cs, mode, data) => {
      const bytes = mode.toUpperCase() === 'B' ? base64ToBytes(data) : qpToBytes(data.replace(/_/g, ' '));
      return bytesToString(bytes, cs.split('*')[0]);
    });
  }

  /** Read a parameter such as boundary="abc" or filename*=UTF-8''na%C3%AFve.pdf */
  function param(value, name) {
    if (!value) return '';
    const pieces = [];
    const re = new RegExp('(?:^|;)\\s*' + name + '(\\*\\d+)?(\\*)?\\s*=\\s*("(?:[^"\\\\]|\\\\.)*"|[^;]*)', 'gi');
    let m, extended = false;
    while ((m = re.exec(value))) {
      const idx = m[1] ? parseInt(m[1].slice(1), 10) : 0;
      let v = m[3].trim().replace(/^"|"$/g, '').replace(/\\(.)/g, '$1');
      if (m[2]) extended = true;
      pieces[idx] = { v, ext: !!m[2] };
    }
    if (!pieces.length) return '';
    let charset = 'utf-8';
    const joined = pieces.filter(Boolean).map((p, i) => {
      let v = p.v;
      if (p.ext && i === 0 && /^[^']*'[^']*'/.test(v)) { charset = v.split("'")[0] || 'utf-8'; v = v.replace(/^[^']*'[^']*'/, ''); }
      return p.ext ? v : v;
    }).join('');
    if (extended) {
      try { return bytesToString(Uint8Array.from(unescape(joined.replace(/%(?![0-9a-f]{2})/gi, '%25')), c => c.charCodeAt(0)), charset); } catch (e) { return joined; }
    }
    return decodeWords(joined);
  }

  // ── MIME structure ──────────────────────────────────────────────────────────
  /** Headers end at the first empty line; everything after is the body. */
  function splitMessage(raw) {
    if (raw.startsWith('\n')) return { head: '', body: raw.slice(1) };
    const m = raw.match(/\n[ \t]*\n/);
    if (!m) return { head: raw, body: '' };
    return { head: raw.slice(0, m.index), body: raw.slice(m.index + m[0].length) };
  }

  function parseHeaders(head) {
    const list = [];
    for (const line of head.replace(/\n[ \t]+/g, ' ').split('\n')) {
      const m = line.match(/^([!-9;-~]+):\s?(.*)$/);
      if (m) list.push([m[1], m[2].trim()]);
    }
    const get = n => { const f = list.find(h => h[0].toLowerCase() === n.toLowerCase()); return f ? f[1] : ''; };
    const all = n => list.filter(h => h[0].toLowerCase() === n.toLowerCase()).map(h => h[1]);
    return { list, get, all };
  }

  /** Walk one part (or a whole message) and collect text, HTML, attachments and attached emails. */
  function walk(raw, out, depth) {
    if (depth > 12) return;
    const { head, body } = splitMessage(raw);
    const h = parseHeaders(head);
    const ct = h.get('Content-Type') || 'text/plain';
    const type = ct.split(';')[0].trim().toLowerCase();
    const cte = h.get('Content-Transfer-Encoding');
    const cd = h.get('Content-Disposition');
    const filename = param(cd, 'filename') || param(ct, 'name');

    if (type.startsWith('multipart/')) {
      const boundary = param(ct, 'boundary');
      if (!boundary) return;
      const esc = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const parts = body.split(new RegExp('^--' + esc + '(?:--)?[ \\t]*$', 'm')).slice(1, -1);
      for (const p of parts) walk(p.replace(/^\n/, ''), out, depth + 1);
      return;
    }
    if (type === 'message/rfc822') {
      // An email attached to an email: typical when users report phishing "as attachment".
      const inner = decodeBody(body, cte, 'utf-8');
      out.attached.push(inner);
      out.attachments.push({ filename: filename || 'attached-message.eml', type, size: inner.length });
      return;
    }
    // Images (attached or inline) are kept so the app can look for QR codes in them.
    // They are only decoded into pixels on this device; nothing is uploaded.
    if (/^image\/(png|jpe?g|gif|webp|bmp)$/i.test(type) && /base64/i.test(cte || '') && body.length < 6e6 && out.images.length < 12) {
      out.images.push({ name: filename || ('inline image ' + (out.images.length + 1)), type, b64: body.replace(/\s/g, '') });
    }
    const isAttachment = /^attachment/i.test(cd) || (filename && !/^inline/i.test(cd)) || (filename && !type.startsWith('text/'));
    if (isAttachment) {
      const size = /base64/i.test(cte || '') ? Math.round(body.replace(/\s/g, '').length * 3 / 4) : body.length;
      out.attachments.push({ filename: filename || '(unnamed)', type, size });
      // HTML / SVG attachments are read AS TEXT (never opened or run) to see what they contain.
      if ((/^(text\/html|image\/svg\+xml|application\/xhtml)/i.test(type) || /\.(s?html?|xhtml|svg)$/i.test(filename)) && body.length < 3e6)
        out.htmlFiles.push({ name: filename || '(unnamed)', html: decodeBody(body, cte, param(ct, 'charset')) });
      return;
    }
    if (type === 'text/plain') out.text.push(decodeBody(body, cte, param(ct, 'charset')));
    else if (type === 'text/html') out.html.push(decodeBody(body, cte, param(ct, 'charset')));
  }

  /** Does this text look like a complete raw email (e.g. Gmail "Show original" → Copy)? */
  function looksRaw(text) {
    const t = text.replace(/\r\n?/g, '\n').trimStart();
    if (!/^[!-9;-~]+:/.test(t)) return false;
    const head = t.split(/\n\s*\n/)[0];
    return /^mime-version:/im.test(head) || (/^content-type:/im.test(head) && /^(received|delivered-to|dkim-signature|x-received|return-path|message-id):/im.test(head));
  }

  /** Parse a full raw email. Returns header object, decoded bodies and attachments. */
  function parse(raw) {
    raw = raw.replace(/\r\n?/g, '\n').replace(/^\s*From [^\n]*\n/, ''); // drop mbox "From " line
    const { head } = splitMessage(raw);
    const headers = parseHeaders(head);
    const out = { text: [], html: [], attachments: [], attached: [], images: [], htmlFiles: [] };
    walk(raw, out, 0);
    return { headers, ...out };
  }

  const KEEP = ['From', 'Sender', 'Reply-To', 'Return-Path', 'To', 'Cc', 'Subject', 'Date', 'Message-ID', 'Authentication-Results', 'ARC-Authentication-Results', 'Received-SPF', 'X-Originating-IP', 'X-Sender-IP', 'X-Mailer'];

  /**
   * Turn a raw email into the text the analyser reads.
   * If the email has another email attached (a forwarded report), the ATTACHED original is analysed.
   */
  function toAnalyserText(raw) {
    let msg = parse(raw);
    let note = '';
    if (msg.attached.length) {
      const reporter = decodeWords(msg.headers.get('From'));
      msg = parse(msg.attached[0]);
      note = `Analysing the original email attached to a report from ${reporter || 'unknown sender'}.`;
    }
    const lines = [];
    for (const name of KEEP) for (const v of msg.headers.all(name)) lines.push(`${name}: ${decodeWords(v)}`);

    // Body: use BOTH the plain-text and the HTML version. Attackers sometimes put a
    // harmless text in one part and the real lure (or a lying link) in the other.
    const html = msg.html.join('\n');
    const htmlInfo = html ? P.normaliseInput(html) : { text: '', anchors: [] };
    const plain = msg.text.join('\n').trim();
    const norm = l => l.toLowerCase().replace(/\s+/g, ' ').trim();
    let body = plain || htmlInfo.text;
    if (plain && htmlInfo.text) {
      const known = new Set(plain.split('\n').map(norm));
      const extra = htmlInfo.text.split('\n').filter(l => norm(l) && !known.has(norm(l)));
      if (extra.length) body += '\n\n--- Only in the HTML version of this email ---\n' + extra.join('\n');
    }

    // Real link destinations, written as  link text <destination>, so the analyser can
    // spot link text that lies about where it goes.
    const seen = new Set();
    const linkLines = [], scriptLines = [];
    const addLinks = anchors => {
      for (const a of anchors) {
        if (seen.has(a.href + '|' + a.text)) continue;
        seen.add(a.href + '|' + a.text);
        if (/^(javascript|data|vbscript):/i.test(a.href)) scriptLines.push(`[HTML script link] → ${a.href.slice(0, 80)}`);
        else if (/^https?:/i.test(a.href)) linkLines.push(`${(a.text || '[image or empty link]').replace(/[<>]/g, '').slice(0, 120)} <${a.href}>`);
      }
    };
    addLinks(htmlInfo.anchors);
    let text = lines.join('\n') + '\n\n' + body.trim();
    if (linkLines.length) text += '\n\n--- Links in this email (link text <real destination>) ---\n' + linkLines.join('\n');
    if (scriptLines.length) text += '\n' + scriptLines.join('\n');

    // HTML / SVG attachments: read as text only, to find fake login forms and links.
    for (const f of msg.htmlFiles) {
      const info = P.normaliseInput(f.html);
      const before = linkLines.length; const beforeS = scriptLines.length;
      addLinks(info.anchors);
      text += `\n\n--- Inside attachment ${f.name} (read as text, never opened) ---\n` + info.text.slice(0, 3000);
      if (linkLines.length > before) text += '\n' + linkLines.slice(before).join('\n');
      if (scriptLines.length > beforeS) text += '\n' + scriptLines.slice(beforeS).join('\n');
    }
    const files = msg.attachments.map(a => a.filename);
    if (files.length) text += '\n\nAttachments: ' + files.join(', ');

    return {
      text,
      note,
      meta: {
        subject: decodeWords(msg.headers.get('Subject')) || '(no subject)',
        from: decodeWords(msg.headers.get('From')) || '(unknown sender)',
        date: msg.headers.get('Date'),
        attachments: msg.attachments,
        images: msg.images,
        links: linkLines.length,
        hasHtml: !!html,
        hasAuth: !!msg.headers.get('Authentication-Results')
      }
    };
  }

  Object.assign(P, { eml: { parse, looksRaw, toAnalyserText, decodeWords } });
})(typeof window !== 'undefined' ? window : globalThis);
