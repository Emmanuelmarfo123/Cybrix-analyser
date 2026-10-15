/*
 * homograph.js — Unicode look-alike ("homograph") detection.
 *
 * Plain-English summary:
 *   Some letters from other alphabets look identical to English letters. For example,
 *   the Cyrillic "а" (U+0430) looks exactly like the Latin "a". Attackers register
 *   domains such as "pаypal.com" with one swapped letter. Browsers store these names
 *   in an ASCII form called Punycode ("xn--pypal-4ve.com").
 *
 *   This file:
 *     1. decodes Punycode back to the letters people actually see,
 *     2. finds which alphabet ("script") each letter belongs to,
 *     3. maps look-alike letters to the English letter they imitate (a "skeleton"),
 *     4. and flags names that MIX alphabets or that imitate a known brand.
 *
 *   Important: a domain is NOT suspicious just because it uses non-English letters.
 *   Many languages need them. We only flag mixing and imitation.
 */
(function (root) {
  'use strict';
  const P = root.PEA = root.PEA || {};

  // ── Punycode (RFC 3492) decoder: "xn--pypal-4ve" → "pаypal" ─────────────────
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const output = [];
    let n = 128, i = 0, bias = 72;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
    const adapt = (delta, numPoints, first) => {
      let k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
    };
    const digit = c => c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error('bad punycode');
        const d = digit(input.charCodeAt(idx++));
        if (d >= base) throw new Error('bad punycode');
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      const len = output.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }
  function toUnicodeHost(host) {
    return (host || '').split('.').map(l => {
      if (!/^xn--/i.test(l)) return l;
      try { return punyDecode(l.slice(4).toLowerCase()); } catch (e) { return l; }
    }).join('.');
  }

  // ── Scripts and look-alike letters ─────────────────────────────────────────
  function scriptOf(ch) {
    const c = ch.codePointAt(0);
    if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0xC0 && c <= 0x24F && c !== 0xD7 && c !== 0xF7) || (c >= 0x1E00 && c <= 0x1EFF)) return 'Latin';
    if (c >= 0x400 && c <= 0x52F) return 'Cyrillic';
    if (c >= 0x370 && c <= 0x3FF) return 'Greek';
    if (c >= 0x530 && c <= 0x58F) return 'Armenian';
    if ((c >= 0x30 && c <= 0x39) || c === 0x2D || c === 0x5F) return null; // digits, hyphen, underscore: neutral
    if (c >= 0x13A0 && c <= 0x13FF) return 'Cherokee';
    if (c >= 0x4E00 && c <= 0x9FFF) return 'Han';
    if (c >= 0x600 && c <= 0x6FF) return 'Arabic';
    return 'Other';
  }

  // Letters from other alphabets (and accented Latin) that pass for plain English letters.
  const CONFUSABLE = {
    // Cyrillic
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g', 'ү': 'y', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't', 'в': 'b', 'п': 'n', 'ѡ': 'w', 'ꙇ': 'i', 'ё': 'e', 'ї': 'i',
    // Greek
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'υ': 'u', 'χ': 'x', 'ε': 'e', 'τ': 't', 'ω': 'w', 'η': 'n', 'γ': 'y',
    // Armenian
    'օ': 'o', 'ս': 'u', 'հ': 'h', 'ո': 'n', 'զ': 'q', 'ց': 'g', 'ք': 'p',
    // Latin look-alikes and accents
    'ı': 'i', 'ɩ': 'i', 'ł': 'l', 'ɑ': 'a', 'ß': 'b', 'ø': 'o', 'đ': 'd', 'ħ': 'h',
    'à': 'a', 'á': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'ā': 'a', 'ă': 'a', 'ą': 'a',
    'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e', 'ē': 'e', 'ė': 'e', 'ę': 'e',
    'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i', 'į': 'i',
    'ò': 'o', 'ó': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ō': 'o', 'ő': 'o',
    'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ū': 'u', 'ů': 'u', 'ű': 'u',
    'ñ': 'n', 'ń': 'n', 'ç': 'c', 'ć': 'c', 'č': 'c', 'ý': 'y', 'ÿ': 'y', 'ś': 's', 'š': 's', 'ź': 'z', 'ż': 'z', 'ž': 'z', 'ğ': 'g', 'ĺ': 'l', 'ľ': 'l', 'ŕ': 'r', 'ř': 'r', 'ť': 't', 'ď': 'd'
  };
  const DIGITS = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '$': 's' };

  /** The plain-English letters a word imitates: "pаypa1" → "paypal". */
  function skeleton(word) {
    let s = '';
    for (const ch of word.toLowerCase()) s += CONFUSABLE[ch] || DIGITS[ch] || ch;
    return s.replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  const name = ch => {
    const sc = scriptOf(ch) || 'symbol';
    return `"${ch}" (${sc}, U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')})`;
  };

  /** Describe the look-alike letters in a word, for the explanation shown to the user. */
  function describe(word) {
    const out = [];
    for (const ch of new Set(word)) if (/[^\x00-\x7F]/.test(ch) && CONFUSABLE[ch]) out.push(`${name(ch)} looks like "${CONFUSABLE[ch]}"`);
    return out.slice(0, 4).join('; ');
  }

  function scriptsIn(word) {
    const set = new Set();
    for (const ch of word) { const sc = scriptOf(ch); if (sc) set.add(sc); }
    return set;
  }

  /**
   * Check one host name. Returns { unicode, issues[] }.
   * brands: list of brand keys to compare against (from rules.js BRANDS).
   */
  function hostIssues(host, brands) {
    const unicode = toUnicodeHost(host);
    const issues = [];
    if (unicode === host && !/[^\x00-\x7F]/.test(host)) return { unicode, issues };
    const labels = unicode.split('.');
    let brandHit = null, mixed = null, whole = null;
    for (const label of labels) {
      if (!/[^\x00-\x7F]/.test(label)) continue;
      const sk = skeleton(label);
      const scripts = scriptsIn(label);
      const brand = (brands || []).find(b => b.length >= 4 && (sk === b || sk.split(/[-_]/).includes(b) || (b.length >= 5 && sk.includes(b))));
      if (brand && !brandHit) brandHit = { label, brand };
      if (scripts.size > 1 && !mixed) mixed = { label, scripts: [...scripts] };
      const letters = [...label].filter(ch => scriptOf(ch));
      if (!scripts.has('Latin') && letters.length && letters.every(ch => CONFUSABLE[ch]) && !whole) whole = { label };
    }
    if (brandHit) issues.push({ type: 'homograph-brand', weight: 35, title: 'Look-alike letters imitate a brand (homograph attack)',
      detail: `"${unicode}" is shown with letters from another alphabet so it looks like "${brandHit.brand}". ${describe(brandHit.label)}. Computers store it as "${host}".` });
    else if (mixed) issues.push({ type: 'mixed-script', weight: 25, title: 'Domain mixes letters from different alphabets',
      detail: `"${mixed.label}" mixes ${mixed.scripts.join(' and ')} letters, a classic way to build a look-alike name. ${describe(mixed.label)}. Stored as "${host}".` });
    else if (whole) issues.push({ type: 'whole-script-confusable', weight: 25, title: 'Domain made entirely of look-alike letters',
      detail: `"${whole.label}" uses only foreign letters that all look like English ones ("${skeleton(whole.label)}"). ${describe(whole.label)}.` });
    else issues.push({ type: 'idn', weight: 3, title: 'International domain name',
      detail: `"${host}" is displayed as "${unicode}". International names are normal in many languages and are not suspicious by themselves. Just make sure it is the site you expect.` });
    return { unicode, issues };
  }

  /** Look for look-alike tricks inside the message text itself. */
  function textIssues(text, brands) {
    const issues = [];
    const mixedWords = new Set(), brandWords = new Set();
    for (const m of text.matchAll(/[\p{L}\p{M}0-9]{3,}/gu)) {
      const w = m[0];
      if (!/[^\x00-\x7F]/.test(w)) continue;
      const scripts = scriptsIn(w);
      const sk = skeleton(w);
      if ((brands || []).some(b => b.length >= 4 && sk === b)) brandWords.add(w);
      else if (scripts.size > 1 && [...w].some(ch => CONFUSABLE[ch] && scriptOf(ch) !== 'Latin')) mixedWords.add(w);
    }
    if (brandWords.size) issues.push({ id: 'text-homoglyph-brand', weight: 25, title: 'Brand name written with look-alike letters',
      evidence: [...brandWords].slice(0, 5), explain: `A brand name in the text is spelled with letters from another alphabet (${[...brandWords].map(describe).filter(Boolean).slice(0, 2).join('; ')}). This fools spam filters that search for the real brand name, while looking normal to you.` });
    if (mixedWords.size) issues.push({ id: 'text-mixed-script', weight: 15, title: 'Words mix letters from different alphabets',
      evidence: [...mixedWords].slice(0, 5), explain: 'Some words mix English letters with look-alike letters from other alphabets. Legitimate senders almost never do this; it is used to slip past filters and impersonate brands.' });
    const invisible = (text.match(/[​-‍⁠﻿­]/g) || []).length;
    if (invisible) issues.push({ id: 'invisible-chars', weight: 12, title: 'Hidden invisible characters',
      evidence: [`${invisible} invisible character${invisible === 1 ? '' : 's'} (zero-width space, joiner or soft hyphen)`], explain: 'Invisible characters are inserted between letters to break up words like "password" so that filters cannot match them, while you still read them normally.' });
    const bidi = (text.match(/[‪-‮⁦-⁩]/g) || []).length;
    if (bidi) issues.push({ id: 'bidi-control', weight: 20, title: 'Text-direction control characters',
      evidence: [`${bidi} right-to-left / direction override character${bidi === 1 ? '' : 's'}`], explain: 'Direction-override characters make text display in a different order than it is stored, for example making "exe.pdf" look like "fdp.exe". They have no place in a normal email.' });
    return issues;
  }

  P.homograph = { punyDecode, toUnicodeHost, scriptOf, skeleton, hostIssues, textIssues, describe };
})(typeof window !== 'undefined' ? window : globalThis);
