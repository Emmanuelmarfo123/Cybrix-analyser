/*
 * app.js — connects the buttons on the page to the analyser and draws the report.
 */
(function () {
  'use strict';
  const P = window.PEA || {};
  const $ = id => document.getElementById(id);

  // ── Start-up check ───────────────────────────────────────────────────────
  // If a file is missing or from an older version, the page cannot work. Instead of
  // failing silently (a dead "Analyse" button), say exactly what is wrong.
  const NEEDED_SCRIPTS = { TEXT_RULES: 'js/rules.js', homograph: 'js/homograph.js', analyse: 'js/analyser.js', whatIf: 'js/guidance.js', EXAMPLES: 'js/content.js', eml: 'js/eml.js', qr: 'js/qr.js', store: 'js/core.js' };
  const NEEDED_IDS = ['qr-file', 'drop-overlay', 'analyse-btn', 'email-input', 'report', 'report-body', 'empty-state', 'mode-email', 'mode-voice', 'voice-tools', 'audio-file', 'audio-player', 'import-zone', 'import-status', 'eml-file', 'input-label', 'example-select', 'clear-btn', 'save-history', 'wipe-btn', 'wipe-status'];
  const missingScripts = [...new Set(Object.entries(NEEDED_SCRIPTS).filter(([k]) => !P[k]).map(([, f]) => f))];
  const missingIds = NEEDED_IDS.filter(id => !$(id));
  if (missingScripts.length || missingIds.length) {
    const box = document.createElement('div');
    box.setAttribute('role', 'alert');
    box.style.cssText = 'margin:16px;padding:14px 16px;border-radius:10px;border:2px solid #f87171;background:#2a0f12;color:#ffe4e6;font:14px/1.5 system-ui,sans-serif';
    const lines = ['The analyser could not start, so the Analyse button will not work.'];
    if (missingScripts.length) lines.push('Missing or failed to load: ' + missingScripts.join(', ') + '. Check these files are uploaded in the js folder and listed in index.html.');
    if (missingIds.length) lines.push('index.html is from a different version (missing page parts: ' + missingIds.join(', ') + '). Upload index.html, css/ and js/ from the SAME download.');
    lines.forEach((t, i) => { const p = document.createElement(i ? 'p' : 'strong'); p.textContent = t; p.style.display = 'block'; p.style.marginTop = i ? '6px' : '0'; box.append(p); });
    document.body.prepend(box);
    console.error('[Analyser] start-up check failed', { missingScripts, missingIds });
    return;
  }
  const { h } = P;
  let mode = 'email';
  let lastReport = null;

  // ── Tabs ─────────────────────────────────────────────────────────────────
  const tabs = [...document.querySelectorAll('.tabs [role=tab]')];
  function showView(name, focus) {
    for (const t of tabs) {
      const on = t.dataset.view === name;
      t.setAttribute('aria-selected', on);
      t.tabIndex = on ? 0 : -1;
      $('view-' + t.dataset.view).hidden = !on;
      if (on && focus) t.focus();
    }
    document.dispatchEvent(new CustomEvent('pea:view', { detail: name }));
    try { history.replaceState(null, '', '#' + name); } catch (e) {}
  }
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => showView(t.dataset.view));
    t.addEventListener('keydown', e => {
      const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (d) showView(tabs[(i + d + tabs.length) % tabs.length].dataset.view, true);
    });
  });
  P.showView = showView;

  // ── Email / Voice mode ───────────────────────────────────────────────────
  function setMode(m) {
    mode = m;
    $('mode-email').setAttribute('aria-checked', m === 'email');
    $('mode-voice').setAttribute('aria-checked', m === 'voice');
    $('voice-tools').hidden = m !== 'voice';
    $('import-zone').hidden = m === 'voice';
    $('analyse-btn').textContent = m === 'voice' ? 'Analyse Call' : 'Analyse Email';
    $('input-label').textContent = m === 'voice'
      ? 'Paste or type what the caller said (transcript)'
      : 'Paste the suspicious email: headers, body, links and attachment names';
    $('email-input').placeholder = m === 'voice'
      ? 'e.g. "Hello, I\'m calling from your bank\'s fraud team. I need you to read me the code we just sent…"'
      : 'Tip: include the From / Reply-To lines and full headers if you have them. You can also paste HTML source.';
  }
  $('mode-email').addEventListener('click', () => setMode('email'));
  $('mode-voice').addEventListener('click', () => setMode('voice'));

  // Audio stays local: URL.createObjectURL makes a temporary in-memory address for the file.
  let audioUrl = null;
  $('audio-file').addEventListener('change', e => {
    const f = e.target.files[0];
    if (!f) return;
    if (audioUrl) URL.revokeObjectURL(audioUrl);
    audioUrl = URL.createObjectURL(f);
    const pl = $('audio-player');
    pl.src = audioUrl; pl.hidden = false;
    P.toast('Loaded ' + f.name + ' (not uploaded)');
  });

  // ── Import a real email (.eml file or pasted raw source) ────────────────
  // FileReader reads the file into memory on THIS device. Nothing is uploaded.
  function importStatus(msg, kind) {
    const el = $('import-status');
    el.textContent = msg; el.className = 'import-status ' + (kind || ''); el.hidden = !msg;
  }
  function importRaw(raw, sourceName) {
    if (!P.eml.looksRaw(raw)) {
      importStatus(`"${sourceName}" doesn't look like a complete email. Make sure you saved or copied the full original message, including its headers.`, 'err');
      return false;
    }
    const conv = P.eml.toAnalyserText(raw);
    const m = conv.meta;
    currentLabel = m.subject;
    setMode('email');
    $('email-input').value = conv.text;
    const att = m.attachments.length ? `${m.attachments.length} attachment${m.attachments.length === 1 ? '' : 's'}` : 'no attachments';
    const imgs = m.images.length ? ` · ${m.images.length} image${m.images.length === 1 ? '' : 's'}` : '';
    importStatus(`Loaded "${m.subject}" from ${m.from} · ${m.links} link${m.links === 1 ? '' : 's'} · ${att}${imgs}${m.hasAuth ? ' · SPF/DKIM/DMARC results found' : ''}.${conv.note ? ' ' + conv.note : ''} Read on this device only.`, 'ok');
    return conv;
  }

  // ── QR codes (quishing) ─────────────────────────────────────────────────
  const QR_HEADER = '--- QR codes found (decoded on this device, never opened) ---';
  function appendQrLines(lines) {
    const box = $('email-input');
    const cur = box.value.replace(/\n*--- QR codes found[\s\S]*$/, '').trimEnd();
    box.value = (cur ? cur + '\n\n' : '') + QR_HEADER + '\n' + lines.join('\n');
  }
  /** Look for QR codes in the images of an imported email, then add what they say. */
  async function scanEmailImages(images) {
    if (!images || !images.length || !P.qr) return;
    const st = $('import-status');
    const before = st.textContent;
    importStatus(before + ` Scanning ${images.length} image${images.length === 1 ? '' : 's'} for QR codes…`, 'ok');
    const res = (await P.qr.scanEmailImages(images)).filter(r => r.data);
    importStatus(before + (res.length ? ` QR codes found: ${res.length} (decoded locally, not opened).` : ' No QR codes in the images.'), 'ok');
    if (res.length) appendQrLines(res.map(r => P.qr.line(r.name, r.data)));
  }
  /** A picture on its own (upload, paste or drop): read any QR code in it and analyse the result. */
  async function scanImageFile(file) {
    showView('analyse');
    if (!P.qr || !P.qr.available()) { importStatus('QR reading is not available in this browser.', 'err'); return; }
    setMode('email');
    importStatus(`Reading "${file.name || 'pasted image'}" for QR codes on this device…`, 'ok');
    try {
      const found = await P.qr.scanBlob(file);
      if (!found.length) { importStatus(`No QR code found in "${file.name || 'pasted image'}". Try a sharper, uncropped image with the whole code visible.`, 'err'); return; }
      appendQrLines(found.map(d => P.qr.line(file.name || 'pasted image', d)));
      importStatus(`QR code decoded from "${file.name || 'pasted image'}": ${found[0].slice(0, 120)}${found.length > 1 ? ` (+${found.length - 1} more)` : ''}. The link was NOT opened.`, 'ok');
      currentLabel = 'QR image: ' + (file.name || 'pasted image');
      run(true);
    } catch (e) {
      importStatus(`Could not read "${file.name || 'image'}" as an image (${e.message}).`, 'err');
    }
  }
  function readFile(f) {
    if (!f) return;
    if (/\.msg$/i.test(f.name)) { importStatus('Outlook .msg files use a closed Microsoft format. Save the email as .eml instead, or paste its Internet headers and text into the box (see "How do I get the email file").', 'err'); return; }
    if (f.size > 25 * 1024 * 1024) { importStatus('That file is larger than 25 MB. Remove big attachments or paste just the headers and text.', 'err'); return; }
    const reader = new FileReader();
    reader.onload = async () => { const conv = importRaw(String(reader.result), f.name); if (conv) { await scanEmailImages(conv.meta.images); run(true); } };
    reader.onerror = () => importStatus('The browser could not read that file.', 'err');
    reader.readAsText(f);
  }
  $('eml-file').addEventListener('change', e => { readFile(e.target.files[0]); e.target.value = ''; });
  $('qr-file').addEventListener('change', e => { const f = e.target.files[0]; if (f) scanImageFile(f); e.target.value = ''; });

  // ── Drag and drop anywhere on the page ───────────────────────────────────
  // Files are routed by type: emails → full email analysis, images → QR reader,
  // HTML files → read as source text. Everything stays on this device.
  function routeFile(f) {
    const name = (f.name || '').toLowerCase();
    showView('analyse');
    if (/^image\//.test(f.type) || /\.(png|jpe?g|gif|webp|bmp)$/.test(name)) return scanImageFile(f);
    if (/\.msg$/.test(name) || /\.(eml|txt|mbox)$/.test(name) || f.type === 'message/rfc822' || f.type === 'text/plain') return readFile(f);
    if (/\.(s?html?|xhtml|svg)$/.test(name) || f.type === 'text/html') {
      const r = new FileReader();
      r.onload = () => { setMode('email'); $('email-input').value = String(r.result); currentLabel = 'HTML file: ' + f.name; importStatus(`Loaded "${f.name}" as HTML source (read as text, never opened).`, 'ok'); run(true); };
      r.readAsText(f);
      return;
    }
    importStatus(`"${f.name}" is not a supported file. Drop an email (.eml), an HTML file or an image with a QR code.`, 'err');
  }
  const overlay = $('drop-overlay');
  let dragDepth = 0;
  const hasFiles = e => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
  window.addEventListener('dragenter', e => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; overlay.hidden = false; });
  window.addEventListener('dragover', e => { if (hasFiles(e)) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; } });
  window.addEventListener('dragleave', e => { if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) overlay.hidden = true; });
  window.addEventListener('drop', e => {
    if (!hasFiles(e)) return;
    e.preventDefault(); dragDepth = 0; overlay.hidden = true;
    const files = [...e.dataTransfer.files];
    if (files.length > 1) P.toast(`Analysing "${files[0].name}". Drop one file at a time.`);
    if (files[0]) routeFile(files[0]);
  });
  // Paste a screenshot of a QR code straight into the message box
  $('email-input').addEventListener('paste', e => {
    const item = [...(e.clipboardData ? e.clipboardData.items : [])].find(i => i.kind === 'file' && /^image\//.test(i.type));
    if (item) { e.preventDefault(); scanImageFile(item.getAsFile()); }
  });

  // ── Examples ─────────────────────────────────────────────────────────────
  const sel = $('example-select');
  for (const ex of P.EXAMPLES) sel.append(h('option', { value: ex.id }, ex.label + (ex.mode === 'voice' ? ' (voice)' : '')));
  let currentLabel = 'Pasted message';
  function loadExample(id) {
    const ex = P.EXAMPLES.find(x => x.id === id);
    if (!ex) return;
    setMode(ex.mode);
    $('email-input').value = ex.text;
    sel.value = '';
    importStatus('');
    currentLabel = ex.label;
    run(false);
  }
  sel.addEventListener('change', () => loadExample(sel.value));
  $('email-input').addEventListener('input', () => { currentLabel = 'Pasted message'; });
  // Hooks used by the sidebar, cards and player bar (shell.js)
  P.loadExample = loadExample;
  P.runAnalysis = () => { showView('analyse'); run(true); };
  P.clearInput = () => $('clear-btn').click();

  $('clear-btn').addEventListener('click', () => {
    $('email-input').value = '';
    importStatus('');
    $('report-body').hidden = true; $('empty-state').hidden = false;
    lastReport = null; P.lastReport = null; P.reportActions = null; currentLabel = 'Pasted message';
    document.dispatchEvent(new CustomEvent('pea:report', { detail: { report: null } }));
    $('email-input').focus();
  });
  $('analyse-btn').addEventListener('click', () => run(true));
  $('email-input').addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run(true); });

  function run(record) {
    let text = $('email-input').value;
    if (!text.trim()) { P.toast('Paste a message first, or pick an example.'); $('email-input').focus(); return; }
    // Pasted raw source (e.g. Gmail "Show original" → Copy)? Decode it first.
    if (mode === 'email' && P.eml.looksRaw(text)) {
      const conv = importRaw(text, 'pasted source');
      if (conv && conv.meta.images.length) { scanEmailImages(conv.meta.images).then(() => run(record)); return; }
      if (conv) text = $('email-input').value;
    }
    let report;
    try { report = P.analyse(text, mode); }
    catch (err) {
      console.error('[Analyser] analysis failed', err);
      P.toast('Analysis failed: ' + err.message + '. Make sure all files come from the same version.');
      return;
    }
    lastReport = report;
    P.lastReport = report; P.lastLabel = currentLabel;
    render(report, !record);
    document.dispatchEvent(new CustomEvent('pea:report', { detail: { report, label: currentLabel } }));
    if (record && $('save-history').checked) {
      P.store.update(s => {
        s.history.push({ t: report.analysedAt, score: report.score, level: report.level, mode: report.mode, ids: report.findings.map(f => f.id), titles: report.findings.filter(f => f.points > 0).map(f => f.title), skills: report.skills });
        if (s.history.length > 500) s.history = s.history.slice(-500);
      });
    }
    if (window.matchMedia('(max-width: 900px)').matches) $('report').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ── Report rendering ─────────────────────────────────────────────────────
  const SEV_COLOR = w => w >= 25 ? 'var(--sev-critical)' : w >= 15 ? 'var(--sev-high)' : w >= 9 ? 'var(--sev-medium)' : 'var(--sev-low)';

  function gauge(score) {
    // A half-circle meter. pathLength=100 lets us draw "score" percent of the arc.
    const arc = 'M 14 84 A 70 70 0 0 1 154 84';
    return h('svg', { class: 'gauge', viewBox: '0 0 168 100', role: 'img', 'aria-label': `Risk score ${score} out of 100` },
      h('path', { d: arc, class: 'g-track', pathLength: 100 }),
      h('path', { d: arc, class: 'g-fill', pathLength: 100, 'stroke-dasharray': `${Math.max(score, 0.5)} 100` }),
      h('text', { x: 84, y: 78, 'text-anchor': 'middle', class: 'g-num' }, String(score)),
      h('text', { x: 84, y: 96, 'text-anchor': 'middle', class: 'g-sub' }, 'RISK / 100'));
  }

  function headline(r) {
    const n = r.findings.filter(f => f.points > 0).length;
    if (r.level === 'Critical') return 'Very likely a phishing attempt';
    if (r.level === 'High') return 'Strong signs of phishing';
    if (r.level === 'Medium') return 'Some warning signs. Verify before acting';
    return n ? 'Few warning signs found' : 'No common warning signs found';
  }

  function annotated(text, spans) {
    // Merge overlapping highlight ranges, then build text + <mark> nodes safely.
    const s = spans.filter(x => x.end > x.start).sort((a, b) => a.start - b.start);
    const merged = [];
    for (const x of s) {
      const last = merged[merged.length - 1];
      if (last && x.start <= last.end) { last.end = Math.max(last.end, x.end); if (!last.titles.includes(x.title)) last.titles.push(x.title); }
      else merged.push({ start: x.start, end: x.end, titles: [x.title] });
    }
    const out = []; let i = 0;
    for (const m of merged) {
      if (m.start > i) out.push(text.slice(i, m.start));
      out.push(h('mark', { title: m.titles.join(' · ') }, text.slice(m.start, m.end)));
      i = m.end;
    }
    out.push(text.slice(i));
    return h('div', { class: 'evidence', tabindex: 0, 'aria-label': 'Message with warning signs highlighted' }, out);
  }

  function findingsCard(r) {
    const groups = ['Patterns', 'Language', 'Hidden', 'Links', 'HTML', 'Attachments', 'Sender'];
    const GROUP_LABEL = { Patterns: 'Attack patterns', Hidden: 'Look-alike & hidden characters', HTML: 'HTML tricks' };
    const counted = r.findings.filter(f => f.points > 0).length;
    const reduced = r.findings.filter(f => f.points < f.weight).length;
    const sum = r.findings.reduce((s, f) => s + f.share, 0);
    const card = h('section', { class: 'card' },
      h('h3', {}, 'Why it is suspicious', h('span', { class: 'count' }, `${counted} warning sign${counted === 1 ? '' : 's'} · ${sum} = risk score ${r.score}`)),
      h('p', { class: 'sub' }, 'Open any item to see the evidence and an explanation. Each number is that sign\'s share of the risk score, and together they add up to exactly ' + r.score + '.'),
      reduced ? h('p', { class: 'score-note' }, `${reduced} signal${reduced === 1 ? ' overlaps' : 's overlap'} with stronger evidence (the same link, file, words or sender), so ${reduced === 1 ? 'it adds' : 'they add'} reduced or zero points instead of being double-counted.`) : null);
    if (!r.findings.length) card.append(h('p', { class: 'empty' }, 'Nothing matched the analyser\'s rules. That does not prove the message is safe.'));
    for (const g of groups) {
      const items = r.findings.filter(f => f.group === g);
      if (!items.length) continue;
      card.append(h('div', { class: 'findings' },
        h('div', { class: 'group-label' }, GROUP_LABEL[g] || g),
        items.map(f => {
          const bar = h('span', { class: 'sev-bar', 'aria-hidden': 'true' });
          bar.style.setProperty('--c', f.points ? SEV_COLOR(f.points) : 'var(--line)');
          const pts = f.points ? '+' + f.share : 'counted above';
          return h('details', { class: 'finding' + (f.points ? '' : ' overlapped') },
            h('summary', {}, bar, h('span', { class: 'f-title' }, f.title, ' ', h('span', { class: 'tag' }, P.SKILLS[f.skill].short)), h('span', { class: 'weight', title: f.note || 'Counted in full' }, pts)),
            h('div', { class: 'finding-body' },
              f.note ? h('p', { class: 'hint' }, f.note) : null,
              h('p', {}, f.explain),
              f.evidence.length ? h('div', { class: 'chips' }, f.evidence.map(e => h('span', { class: 'chip' }, e))) : null));
        })));
    }
    for (const p of r.headers.positives) card.append(h('p', { class: 'positive' }, p));
    return card;
  }

  function linksCard(r) {
    if (!r.urls.length && !r.attachments.length) return null;
    const card = h('section', { class: 'card' }, h('h3', {}, 'Links & attachments', h('span', { class: 'count' }, `${r.urls.length} link${r.urls.length === 1 ? '' : 's'} · ${r.attachments.length} file${r.attachments.length === 1 ? '' : 's'}`)),
      h('p', { class: 'sub' }, 'Links are read as text only. The analyser never visits them.'));
    if (r.urls.length) card.append(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Link'), h('th', {}, 'Real owner'), h('th', {}, 'Verdict'))),
      h('tbody', {}, r.urls.map(u => h('tr', {},
        h('td', { class: 'mono' }, u.raw,
          u.shownAs ? h('div', { class: 'hint' }, 'Shown as: "' + u.shownAs + '"') : null,
          u.unicodeHost ? h('div', { class: 'hint' }, 'Displays as: "' + u.unicodeHost + '"') : null,
          u.nested ? h('div', { class: 'hint' }, 'Forwards to: ' + u.nested) : null),
        h('td', { class: 'mono' }, u.reg || '—'),
        h('td', {}, u.issues.length ? h('span', { class: 'bad' }, u.issues.map(i => i.title).join('; ')) : h('span', { class: 'ok' }, 'No tricks detected'))))))));
    if (r.attachments.length) card.append(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'File name'), h('th', {}, 'Type'), h('th', {}, 'Verdict'))),
      h('tbody', {}, r.attachments.map(a => h('tr', {},
        h('td', { class: 'mono' }, a.name), h('td', { class: 'mono' }, '.' + a.ext),
        h('td', {}, a.issues.length ? h('span', { class: 'bad' }, a.issues.map(i => i.title).join('; ')) : h('span', { class: 'ok' }, 'Common document type'))))))));
    return card;
  }

  function whatIfCard(r) {
    return h('section', { class: 'card' },
      h('h3', {}, 'What happens if you…'),
      h('p', { class: 'sub' }, 'A walk-through of the likely consequences of each action, based on what this message asks for.'),
      h('div', { class: 'whatif' }, P.whatIf(r).map(w => h('article', {},
        h('h4', {}, w.action, h('span', { class: 'sev-tag', 'data-s': w.severity }, w.severity)),
        h('ol', {}, w.steps.map(s => h('li', {}, s)))))));
  }

  function pathCard(r) {
    const stages = P.attackPath(r);
    const list = h('ol', { class: 'path' }, stages.map(s => h('li', {},
      h('div', { class: 'stage-body' },
        h('h4', {}, s.stage),
        h('p', {}, s.what),
        h('div', { class: 'chips' }, s.techniques.map(([id, name]) => h('span', { class: 'chip ttp' }, id, ' ', h('span', {}, name)))),
        h('p', { class: 'detect' }, h('b', {}, 'How defenders spot it: '), s.detect)))));
    let timer = null;
    const btn = h('button', { type: 'button', class: 'btn small', onclick: play }, '▶ Play simulation');
    function play() {
      const items = [...list.children];
      clearInterval(timer);
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { items.forEach(li => li.classList.add('done')); return; }
      items.forEach(li => li.classList.remove('active', 'done'));
      list.classList.add('playing');
      let i = 0;
      const step = () => {
        if (i > 0) { items[i - 1].classList.remove('active'); items[i - 1].classList.add('done'); }
        if (i >= items.length) { clearInterval(timer); list.classList.remove('playing'); btn.textContent = '↻ Replay simulation'; return; }
        items[i].classList.add('active'); i++;
      };
      step(); timer = setInterval(step, 1400);
    }
    return h('section', { class: 'card' },
      h('div', { class: 'row' }, h('h3', {}, 'Attack path simulation'), btn),
      h('p', { class: 'sub' }, 'How this attack would most likely unfold, mapped to MITRE ATT&CK technique IDs used by security teams.'),
      list);
  }

  function actionsCard(r) {
    const a = P.actions(r);
    const panes = {
      now: h('ol', { class: 'steps' }, a.now.map(s => h('li', {}, s))),
      ir: h('div', { class: 'ir-grid' }, a.ir.map(b => h('div', { class: 'ir-block' }, h('h4', {}, b.title), h('ol', { class: 'steps' }, b.steps.map(s => h('li', {}, s)))))),
      soc: h('ol', { class: 'steps' }, a.soc.map(s => h('li', {}, s)))
    };
    const labels = { now: 'What to do now', ir: 'If you already interacted', soc: 'For security analysts' };
    const body = h('div', {});
    const btns = Object.keys(panes).map(k => h('button', { type: 'button', role: 'tab', 'aria-selected': k === 'now', onclick: () => pick(k) }, labels[k]));
    function pick(k) { btns.forEach((b, i) => b.setAttribute('aria-selected', Object.keys(panes)[i] === k)); body.replaceChildren(panes[k]); }
    pick(r.level === 'Low' ? 'now' : 'now');
    return h('section', { class: 'card' }, h('h3', {}, 'Recommended actions & incident response'), h('div', { class: 'action-tabs', role: 'tablist' }, btns), body);
  }

  function iocCard(r) {
    const io = r.iocs;
    const sets = [['URLs', io.urls], ['Domains', io.domains], ['IP addresses', io.ips], ['Email addresses', io.emails], ['Files', io.files], ['Phone numbers', io.phones]].filter(x => x[1].length);
    const lines = sets.flatMap(([k, v]) => [`# ${k}`, ...v.map(x => k === 'Phone numbers' || k === 'Files' ? x : P.defang(x)), '']).join('\n');
    P.reportActions = {
      copyIocs: () => sets.length ? P.copyText(lines, 'IOCs') : P.toast('No suspicious indicators to copy.'),
      download: () => P.download('phishing-report.txt', textReport(r), 'text/plain')
    };
    return h('section', { class: 'card' },
      h('h3', {}, 'Indicators of compromise (IOCs)'),
      h('p', { class: 'sub' }, 'Defanged ("evil[.]com") so they cannot be clicked by accident when you share them with your security team.'),
      sets.length ? h('div', { class: 'ioc-grid' }, sets.map(([k, v]) => h('div', {}, h('h4', {}, k), h('ul', {}, v.map(x => h('li', {}, k === 'Phone numbers' || k === 'Files' ? x : P.defang(x))))))) : h('p', { class: 'empty' }, 'No suspicious indicators extracted.'),
      h('div', { class: 'row' },
        sets.length ? h('button', { type: 'button', class: 'btn small', onclick: () => P.copyText(lines, 'IOCs') }, 'Copy IOCs') : null,
        h('button', { type: 'button', class: 'btn small', onclick: () => P.download('phishing-report.txt', textReport(r), 'text/plain') }, 'Download report (.txt)'),
        h('button', { type: 'button', class: 'btn small', onclick: () => P.copyText(textReport(r), 'Report') }, 'Copy report')));
  }

  function textReport(r) {
    const L = [];
    L.push('PHISHING ANALYSIS REPORT', `Generated: ${new Date(r.analysedAt).toLocaleString()}`, `Type: ${r.mode === 'voice' ? 'Voice call transcript' : 'Email'}`, `Risk: ${r.score}/100 (${r.level})`, '');
    L.push('WARNING SIGNS');
    L.push(`Each sign's share of the risk score is shown in brackets; the shares add up to ${r.score}. Overlapping evidence is not double-counted.`, '');
    r.findings.forEach(f => L.push(`- [${f.points ? '+' + f.share : 'counted above'}] ${f.title}${f.evidence.length ? ' :: ' + f.evidence.map(e => P.defang(e)).join(' | ') : ''}`));
    L.push('', 'ATTACK PATH (MITRE ATT&CK)');
    P.attackPath(r).forEach((s, i) => L.push(`${i + 1}. ${s.stage}: ${s.techniques.map(t => t.join(' ')).join(', ')}`));
    L.push('', 'IOCs (defanged)');
    Object.entries(r.iocs).forEach(([k, v]) => v.length && L.push(`${k}: ${v.map(x => (k === 'phones' || k === 'files') ? x : P.defang(x)).join(', ')}`));
    L.push('', 'Generated locally by Phishing Email Analyser. The message text is not included in this report.');
    return L.join('\n');
  }

  function render(r, isExample) {
    const body = $('report-body');
    const verdict = h('section', { class: 'card verdict', 'data-level': r.level },
      gauge(r.score),
      h('div', { class: 'verdict-text' },
        h('span', { class: 'level-pill' }, r.level + ' risk'),
        h('h2', {}, headline(r)),
        h('div', { class: 'stat-row' },
          h('span', {}, h('b', {}, r.findings.filter(f => f.points > 0).length), ' warning signs'),
          h('span', {}, h('b', {}, r.urls.filter(u => u.issues.length).length), ' / ', r.urls.length, ' links suspicious'),
          r.mode === 'email' ? h('span', {}, h('b', {}, r.attachments.filter(a => a.issues.length).length), ' risky files') : null,
          r.wasHtml ? h('span', {}, 'HTML source detected') : null)));
    const evidence = h('section', { class: 'card' },
      h('h3', {}, 'Evidence in the message'),
      h('p', { class: 'sub' }, 'Highlighted text triggered a rule. Hover or long-press a highlight to see which.'),
      annotated(r.text, r.spans));
    const note = isExample ? h('p', { class: 'sample-banner' }, 'This is a built-in example so you can see a full report. Clear the box and paste your own message to analyse it.') : null;
    body.replaceChildren(...[note, verdict, findingsCard(r), evidence, linksCard(r), whatIfCard(r), pathCard(r), actionsCard(r), iocCard(r)].filter(Boolean));
    $('empty-state').hidden = true;
    body.hidden = false;
  }

  // Open the tab named in the address (e.g. …/#challenge), otherwise start on Analyse.
  const start = (location.hash || '').slice(1);
  if (['home', 'analyse', 'challenge', 'training', 'dashboard', 'about'].includes(start)) setTimeout(() => showView(start), 0);

  // Show a worked example on first load so the page is never empty.
  loadExample(P.EXAMPLES[0].id);

  $('wipe-btn').addEventListener('click', () => {
    P.store.wipe();
    $('wipe-status').textContent = 'All locally stored data deleted.';
  });
})();
