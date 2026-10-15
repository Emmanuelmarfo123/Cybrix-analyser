/*
 * shell.js — the Analyse page extras: summary cards, example cards and header buttons.
 *
 * Plain-English summary:
 *   The analysis itself lives in app.js. This file only decorates it: whenever a new
 *   report is ready, app.js announces it ("pea:report") and this file redraws the
 *   coloured summary cards and the bottom bar. All text is inserted safely with h().
 */
(function () {
  'use strict';
  const P = window.PEA;
  const { h } = P;
  const $ = id => document.getElementById(id);
  const EX = P.EXAMPLES;

  const svg = d => {
    const s = h('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' });
    s.append(h('path', { d }));
    return s;
  };
  const ICONS = {
    mail: 'M3 5h18v14H3V5zm2 2v.5l7 4.7 7-4.7V7H5zm14 2.9-7 4.7-7-4.7V17h14V9.9z',
    phone: 'M6.6 10.8a15 15 0 0 0 6.6 6.6l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1A17 17 0 0 1 3 4c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.3.2 2.5.6 3.6.1.3 0 .7-.2 1l-2.3 2.2z',
    link: 'M10.6 13.4a1 1 0 0 1 0-1.4l3.5-3.5a1 1 0 1 1 1.4 1.4L12 13.4a1 1 0 0 1-1.4 0zM8.5 19a4.5 4.5 0 0 1-3.2-7.7l2.1-2.1 1.4 1.4-2.1 2.1a2.5 2.5 0 0 0 3.5 3.5l2.1-2.1 1.4 1.4-2.1 2.1A4.5 4.5 0 0 1 8.5 19zm8.1-4.3-1.4-1.4 2.1-2.1a2.5 2.5 0 0 0-3.5-3.5l-2.1 2.1-1.4-1.4 2.1-2.1a4.5 4.5 0 0 1 6.4 6.4l-2.2 2z',
    shield: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3zm-1.2 13.6-3.3-3.3 1.4-1.4 1.9 1.9 4.6-4.6 1.4 1.4-6 6z',
    alert: 'M12 2 1 21h22L12 2zm0 4.5L19.5 19h-15L12 6.5zM11 10v4h2v-4h-2zm0 6v2h2v-2h-2z',
    list: 'M3 5h12v2H3V5zm0 4h12v2H3V9zm0 4h8v2H3v-2zm14-2v6.3a2.5 2.5 0 1 0 2 2.4V13h2v-2h-4z'
  };

  // ── "Popular examples": tall abstract cards ──────────────────────────────
  const pop = $('pop-row');
  EX.forEach((ex, i) => pop.append(h('button', { type: 'button', class: 'pop-card art-' + (i % 5 + 1), onclick: () => pick(ex.id), 'aria-label': 'Load example: ' + ex.label },
    h('span', { class: 'pop-label' }, h('b', {}, ex.label), h('span', {}, ex.mode === 'voice' ? 'Voice call' : ex.id === 'legit' ? 'Email · safe example' : 'Email')))));

  function pick(id) {
    P.showView('analyse');
    P.loadExample(id);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // ── Summary cards (the big gradient cards) ───────────────────────────────
  function goTo(heading) {
    const sec = [...document.querySelectorAll('#report-body section h3')].find(x => x.textContent.startsWith(heading));
    if (sec) sec.closest('section').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function gcard(cls, icon, big, title, sub, rows, target) {
    return h('article', { class: 'g-card ' + cls, tabindex: 0, role: 'button', 'aria-label': title + ', open details',
      onclick: () => goTo(target), onkeydown: e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); goTo(target); } } },
      h('div', { class: 'g-art', 'aria-hidden': 'true' }, svg(icon), big ? h('span', { class: 'g-big' }, big) : null),
      h('div', { class: 'g-caption' }, h('b', {}, title), h('span', {}, sub)),
      h('ol', { class: 'g-list' }, rows.slice(0, 6).map((r, i) => h('li', {}, h('span', { class: 'n' }, String(i + 1)), h('span', { class: 't' }, r[0]), h('span', { class: 'd' }, r[1])))));
  }
  function renderHero(r) {
    const row = $('hero-row');
    if (!r) {
      row.replaceChildren(
        gcard('blue', ICONS.alert, '–', 'No analysis yet', 'Paste a message below', [['Paste an email or transcript', ''], ['Or drop an .eml file', ''], ['Or pick an example', '']], 'Why'),
        gcard('violet', ICONS.link, null, 'Links & files', 'Checked without opening', [['Look-alike domains', ''], ['Hidden link targets', ''], ['Risky attachments', '']], 'Links'),
        gcard('cyan', ICONS.shield, null, 'Private by design', 'Nothing leaves this tab', [['No uploads', ''], ['No tracking', ''], ['Works offline', '']], 'Recommended'));
      return;
    }
    const counted = r.findings.filter(f => f.points > 0);
    const bad = r.urls.filter(u => u.issues.length), files = r.attachments.filter(a => a.issues.length);
    const linkRows = [
      ...r.urls.map(u => [u.host || u.raw, u.issues.length ? 'risky' : 'ok']),
      ...r.attachments.map(a => [a.name, a.issues.length ? 'risky' : 'ok'])
    ].sort((a, b) => (a[1] === 'risky' ? 0 : 1) - (b[1] === 'risky' ? 0 : 1));
    const steps = P.actions(r).now.map(s => [s.replace(/\.$/, ''), '']);
    row.replaceChildren(
      gcard('blue', ICONS.alert, String(r.score), r.level + ' risk', `${counted.length} warning signs add up to ${r.score}`,
        counted.length ? counted.map(f => [f.title, '+' + f.share]) : [['No common warning signs found', '']], 'Why'),
      gcard('violet', ICONS.link, null, 'Links & files', `${bad.length} of ${r.urls.length} links risky · ${files.length} risky files`,
        linkRows.length ? linkRows : [['No links or attachments found', '']], 'Links'),
      gcard('cyan', ICONS.shield, null, 'What to do now', r.level === 'Low' ? 'Still verify before acting' : 'Do not click, reply or pay', steps, 'Recommended'));
  }

  // ── Header buttons ───────────────────────────────────────────────────────
  $('head-analyse').addEventListener('click', () => P.runAnalysis());
  const act = name => () => P.reportActions ? P.reportActions[name]() : P.toast('Analyse a message first.');
  $('head-copy').addEventListener('click', act('copyIocs'));
  $('head-download').addEventListener('click', act('download'));

  function update(r) { renderHero(r); }
  document.addEventListener('pea:report', e => update(e.detail.report));
  update(P.lastReport);
})();
