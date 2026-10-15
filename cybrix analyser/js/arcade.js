/*
 * arcade.js — the CYBRIX "Arcade" home page: games, progress, badges, leaderboard.
 *
 * Plain-English summary:
 *   Everything here is calculated from what is already stored in THIS browser
 *   (analysis summaries, challenge answers, training progress, imported team files).
 *   XP, levels and badges are just a friendlier way of showing that progress.
 */
(function () {
  'use strict';
  const P = window.PEA;
  const { h } = P;
  const $ = id => document.getElementById(id);
  const XP_PER_LEVEL = 500;

  // ── XP and level ─────────────────────────────────────────────────────────
  function progress() {
    const s = P.store.get();
    const aw = P.awareness();
    const answers = Object.values(s.challenge.answers);
    const correct = answers.filter(a => a.correct).length;
    const flagsHit = answers.reduce((n, a) => n + a.hit.length, 0);
    const quizzes = Object.values(s.training.quiz);
    const quizRight = quizzes.filter(Boolean).length;
    const analyses = s.history.length;
    const xp = Math.min(analyses, 50) * 10 + correct * 100 + flagsHit * 20 + aw.done * 150 + quizRight * 50;
    const level = 1 + Math.floor(xp / XP_PER_LEVEL);
    return { s, aw, answers, correct, quizzes, quizRight, analyses, xp, level, intoLevel: xp % XP_PER_LEVEL };
  }

  // ── Badges: small achievements, earned from real activity ────────────────
  const BADGES = [
    { id: 'first-scan', name: 'First scan: analysed a message', color: 'orange', icon: 'M11 4a7 7 0 1 0 4.4 12.4l4.3 4.3 1.4-1.4-4.3-4.3A7 7 0 0 0 11 4zm0 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10z', test: p => p.analyses >= 1 },
    { id: 'critical', name: 'Critical catch: analysed a Critical-risk message', color: 'red', icon: 'M12 2c1 4 6 6 6 12a6 6 0 0 1-12 0c0-3 2-5 3-6 0 2 1 3 2 3 0-4 1-6 1-9z', test: p => p.s.history.some(x => x.level === 'Critical') },
    { id: 'eagle', name: 'Eagle eye: 5 correct challenge verdicts', color: 'purple', icon: 'M12 5C6 5 2 12 2 12s4 7 10 7 10-7 10-7-4-7-10-7zm0 3a4 4 0 1 1 0 8 4 4 0 0 1 0-8zm0 2a2 2 0 1 0 0 4 2 2 0 0 0 0-4z', test: p => p.correct >= 5 },
    { id: 'perfect', name: 'Perfect round: all 12 challenge messages correct', color: 'gold', icon: 'M7 3h10v2h4v3a5 5 0 0 1-4.6 5A5 5 0 0 1 13 15.9V18h3v3H8v-3h3v-2.1A5 5 0 0 1 7.6 13 5 5 0 0 1 3 8V5h4V3z', test: p => p.correct >= P.CHALLENGE.length },
    { id: 'voice', name: 'Call screener: analysed a phone call', color: 'green', icon: 'M6.6 10.8a15 15 0 0 0 6.6 6.6l2.2-2.2c.3-.3.7-.4 1-.2 1.1.4 2.3.6 3.6.6.6 0 1 .4 1 1V20c0 .6-.4 1-1 1A17 17 0 0 1 3 4c0-.6.4-1 1-1h3.5c.6 0 1 .4 1 1 0 1.3.2 2.5.6 3.6.1.3 0 .7-.2 1l-2.3 2.2z', test: p => p.s.history.some(x => x.mode === 'voice') },
    { id: 'quiz', name: 'Quiz whiz: 5 lesson quizzes right', color: 'blue', icon: 'm12 2 3 6.5 7 .8-5.2 4.8 1.5 7L12 17.6 5.7 21l1.5-7L2 9.3l7-.8z', test: p => p.quizRight >= 5 },
    { id: 'scholar', name: 'Scholar: all 9 lessons complete', color: 'blue', icon: 'M12 3 1 9l11 6 9-4.9V17h2V9L12 3zM5 13.2V17l7 4 7-4v-3.8l-7 3.8-7-3.8z', test: p => p.aw.done >= p.aw.total },
    { id: 'team', name: 'Team player: team results loaded', color: 'cyan', icon: 'M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm8 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8 13c-3 0-6 1.5-6 4v2h12v-2c0-2.5-3-4-6-4zm8 0c-.6 0-1.2.1-1.8.2A4.9 4.9 0 0 1 16 17v2h6v-2c0-2.5-3-4-6-4z', test: p => p.s.team.length > 0 }
  ];

  const svg = d => { const e = h('svg', { viewBox: '0 0 24 24', 'aria-hidden': 'true' }); e.append(h('path', { d })); return e; };
  const initials = n => n.replace(/\(.*?\)/g, '').trim().split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase() || '?';

  function render() {
    const p = progress();
    const { aw, s } = p;

    // Progress panel
    $('pr-level').textContent = p.level;
    $('ring-fill').setAttribute('stroke-dasharray', `${Math.max(1, Math.round(p.intoLevel / XP_PER_LEVEL * 100))} 100`);
    $('pr-xp').textContent = p.xp.toLocaleString();
    $('pr-xp-next').textContent = '/ ' + (p.level * XP_PER_LEVEL).toLocaleString();
    $('pr-xp-fill').style.width = (p.intoLevel / XP_PER_LEVEL * 100) + '%';
    const earned = BADGES.filter(b => b.test(p));
    $('pr-badge-count').textContent = `${earned.length} / ${BADGES.length}`;
    $('pr-badges').replaceChildren(...BADGES.map(b => {
      const on = b.test(p);
      return h('li', { class: 'badge b-' + b.color + (on ? '' : ' locked'), title: (on ? '' : 'Locked: ') + b.name }, svg(b.icon), h('span', { class: 'visually-hidden' }, (on ? 'Earned: ' : 'Locked: ') + b.name));
    }));
    $('pr-score').textContent = aw.score ?? '–';
    $('pr-grade').textContent = aw.score == null ? 'play a game to get rated' : P.grade(aw.score);

    // Game subtitles
    $('game-sub-challenge').textContent = `${p.answers.length} / ${P.CHALLENGE.length} messages`;
    $('game-sub-training').textContent = `${aw.done} / ${aw.total} lessons`;

    // Stats
    $('st-played').textContent = p.analyses + p.answers.length + p.quizzes.length;
    $('st-won').textContent = p.correct;
    $('st-acc').textContent = aw.accuracy == null ? '–' : Math.round(aw.accuracy * 100) + '%';

    // Leaderboard: team results + you
    const rows = s.team.filter(t => typeof t.score === 'number').map(t => ({ name: t.alias, dept: t.dept, score: t.score }));
    if (aw.score != null) rows.push({ name: (s.profile.alias || 'You'), dept: s.profile.dept || '', score: aw.score, me: true });
    rows.sort((a, b) => b.score - a.score);
    const list = $('lb-list');
    if (!rows.length) {
      list.replaceChildren(h('li', { class: 'lb-empty' }, 'No scores yet. Play Phish or Legit to get on the board, or load the example team in Team Arena.'));
    } else {
      let shown = rows.slice(0, 5);
      const me = rows.findIndex(r => r.me);
      if (me >= 5) shown = rows.slice(0, 4).concat(rows[me]);
      list.replaceChildren(...shown.map(r => {
        const rank = rows.indexOf(r) + 1;
        const medal = rank <= 3 ? h('span', { class: 'medal m' + rank, 'aria-label': 'Rank ' + rank }, String(rank)) : h('span', { class: 'rank' }, String(rank));
        return h('li', { class: r.me ? 'me' : '' }, medal,
          h('span', { class: 'avatar' }, initials(r.name)),
          h('span', { class: 'lb-name' }, r.name, r.dept ? h('small', {}, r.dept) : null),
          rank <= 3 ? h('span', { class: 'cup c' + rank }, svg(BADGES[3].icon)) : h('span', {}),
          h('b', { class: 'lb-score' }, String(r.score)));
      }));
    }

    // Next mission: the weakest unfinished lesson, or the challenge first
    let name, why, go;
    if (!p.answers.length) { name = 'Play Phish or Legit'; why = 'Decide on 12 messages to find out which tricks you miss.'; go = () => P.showView('challenge'); }
    else {
      const todo = Object.keys(P.SKILLS).filter(k => !s.training.done[k]).sort((a, b) => (aw.skillPct[a] ?? 0.6) - (aw.skillPct[b] ?? 0.6));
      if (todo.length) {
        const k = todo[0];
        name = 'Lesson: ' + P.SKILLS[k].name;
        why = aw.skillPct[k] != null ? `Your weakest topic right now (${Math.round(aw.skillPct[k] * 100)}%).` : 'Next lesson in your plan.';
        go = () => { P.showView('training'); setTimeout(() => { const m = $('module-' + k); if (m) { m.open = true; m.scrollIntoView({ behavior: 'smooth', block: 'start' }); } }, 50); };
      } else { name = 'Inbox Detective'; why = 'All lessons done. Put your skills to work on a real email.'; go = () => P.showView('analyse'); }
    }
    $('ms-name').textContent = name; $('ms-why').textContent = why;
    $('ms-go').onclick = go;
  }

  // Play buttons
  document.querySelectorAll('.game .play').forEach(b => b.addEventListener('click', () => {
    const go = b.dataset.go;
    if (go === 'voice') { P.showView('analyse'); P.loadExample('vish'); window.scrollTo({ top: 0, behavior: 'smooth' }); }
    else { P.showView(go); window.scrollTo({ top: 0, behavior: 'smooth' }); }
  }));

  document.querySelector('.logo-tile').addEventListener('click', e => { e.preventDefault(); P.showView('home'); });
  document.addEventListener('pea:view', e => { if (e.detail === 'home') render(); });
  document.addEventListener('pea:data', render);
  render();
})();
