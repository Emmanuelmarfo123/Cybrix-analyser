/*
 * Automated checks for the detection engine.
 * Run with:  node tests/run-tests.js
 * (Only needed for development. Visitors never run this.)
 */
require('../js/rules.js');
require('../js/homograph.js');
require('../js/analyser.js');
require('../js/guidance.js');
require('../js/content.js');
require('../js/eml.js');
const fs = require('fs');
const P = globalThis.PEA;

let pass = 0, fail = 0;
function check(name, cond, info) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (info ? '  → ' + info : '')); }
}
const ids = r => r.findings.map(f => f.id);

console.log('\nCredential phish with look-alike domain');
let r = P.analyse(`From: "PayPal Security" <service@paypa1-secure.xyz>
Reply-To: help@mail-collector.ru
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-secure.xyz; dkim=none; dmarc=fail
Subject: Your account has been suspended

Dear Customer,
We detected unusual sign-in activity. Your account will be suspended within 24 hours.
Please verify your account and confirm your password here: http://paypal.com.account-verify.xyz/login
Or use https://bit.ly/3xYz12
Failure to comply will result in permanent closure.`);
check('score is Critical', r.level === 'Critical', r.score);
['urgency', 'threat', 'password-request', 'generic-greeting', 'url-brand-mismatch', 'url-shortener', 'reply-to-mismatch', 'spf-fail', 'dmarc-fail', 'display-brand-mismatch', 'combo-credential-harvest']
  .forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));
check('sender lookalike', ids(r).some(i => i.startsWith('sender-')), ids(r).join(','));

console.log('\nBEC / bank change');
r = P.analyse(`Hi Sarah, are you at your desk? I need you to process an urgent wire transfer today.
Our supplier's bank details have changed, please use the new IBAN below. Keep this confidential, I'm in a meeting and can't talk.
Regards, John (CEO)`);
['bank-change', 'payment', 'secrecy', 'authority', 'combo-bec'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));
check('High or Critical', ['High', 'Critical'].includes(r.level), r.score);

console.log('\nMalware attachment');
r = P.analyse(`Please find attached the overdue invoice. Attachment: Invoice_4471.pdf.exe and report.docm, plus scan.iso
If you see a yellow bar, click Enable Content to view the document.`);
['att-double-ext', 'att-executable', 'att-macro', 'att-container', 'macros', 'invoice', 'combo-malware'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));

console.log('\nURL tricks');
r = P.analyse(`Visit http://192.168.10.5/login.php or https://www.microsoft.com@evil.example/auth or https://xn--pple-43d.com/id
Track: https://arnazon.com/orders  and https://login-portal.web.app/`);
['url-ip-url', 'url-userinfo', 'url-homograph-brand', 'url-lookalike', 'url-abused-host'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));

console.log('\nMisleading link text (HTML and plain text)');
r = P.analyse(`<html><body><p>Dear user, sign in to <a href="http://secure-update.top/x">https://www.paypal.com/signin</a></p></body></html>`);
check('HTML misleading', ids(r).includes('url-misleading-text'), ids(r).join(','));
r = P.analyse(`Sign in at https://login.microsoftonline.com <http://evil-login.click/ms>`);
check('plain-text misleading', ids(r).includes('url-misleading-text'), ids(r).join(','));
check('official MS link not flagged', !r.urls.find(u => u.host === 'login.microsoftonline.com').issues.length);

console.log('\nVoice transcript');
r = P.analyse(`Hello, I'm calling from your bank's fraud department. We've seen an unauthorised transaction. To stop it I need you to read me the code we just sent to your phone. Please stay on the line. To protect your savings we will move your money to a safe account. Please install AnyDesk so I can help.`, 'voice');
['caller-authority', 'mfa-request', 'stay-on-line', 'safe-account', 'remote-access', 'combo-vishing'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));
check('Critical', r.level === 'Critical', r.score);

console.log('\nBenign messages stay low');
r = P.analyse(`Hi team, the agenda for Thursday's planning meeting is attached as agenda.pdf. Lunch will be provided. See https://www.google.com/maps for directions. Thanks, Maria`);
check('benign Low', r.level === 'Low', r.score + ' ' + ids(r).join(','));
r = P.analyse(`Your Amazon order #112-555 has shipped. Track it at https://www.amazon.de/gp/your-account/order-history. Thanks for shopping with us.`);
check('legit amazon Low', r.level === 'Low', r.score + ' ' + ids(r).join(','));
r = P.analyse(`I made a purchase at the officedepot store yesterday, see https://www.officedepot.com/receipt`);
check('no false brand hit on "purchase"/officedepot', !ids(r).some(i => i.includes('brand-mismatch')), ids(r).join(','));

console.log('\nIOCs & defang');
r = P.analyse(`Go to http://203.0.113.9/pay and email billing@evil-pay.top or call +44 20 7946 0958`);
check('IP ioc', r.iocs.ips.includes('203.0.113.9'));
check('email ioc', r.iocs.emails.includes('billing@evil-pay.top'));
check('phone ioc', r.iocs.phones.length === 1, JSON.stringify(r.iocs.phones));
check('defang', P.defang('http://evil.com/a') === 'hxxp[://]evil[.]com/a', P.defang('http://evil.com/a'));

console.log('\nBuilt-in examples & challenge items');
for (const ex of P.EXAMPLES) {
  const rr = P.analyse(ex.text, ex.mode);
  check(`example "${ex.label}" → ${rr.level} (${rr.score})`, ex.id === 'legit' ? rr.level === 'Low' : ['High', 'Critical'].includes(rr.level), ids(rr).join(','));
  check('guidance renders for ' + ex.id, P.whatIf(rr).length && P.attackPath(rr).length >= 4 && P.actions(rr).now.length);
}
for (const c of P.CHALLENGE) {
  const rr = P.analyse('From: ' + c.from + '\n\n' + c.body, c.kind === 'Voice' ? 'voice' : 'email');
  check(`challenge ${c.id} (${c.phish ? 'phish' : 'legit'}) → ${rr.level} ${rr.score}`, c.phish ? rr.score >= 45 : rr.score < 20, ids(rr).join(','));
}

console.log('\nReal email files (.eml)');
{
  const raw = fs.readFileSync(__dirname + '/samples/phishing-sample.eml', 'utf8');
  check('raw source detected', P.eml.looksRaw(raw));
  const conv = P.eml.toAnalyserText(raw);
  check('subject decoded (RFC 2047)', conv.meta.subject.includes('Konto wird gesperrt'), conv.meta.subject);
  check('from decoded', conv.meta.from.includes('PayPal Service') && conv.meta.from.includes('paypa1-security.top'), conv.meta.from);
  check('attachment name decoded (RFC 2231)', conv.meta.attachments.some(a => a.filename === 'Rechnung überfällig.docm'), JSON.stringify(conv.meta.attachments));
  check('quoted-printable body decoded', conv.text.includes('Café – Sécurité'), conv.text.slice(0, 400));
  check('HTML link destinations listed', conv.meta.links === 2, conv.meta.links);
  check('no Received IPs leak into analysis text', !conv.text.includes('Received:'));
  const rr = P.analyse(conv.text, 'email');
  ['url-misleading-text', 'url-ip-url', 'url-shortener', 'spf-fail', 'dkim-fail', 'dmarc-fail', 'reply-to-mismatch', 'display-brand-mismatch', 'att-macro', 'password-request', 'threat']
    .forEach(id => check('eml finds ' + id, ids(rr).includes(id), ids(rr).join(',')));
  check('eml Critical', rr.level === 'Critical', rr.score);

  const rep = P.eml.toAnalyserText(fs.readFileSync(__dirname + '/samples/reported-as-attachment.eml', 'utf8'));
  check('forwarded-as-attachment: analyses the original', rep.note.includes('Nana') && rep.meta.from.includes('paypa1-security.top'), rep.note + ' | ' + rep.meta.from);
  check('forwarded original scores Critical', P.analyse(rep.text).level === 'Critical');

  const leg = P.eml.toAnalyserText(fs.readFileSync(__dirname + '/samples/legitimate-sample.eml', 'utf8'));
  const lr = P.analyse(leg.text);
  check('legitimate .eml Low', lr.level === 'Low', lr.score + ' ' + ids(lr).join(','));
  check('auth pass noted', lr.headers.positives.length === 1);
  check('simple pasted email is not mistaken for raw source', !P.eml.looksRaw(P.EXAMPLES[0].text));
}

console.log('\nScoring accuracy (no double-counting)');
{
  const pts = (r, pred) => r.findings.filter(pred).reduce((a, f) => a + f.points, 0);
  const all = [...P.EXAMPLES.map(e => P.analyse(e.text, e.mode)),
    ...P.CHALLENGE.map(c => P.analyse('From: ' + c.from + '\n\n' + c.body, c.kind === 'Voice' ? 'voice' : 'email')),
    ...['phishing-sample.eml', 'reported-as-attachment.eml', 'legitimate-sample.eml'].map(f => P.analyse(P.eml.toAnalyserText(fs.readFileSync(__dirname + '/samples/' + f, 'utf8')).text))];
  check(`displayed points sum to the total in all ${all.length} reports`, all.every(r => r.findings.reduce((a, f) => a + f.points, 0) === r.raw));
  check(`reason numbers add up to the risk score in all ${all.length} reports`, all.every(r => r.findings.reduce((a, f) => a + f.share, 0) === r.score), all.map(r => r.score + '/' + r.findings.reduce((a, f) => a + f.share, 0)).join(' '));
  check('every counted reason shows at least +1, overlapped reasons show 0', all.every(r => r.findings.every(f => f.points > 0 ? (f.share >= 1 || r.score < r.findings.filter(x => x.points > 0).length) : f.share === 0)));
  for (const [t, m] of [['urgent', 'email'], ['Dear customer, verify your password', 'email'], ['hello', 'email'], ['Please install AnyDesk', 'voice']]) {
    const x = P.analyse(t, m);
    check(`shares = score for "${t}" (${x.score})`, x.findings.reduce((a, f) => a + f.share, 0) === x.score);
  }
  check('no finding adds more than its own weight', all.every(r => r.findings.every(f => f.points >= 0 && f.points <= f.weight)));

  let r = P.analyse('Sign in: http://203.0.113.9/secure/login.php');
  check('one link with four problems counts at most 40 points', pts(r, f => f.group === 'Links') <= 40, pts(r, f => f.group === 'Links'));
  check('…but every problem is still listed', ['url-ip-url', 'url-no-https', 'url-login-words'].every(id => ids(r).includes(id)));

  r = P.analyse('Attachment: invoice.pdf.exe');
  check('one file with two problems counts at most 40 points', pts(r, f => f.group === 'Attachments') <= 40, pts(r, f => f.group === 'Attachments'));

  r = P.analyse('Payment is due immediately.');
  const w = r.findings.reduce((a, f) => a + f.weight, 0);
  check('the same sentence is not scored in full by three rules', r.raw < w, `${r.raw} vs ${w}`);

  r = P.analyse('Please review https://intranet.example.com/office365-migration and email daniel.weber@gmail.com');
  check('brand words inside links and email addresses are not counted', !ids(r).includes('brand'), ids(r).join(','));

  r = P.analyse('urgent. urgent. urgent. urgent.');
  check('repeating a phrase does not inflate its points', r.findings.find(f => f.id === 'urgency').points === 12);

  r = P.analyse(P.EXAMPLES[0].text);
  check('brand mention adds 0 when a brand mismatch is proven', r.findings.find(f => f.id === 'brand').points === 0);
  check('SPF+DKIM+DMARC count as one family', pts(r, f => /^(spf|dkim|dmarc)-fail$/.test(f.id)) <= 22 + Math.ceil(0.35 * 33));
  check('every reduced finding explains why', r.findings.every(f => f.points === f.weight || f.note));
  check('same input → same score', P.analyse(P.EXAMPLES[0].text).score === r.score);
}

console.log('\nUnicode homographs');
{
  let r = P.analyse('Sign in at https://xn--pypal-4ve.com/signin');
  const f = r.findings.find(x => x.id === 'url-homograph-brand');
  check('Cyrillic "а" in pаypal.com detected as brand homograph', !!f, ids(r).join(','));
  check('explanation names the look-alike letter', f && /U\+0430/.test(f.explain), f && f.explain);
  check('decoded (displayed) name is shown', r.urls[0].unicodeHost === 'pаypal.com', r.urls[0].unicodeHost);
  r = P.analyse('Order from https://müller.de/shop today');
  check('legit international domain only gets an info note', ids(r).includes('url-idn') && r.level === 'Low', r.score + ' ' + ids(r).join(','));
  r = P.analyse('Please confirm with your PаyPal account');
  check('brand spelled with look-alike letters in text', ids(r).includes('text-homoglyph-brand'), ids(r).join(','));
  r = P.analyse('Enter your pass\u200Bword here');
  check('invisible zero-width characters', ids(r).includes('invisible-chars'), ids(r).join(','));
  r = P.analyse('Привет, как дела? Grüße aus München, à bientôt.');
  check('normal Russian / German / French text is not flagged', !r.findings.some(x => x.group === 'Hidden'), ids(r).join(','));
  check('sender domain homograph', ids(P.analyse('From: "Apple" <id@xn--pple-43d.com>\n\nhello')).some(i => i.startsWith('sender-homograph')));
}

console.log('\nHTML link detection');
{
  let r = P.analyse('<html><body><form action="https://evil.example/c.php"><input type="email" name="user"><input type="password" name="pw"></form></body></html>');
  check('HTML form asking for a password', ids(r).includes('html-form-secret'), ids(r).join(','));
  r = P.analyse('<html><head><meta http-equiv="refresh" content="0;url=https://evil.example/x"></head><body><iframe src="https://evil.example/f"></iframe><p style="display:none">hidden words</p></body></html>');
  ['html-refresh', 'html-frame', 'html-hidden'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));
  r = P.analyse('Click https://tracker.example/r?u=https%3A%2F%2Fpaypal-verify.top%2Flogin');
  check('encoded redirect destination found and checked', ids(r).includes('url-redirect') && ids(r).includes('url-brand-mismatch'), ids(r).join(','));
  r = P.analyse('Link: https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.github.com%2F&data=1');
  check('security wrapper with safe destination stays Low', r.level === 'Low', r.score + ' ' + ids(r).join(','));
  const q = P.eml.toAnalyserText(fs.readFileSync(__dirname + '/samples/quishing-html-sample.eml', 'utf8'));
  check('text that exists only in the HTML part is analysed', /Only in the HTML version/.test(q.text) && /Scan the QR code/.test(q.text));
  check('HTML attachment is read as text', /Inside attachment Storage_Upgrade\.html/.test(q.text));
  check('inline image kept for QR scanning', q.meta.images.length === 1, q.meta.images.length);
  r = P.analyse(q.text);
  ['html-form-secret', 'html-refresh', 'html-hidden', 'url-redirect', 'url-homograph-brand', 'url-misleading-text', 'text-homoglyph-brand', 'urgency']
    .forEach(id => check('quishing sample finds ' + id, ids(r).includes(id), ids(r).join(',')));
  check('hidden filler words are flagged but not read as message text', !ids(r).includes('invoice'), ids(r).join(','));
}

console.log('\nQR codes');
{
  let PNG;
  try { ({ PNG } = require(process.env.PNGJS || 'pngjs')); } catch (e) { console.log('  (skipped image decoding: run "npm install pngjs" to include it)'); }
  if (PNG) {
  const jsQR = require('../js/vendor/jsQR.js');
  const png = PNG.sync.read(fs.readFileSync(__dirname + '/samples/qr-code-sample.png'));
  const res = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  check('bundled reader decodes the sample QR image', res && res.data === 'http://198.51.100.77/m365/verify?session=8812', res && res.data);
  global.window = undefined;
  require('../js/qr.js');
  const line = P.qr.line('qr-code-sample.png', res.data);
  const r = P.analyse('Scan this to keep your mailbox.\n\n--- QR codes found ---\n' + line);
  check('decoded QR link is analysed as a link', ['url-qr', 'url-ip-url'].every(id => ids(r).includes(id)), ids(r).join(','));
  check('QR + same link not double-counted', r.findings.filter(f => f.group === 'Links').reduce((a, f) => a + f.points, 0) <= 40);
  check('QR text payload handled', ids(P.analyse(P.qr.line('x.png', 'WIFI:S:office;T:WPA;P:secret;;'))).includes('url-qr-text'));
  }
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
