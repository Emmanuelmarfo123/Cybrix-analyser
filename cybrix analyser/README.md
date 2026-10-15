# CYBRIX — Phishing Email Analyser

A free, private phishing and social-engineering analyser that runs **entirely in your web browser**.
Paste a suspicious email or a phone-call transcript and get a risk score, a clear explanation, an attack-path simulation mapped to MITRE ATT&CK, incident-response guidance and IOCs. It also includes an awareness challenge, personalised training and a team dashboard.

No server, no database, no accounts, no AI APIs, no tracking.

---

## Analyse a real email from your inbox

On the **Analyse** tab, use **Analyse a real email**:

1. Save the suspicious email from your mail app as an `.eml` file:
   - **Gmail:** open the email → **⋮ More** → **Download message**. Or use **Show original** → **Copy to clipboard** and paste it into the box.
   - **Outlook on the web / new Outlook:** **⋯** → **Save** / **Download**.
   - **Classic Outlook for Windows:** `.msg` files aren't supported. Copy **File → Properties → Internet headers** and paste them above the message text.
   - **Apple Mail:** **File → Save As → Raw Message Source**. **Thunderbird:** **File → Save As → File**.
2. Drop the file onto the analyser (or click **Open .eml file**).

The analyser decodes the real message: full headers (SPF/DKIM/DMARC, Reply-To, Return-Path), the body, the **true destination behind every link**, and attachment names. If someone forwarded a phishing email **as an attachment** (common when reporting to a SOC), the attached original is analysed.

Privacy: the file is read with the browser's `FileReader` on your own device. Attachments are never opened, links are never visited, and remote images (tracking pixels) are never loaded. Try it with the samples in `tests/samples/`.

> **Why doesn't it log in to my mailbox?** A web page asking for your email password is exactly what phishing looks like. A safe live connection needs OAuth sign-in and a server, which this version deliberately avoids. See "Ideas to extend it" for that route.

## Advanced detection: QR codes, HTML links, drag and drop, look-alike letters

| Feature | What it does | Privacy |
|---|---|---|
| **QR code detection (quishing)** | Click **Scan QR image**, paste a screenshot (Ctrl+V) into the message box, or drop an image anywhere. QR codes inside imported `.eml` emails (inline or attached images) are found automatically. The decoded link is checked like any other link and gets its own warning sign, "Link hidden in a QR code". | Decoded on your device with the browser's BarcodeDetector or the bundled jsQR reader (`js/vendor/jsQR.js`, Apache-2.0). The link is never opened. |
| **HTML link detection** | Reads **both** the plain-text and HTML versions of an email (attackers hide the lure in the version you do not expect). It also compares link text with the real destination, follows encoded redirects (`?url=https%3A%2F%2F…`) to the hidden address, and reports fill-in forms asking for passwords, auto-redirects (meta refresh), embedded frames, `javascript:`/`data:` links and hidden filler text. HTML/SVG attachments are read as text to find fake login pages. | HTML is only read as text; nothing in it runs or loads. |
| **Drag and drop anywhere** | Drop a file on any page: `.eml`/`.txt` emails go to the email reader, images to the QR reader, `.html` files to the HTML checks. | Files are read with `FileReader` in the browser and never uploaded. |
| **Unicode homograph detection** | Decodes international domain names (Punycode, e.g. `xn--pypal-4ve.com` → `pаypal.com`), names each look-alike letter (e.g. Cyrillic "а", U+0430), and flags domains that mix alphabets or imitate a brand, brand names spelled with look-alike letters in the text, invisible zero-width characters and text-direction tricks. Legitimate international domains (e.g. `müller.de`) only get a small information note. | All checks run locally. |

Try them with `tests/samples/qr-code-sample.png` and `tests/samples/quishing-html-sample.eml`.

## Run it on your computer (30 seconds)

1. Unzip the folder.
2. Double-click `index.html`. It opens in your browser and works offline.

## Put it on the internet for free

All three options are free for static sites like this one.

**Option A: Netlify Drop (easiest, no account needed to try)**
1. Go to <https://app.netlify.com/drop>.
2. Drag the whole `phishing-email-analyser` folder onto the page.
3. You get a public link straight away. Create a free account to keep it permanently.

**Option B: GitHub Pages (good for your portfolio)**
1. Create a free GitHub account and a new **public** repository, e.g. `phishing-email-analyser`.
2. Click **Add file → Upload files**, drag in everything from this folder (keep the `css` and `js` folders), then **Commit**.
3. Go to **Settings → Pages**, set *Source* to **Deploy from a branch**, choose `main` and `/ (root)`, then **Save**.
4. After a minute your site is live at `https://YOUR-USERNAME.github.io/phishing-email-analyser/`.

**Option C: Cloudflare Pages**: create a project, choose *Direct Upload*, and upload the folder.

> Optional hardening for hosts that support headers (Netlify, Cloudflare): the included `_headers` file adds the same privacy policy as an HTTP header, plus `frame-ancestors 'none'` so other sites cannot embed yours.

---

## What is in the folder

| File | What it does (plain English) |
|---|---|
| `index.html` | The page layout: tabs, text box and buttons. Contains the privacy lock (see below). |
| `css/styles.css` | Colours, spacing and layout, including dark mode and phone layout. |
| `js/rules.js` | The **knowledge base**: every warning sign, its weight and its explanation. Edit this to add your own rules. |
| `js/analyser.js` | The **detection engine**: reads the text, checks links, attachments and headers, calculates the score and extracts IOCs. |
| `js/guidance.js` | Turns findings into "what happens if…", the attack path and incident-response steps. |
| `js/homograph.js` | Unicode look-alike detection: Punycode decoding, alphabet (script) checks and look-alike letter mapping. |
| `js/qr.js` | Reads QR codes in images on this device (BarcodeDetector or the bundled jsQR). |
| `js/vendor/jsQR.js` | The open-source jsQR reader (Apache-2.0, licence in `js/vendor/jsQR-LICENSE.txt`), bundled so no download is needed. |
| `js/eml.js` | Reads real email files (`.eml` or pasted raw source): decodes MIME parts, base64, quoted-printable, encoded subjects and attachment names. |
| `js/content.js` | Example emails, the 12 challenge messages and the training lessons. |
| `js/core.js` | Shared helpers: safe storage, safe display of text, awareness-score formula. |
| `js/app.js` | Connects the Analyse page buttons to the engine and draws the report. |
| `js/shell.js` | Analyse-page extras: summary cards, example cards and header buttons. |
| `js/arcade.js` | The CYBRIX Arcade home: featured games, XP and level, badges, leaderboard, stats and next mission (all from data stored in this browser). |
| `js/learn.js` | The Challenge and Training pages. |
| `js/dashboard.js` | Personal and team dashboards. |
| `tests/run-tests.js` | 142 automated checks for detection, email parsing, scoring, homographs, HTML tricks and QR codes (`node tests/run-tests.js`; run `npm install pngjs` first to include the QR image test). |
| `tests/samples/` | Sample emails (phishing, reported-as-attachment, legitimate, QR + HTML quishing) and a QR-code image to try the features. |
| `tools/build-preview.py` | Makes a single-file copy (`dist/preview.html`) for previews. Not needed for hosting. |

---

## Key decisions, explained

**Why plain HTML, CSS and JavaScript?** Browsers understand these three languages natively. There is nothing to install or build and nothing to break when a framework updates. It is also the easiest code to learn from.

**How is privacy guaranteed?** The page has a *Content Security Policy* (CSP), a line in `index.html` that the browser enforces. `connect-src 'none'` means the page is forbidden from sending data to any server. Even if someone added a bad line of code, the browser would block the upload. Try it: open DevTools (F12) → **Network**, click Analyse, and you'll see no new requests.

**Why no Google Fonts?** Loading a font from Google tells Google that someone visited. The app uses fonts already on your device.

**Why no automatic voice transcription?** The speech recognition built into browsers (Web Speech API) sends audio to Google or Apple servers. That would break the privacy rule, so you load a recording to *play locally* and type what was said.

**How are emails displayed safely?** Email text is untrusted. If we inserted it into the page as HTML, a malicious email could run code (an attack called **XSS, Cross-Site Scripting**). The app only ever inserts text as plain characters (`textContent`), so `<script>` in an email is just shown, never run. Links are read as text and **never visited**.

**What is stored?** Only small summaries (score and warning-sign names, never the message), challenge answers and training progress, in your browser's `localStorage`. "Privacy & how it works → Delete all data" wipes it.

**How does the team dashboard work without a database?** Each person exports a small JSON file of scores. A manager imports those files, and the combining happens in the manager's browser.

**How is the risk score calculated?** Each warning sign has a weight (a password request = 25, a generic greeting = 6). The score counts **independent evidence, not rule hits**, so the same evidence is never counted twice:
- words already matched by a stronger rule are not counted again, and words inside links or email addresses are not treated as message text;
- each link and each file counts once: its strongest problem in full, other problems with the same link or file add 25%, extra suspicious links or files add 50% (one link is capped at 40 points);
- related checks form families (SPF/DKIM/DMARC; urgency + threats; sender identity; reply/return path; money requests): the strongest counts in full, the rest add a reduced share;
- "mentions a brand" adds nothing once a brand mismatch is proven, and repeating a phrase does not add points.

Dangerous combinations add a pattern bonus. The evidence total is converted to the 0–100 risk score with `100 × (1 − e^(−total/55))`. That score is then **shared out between the counted warning signs** in proportion to their evidence (whole numbers, largest-remainder rounding), so the numbers shown next to the reasons **always add up to exactly the risk score**. Bands: Low 0–19, Medium 20–44, High 45–69, Critical 70–100. Automated tests check that the shares always equal the score and that nothing is double-counted.

---

## Ideas to extend it (great practice)

1. **Add a rule.** Open `js/rules.js`, copy an existing rule, change the `id`, `title`, `patterns` and `explain`. Re-run the tests.
2. **Add a brand.** Add it to `BRANDS` in `rules.js` with its real domains so look-alikes get caught.
3. **Add challenge messages.** Add entries to `CHALLENGE` in `js/content.js`.
4. **Live mailbox integration.** Build an Outlook add-in or Gmail add-on that reuses `rules.js` + `analyser.js` + `eml.js`, or a small server that reads a "report phishing" mailbox through the Microsoft Graph / Gmail API.

## Limits

This is a rule-based teaching tool. It can miss carefully written attacks and can flag genuine messages. A low score does not prove a message is safe. Always verify through a trusted channel and report suspicious messages to your security team.
