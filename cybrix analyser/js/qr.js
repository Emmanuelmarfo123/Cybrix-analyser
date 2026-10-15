/*
 * qr.js — finds and reads QR codes in images, on this device only.
 *
 * Plain-English summary:
 *   "Quishing" hides a phishing link inside a QR code picture, so you cannot hover over
 *   it and email filters cannot read it. This file turns an image into pixels inside the
 *   browser and reads any QR code in it:
 *     1. with the browser's built-in BarcodeDetector, when it has one (Chrome, Edge, Android),
 *     2. otherwise with jsQR, a small reader bundled in js/vendor (no download needed).
 *   The decoded link is only READ. It is never opened.
 */
(function (root) {
  'use strict';
  const P = root.PEA = root.PEA || {};
  const MAX_SIDE = 1600; // shrink huge photos so decoding stays fast

  async function bitmapFrom(blob) {
    if (typeof createImageBitmap === 'function') return createImageBitmap(blob);
    // Fallback for older browsers: load through a temporary local blob: address
    const url = URL.createObjectURL(blob);
    try {
      const img = new Image();
      img.src = url;
      await img.decode();
      return img;
    } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
  }

  function pixels(bmp, scale) {
    const w = Math.max(1, Math.round(bmp.width * scale)), h = Math.max(1, Math.round(bmp.height * scale));
    const c = document.createElement('canvas');
    c.width = w; c.height = h;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h); // transparent PNGs → white background
    ctx.drawImage(bmp, 0, 0, w, h);
    return ctx.getImageData(0, 0, w, h);
  }

  /** Read every QR code we can find in an image Blob/File. Returns an array of strings. */
  async function scanBlob(blob) {
    const bmp = await bitmapFrom(blob);
    const found = new Set();
    // 1) Built-in detector (can find several codes at once)
    if ('BarcodeDetector' in root) {
      try {
        const formats = await root.BarcodeDetector.getSupportedFormats();
        if (formats.includes('qr_code')) {
          const codes = await new root.BarcodeDetector({ formats: ['qr_code'] }).detect(bmp);
          codes.forEach(c => c.rawValue && found.add(c.rawValue));
        }
      } catch (e) { /* fall through to jsQR */ }
    }
    // 2) Bundled reader, at a few sizes (helps with tiny or very large codes)
    if (!found.size && typeof root.jsQR === 'function') {
      const base = Math.min(1, MAX_SIDE / Math.max(bmp.width, bmp.height));
      for (const s of [base, base * 0.5, Math.min(2, base * 2)]) {
        const img = pixels(bmp, s);
        const r = root.jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
        if (r && r.data) { found.add(r.data); break; }
      }
    }
    if (bmp.close) bmp.close();
    return [...found];
  }

  function base64ToBlob(b64, type) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new Blob([bytes], { type: type || 'image/png' });
  }

  /** Scan a list of {name, type, b64} images (from an .eml file). Returns [{name, data}]. */
  async function scanEmailImages(images) {
    const out = [];
    for (const im of images || []) {
      try { for (const d of await scanBlob(base64ToBlob(im.b64, im.type))) out.push({ name: im.name, data: d }); }
      catch (e) { out.push({ name: im.name, error: true }); }
    }
    return out;
  }

  /** The line format the analyser understands. */
  const line = (name, data) => `QR code in ${String(name).replace(/[→\n]/g, ' ').slice(0, 80)} → ${String(data).replace(/\s+/g, ' ').trim()}`;

  P.qr = { scanBlob, scanEmailImages, line, available: () => typeof root.jsQR === 'function' || 'BarcodeDetector' in root };
})(typeof window !== 'undefined' ? window : globalThis);
