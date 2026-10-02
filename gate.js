/*
 * Password gate. payload.js holds the whole tools app, gzip-compressed and encrypted with AES-256-GCM.
 * The key is derived from the password with PBKDF2-SHA256 (600,000 rounds), so guessing is slow.
 * Wrong password → decryption fails → nothing is revealed.
 */
(() => {
  'use strict';
  const P = window.DOT_PAYLOAD;
  const STORE = 'dot-data-tools-key';
  const $ = id => document.getElementById(id);
  const form = $('gate-form'), pw = $('gate-pw'), remember = $('gate-remember'), btn = $('gate-btn'), msg = $('gate-msg');

  const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const safe = fn => { try { return fn(); } catch { return null; } };

  function showError(text) {
    msg.textContent = text;
    msg.hidden = false;
  }

  if (!P || !window.crypto || !crypto.subtle || typeof DecompressionStream === 'undefined') {
    showError('This browser is too old or the page was not opened over https. Please use an up-to-date Chrome, Edge or Firefox.');
    btn.disabled = true;
    return;
  }

  async function keyFromPassword(password) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: fromB64(P.salt), iterations: P.iter, hash: 'SHA-256' }, base, 256);
  }

  async function open(rawKey) {
    const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    const zipped = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(P.iv) }, key, fromB64(P.data));
    const text = await new Response(new Blob([zipped]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    return JSON.parse(text);
  }

  function lock() {
    safe(() => sessionStorage.removeItem(STORE));
    safe(() => localStorage.removeItem(STORE));
    location.replace(location.pathname);
  }

  function launch(app) {
    window.DOT_GATE = { lock };
    document.title = app.title;
    $('gate-css').remove();
    const style = document.createElement('style');
    style.textContent = app.css;
    document.head.appendChild(style);
    document.body.className = '';
    document.body.innerHTML = app.body;
    for (const code of app.scripts) {
      const s = document.createElement('script');
      s.textContent = code;            // allowed by the hash list in this page's Content-Security-Policy
      document.body.appendChild(s);
    }
  }

  // Already unlocked in this tab (or remembered on this computer)?
  const saved = safe(() => JSON.parse(sessionStorage.getItem(STORE) || localStorage.getItem(STORE) || 'null'));
  if (saved && saved.salt === P.salt) {
    open(fromB64(saved.key)).then(launch).catch(() => {
      safe(() => sessionStorage.removeItem(STORE));
      safe(() => localStorage.removeItem(STORE));
    });
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    msg.hidden = true;
    btn.disabled = true;
    btn.textContent = 'Unlocking…';
    try {
      const raw = await keyFromPassword(pw.value);
      const app = await open(raw);
      const record = JSON.stringify({ salt: P.salt, key: toB64(raw) });
      safe(() => sessionStorage.setItem(STORE, record));
      if (remember.checked) safe(() => localStorage.setItem(STORE, record));
      launch(app);
    } catch {
      showError('Wrong password. Please try again.');
      pw.select();
      btn.disabled = false;
      btn.textContent = 'Unlock';
    }
  });
})();
