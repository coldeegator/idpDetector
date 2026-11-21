// Content script (classic script, not a module). Reads the DOM of the page you are viewing and
// reports small, sanitized signals to the service worker. Nothing leaves your machine.
//
// Tokens: JWT-shaped strings in the URL, JS-readable cookies and web storage are passed to the
// service worker, which keeps only {iss, alg, kid, claim NAMES} and drops the raw token and all
// claim values.
(() => {
  const sent = new Set();
  let selectors = [];
  let globalNames = []; // allowlist of page-global paths to probe (from the signature table)
  let globalHits = []; // those the MAIN-world probe found

  const clean = (u) => {
    try {
      const x = new URL(u, location.href);
      if (!/^https?:$/.test(x.protocol)) return null;
      const names = [...new Set([...x.searchParams.keys()])];
      return x.origin + x.pathname + (names.length ? '?' + names.join('&') : '');
    } catch { return null; }
  };

  // A classic content script cannot import modules, so it only FINDS token-shaped strings and
  // hands them to the service worker, which decodes them with the single shared summarizeJwt()
  // (detector.js) and discards the raw token. Tokens never leave the extension.
  const JWT_RE = /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;

  function jwtSignals(text, out) {
    if (!text || text.length > 200000) return;
    for (const tok of (text.match(JWT_RE) || []).slice(0, 5)) out.push({ k: 'tok', v: tok });
  }

  function collect() {
    const out = [];
    for (const s of selectors) {
      try { if (document.querySelector(s)) out.push({ k: 'sel', v: s }); } catch { /* bad selector */ }
    }
    for (const el of document.querySelectorAll('script[src]')) {
      const u = clean(el.src); if (u) out.push({ k: 'dom', v: 'script:' + u });
    }
    for (const el of document.querySelectorAll('link[href]')) {
      const rel = (el.getAttribute('rel') || '').toLowerCase();
      if (rel.includes('stylesheet') || rel.includes('preload') || rel.includes('modulepreload')) {
        const u = clean(el.href); if (u) out.push({ k: 'dom', v: 'link:' + u });
      }
    }
    for (const el of document.querySelectorAll('form[action]')) {
      const u = clean(el.action);
      if (u) { out.push({ k: 'dom', v: 'form:' + u }); out.push({ k: 'url', v: u, rt: 'form' }); }
    }
    for (const el of document.querySelectorAll('input[name]')) {
      const n = el.getAttribute('name');
      if (/^(SAMLRequest|SAMLResponse|RelayState|wa|wresult|wctx)$/.test(n)) {
        out.push({ k: 'dom', v: 'input:' + n });
        out.push({ k: 'url', v: location.origin + location.pathname + '?' + n, rt: 'form' }); // lets protocol detection see it
      }
    }
    if (document.title) out.push({ k: 'dom', v: 'title:' + document.title.slice(0, 100) });

    jwtSignals(location.hash, out);
    try { jwtSignals(decodeURIComponent(location.search || ''), out); } catch { /* bad escape */ }
    jwtSignals(document.cookie, out); // JS-readable cookies only (HttpOnly ones are not visible here)
    for (const store of [localStorage, sessionStorage]) {
      try {
        for (let i = 0; i < Math.min(store.length, 60); i++) jwtSignals(store.getItem(store.key(i)), out);
        // Storage KEY NAMES only (SDK-specific keys like okta-token-storage); values are not sent.
        for (let i = 0; i < Math.min(store.length, 200); i++) out.push({ k: 'store', v: String(store.key(i)).slice(0, 120) });
      } catch { /* storage blocked */ }
    }
    for (const g of globalHits) out.push({ k: 'glob', v: g });
    return out;
  }

  function report() {
    const fresh = [];
    for (const s of collect()) {
      const id = s.k + '\u0000' + JSON.stringify(s.v);
      if (!sent.has(id)) { sent.add(id); fresh.push(s); }
    }
    if (fresh.length) {
      try { chrome.runtime.sendMessage({ type: 'dom', sigs: fresh }); } catch { /* extension reloaded */ }
    }
  }

  // The MAIN-world script (main-world.js) answers this probe with the globals that exist.
  // Events on `document` cross the isolated/main world boundary; payloads are JSON strings.
  const probeGlobals = () => {
    if (!globalNames.length) return;
    document.dispatchEvent(new CustomEvent('__idpd_probe', { detail: JSON.stringify(globalNames) }));
  };
  document.addEventListener('__idpd_globals', (e) => {
    try {
      const names = JSON.parse(e.detail);
      if (Array.isArray(names)) {
        globalHits = names.filter((n) => typeof n === 'string' && globalNames.includes(n));
        report();
      }
    } catch { /* ignore malformed event */ }
  });
  document.addEventListener('__idpd_ready', probeGlobals);

  chrome.runtime.sendMessage({ type: 'config' }).then((cfg) => {
    selectors = Array.isArray(cfg?.selectors) ? cfg.selectors : [];
    globalNames = Array.isArray(cfg?.globals) ? cfg.globals : [];
    probeGlobals();
    report();
    // SPA login pages (e.g. AM XUI, Okta widget) render after load, and SDKs attach late.
    setTimeout(() => { probeGlobals(); report(); }, 1500);
    setTimeout(() => { probeGlobals(); report(); }, 4000);
    addEventListener('hashchange', report);
  }).catch(() => { /* service worker not ready */ });
})();
