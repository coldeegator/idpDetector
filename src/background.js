// Service worker. OBSERVE-ONLY: never blocks, redirects or modifies a request.
// Collects sanitized signals per tab (URL param NAMES only, cookie NAMES only, no values, no bodies).
import { SELECTORS, GLOBALS, INTERESTING_URL } from './signatures.js';
import { analyze, sanitizeUrl, discoverySignals, discoveryCandidates, summarizeJwt, findJwts } from './detector.js';

const MAX_SIGNALS = 500;
const NOISE_HEADERS = new Set([
  'date', 'content-length', 'content-type', 'cache-control', 'etag', 'vary', 'accept-ranges',
  'connection', 'expires', 'last-modified', 'content-encoding', 'strict-transport-security',
  'set-cookie', 'cookie', 'authorization', 'age', 'pragma', 'keep-alive', 'transfer-encoding',
]);
const RESET_TRANSITIONS = new Set(['typed', 'auto_bookmark', 'keyword', 'keyword_generated', 'generated', 'reload']);

const key = (tabId) => `t${tabId}`;
const pending = new Map(); // tabId -> signals not yet flushed
const flushTimers = new Map();
const chain = new Map(); // tabId -> promise (serialises storage read-modify-write)
const navStart = new Map(); // tabId -> timeStamp of latest top-level onBeforeNavigate

const blank = () => ({ signals: [], seen: {}, probes: [] });

// Signal identity includes resource type (rt) and source origin (o): the same header from two
// different origins is two different pieces of evidence.
const sigId = (s) => [s.k, JSON.stringify(s.v), s.rt || '', s.o || ''].join('\u0000');
const rtOf = (type) => (type === 'main_frame' ? 'nav' : type === 'sub_frame' ? 'frame' : 'res');
const originOf = (u) => { try { return new URL(u).origin; } catch { return undefined; } };

async function load(tabId) {
  const o = await chrome.storage.session.get(key(tabId));
  return o[key(tabId)] || blank();
}
const save = (tabId, st) => chrome.storage.session.set({ [key(tabId)]: st });

function enqueue(tabId, fn) {
  const next = (chain.get(tabId) || Promise.resolve()).then(fn).catch((e) => console.warn('idp-detector', e));
  chain.set(tabId, next);
  return next;
}

async function commit(tabId, sigs) {
  const st = await load(tabId);
  const t = Date.now();
  for (const s of sigs) {
    if (st.signals.length >= MAX_SIGNALS) break;
    const id = sigId(s);
    if (st.seen[id]) continue;
    st.seen[id] = 1;
    st.signals.push({ ...s, t });
  }
  await save(tabId, st);
}

function add(tabId, sigs) {
  if (tabId < 0 || !sigs.length) return;
  const q = pending.get(tabId) || [];
  q.push(...sigs);
  pending.set(tabId, q);
  if (!flushTimers.has(tabId)) {
    flushTimers.set(tabId, setTimeout(() => flush(tabId), 250));
  }
}

function flush(tabId) {
  clearTimeout(flushTimers.get(tabId));
  flushTimers.delete(tabId);
  const sigs = pending.get(tabId) || [];
  pending.delete(tabId);
  return enqueue(tabId, () => (sigs.length ? commit(tabId, sigs) : undefined));
}

// ---------- network observation ----------
const FILTER = { urls: ['<all_urls>'] };

chrome.webRequest.onBeforeRequest.addListener((d) => {
  const isFrame = d.type === 'main_frame' || d.type === 'sub_frame';
  const s = sanitizeUrl(d.url);
  if (!s || (!isFrame && !INTERESTING_URL.test(s))) return;
  add(d.tabId, [{ k: 'url', v: s, rt: rtOf(d.type) }]);
}, FILTER);

chrome.webRequest.onBeforeRedirect.addListener((d) => {
  const from = sanitizeUrl(d.url);
  const to = sanitizeUrl(d.redirectUrl);
  const rt = rtOf(d.type); // a redirect of the top-level navigation is part of the login flow
  add(d.tabId, [from && { k: 'url', v: from, rt }, to && { k: 'url', v: to, rt }].filter(Boolean));
}, FILTER);

chrome.webRequest.onHeadersReceived.addListener((d) => {
  if (!['main_frame', 'sub_frame', 'xmlhttprequest'].includes(d.type)) return;
  const sigs = [];
  const o = originOf(d.url); // which origin produced this header/cookie
  for (const h of d.responseHeaders || []) {
    const name = h.name.toLowerCase();
    if (name === 'set-cookie') {
      const cname = (h.value || '').split('=')[0].trim();
      if (cname) sigs.push({ k: 'cookie', v: cname, o });
    } else if (!NOISE_HEADERS.has(name) && !name.startsWith('access-control-')) {
      sigs.push({ k: 'hdr', v: `${name}: ${(h.value || '').slice(0, 300)}`, o });
    }
  }
  add(d.tabId, sigs);
}, FILTER, ['responseHeaders', 'extraHeaders']);

// Access tokens are mostly sent as "Authorization: Bearer <jwt>" to APIs, which no page-level
// scan can see. Decode here (summarizeJwt keeps only iss/alg/kid/claim NAMES) and drop the token.
chrome.webRequest.onBeforeSendHeaders.addListener((d) => {
  const h = (d.requestHeaders || []).find((x) => x.name.toLowerCase() === 'authorization');
  if (!h) return;
  const sigs = findJwts(h.value || '', 1)
    .map(summarizeJwt)
    .filter(Boolean)
    .map((v) => ({ k: 'jwt', v, rt: 'auth', o: originOf(d.url) }));
  add(d.tabId, sigs);
}, FILTER, ['requestHeaders', 'extraHeaders']);

// ---------- per-tab lifecycle ----------
chrome.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId === 0) navStart.set(d.tabId, d.timeStamp);
});

// A fresh user-initiated navigation (typed URL, reload, ...) drops older signals, but keeps
// the redirect chain of THIS navigation (signals recorded since onBeforeNavigate).
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0 || !RESET_TRANSITIONS.has(d.transitionType)) return;
  const since = navStart.get(d.tabId) ?? 0;
  flush(d.tabId).then(() => enqueue(d.tabId, async () => {
    const st = await load(d.tabId);
    const keep = blank();
    for (const s of st.signals) {
      if (s.t >= since - 50) {
        keep.signals.push(s);
        keep.seen[sigId(s)] = 1;
      }
    }
    await save(d.tabId, keep);
  }));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  pending.delete(tabId); navStart.delete(tabId); chain.delete(tabId);
  chrome.storage.session.remove(key(tabId));
});

// ---------- opt-in discovery probe (popup button only) ----------
async function probe(tabId) {
  await flush(tabId);
  const tab = await chrome.tabs.get(tabId);
  const st = await load(tabId);
  const urls = discoveryCandidates(tab.url || '', st.signals);
  const probes = [];
  const sigs = [];
  for (const url of urls) {
    try {
      const r = await fetch(url, { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(6000) });
      const text = (await r.text()).slice(0, 300000);
      let doc;
      try { doc = JSON.parse(text); } catch { /* not JSON */ }
      if (r.ok && doc && typeof doc.issuer === 'string') {
        probes.push({ url, status: r.status, ok: true });
        sigs.push(...discoverySignals(doc));
      } else {
        probes.push({ url, status: r.status, ok: false });
      }
    } catch (e) {
      probes.push({ url, status: 0, ok: false, error: String(e.name || e) });
    }
  }
  await enqueue(tabId, async () => {
    await commit(tabId, sigs);
    const cur = await load(tabId);
    cur.probes = probes;
    await save(tabId, cur);
  });
  return probes;
}

// ---------- messages ----------
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  (async () => {
    switch (msg?.type) {
      case 'config':
        return { selectors: SELECTORS, globals: GLOBALS };
      case 'dom':
        // Content-script signals describe the top page: stamp them with its origin.
        // Token candidates ('tok') are decoded to a summary here; the raw string is dropped.
        if (sender.tab) {
          add(sender.tab.id, (msg.sigs || []).slice(0, 200).flatMap((s) => {
            // The page can forge events, so only accept global names we asked about.
            if (s.k === 'glob') return GLOBALS.includes(s.v) ? [{ k: 'glob', v: s.v, o: sender.origin }] : [];
            if (s.k === 'store') return typeof s.v === 'string' ? [{ k: 'store', v: s.v.slice(0, 120), o: sender.origin }] : [];
            if (s.k !== 'tok') return [{ ...s, o: sender.origin }];
            const v = summarizeJwt(s.v);
            return v ? [{ k: 'jwt', v, rt: 'page', o: sender.origin }] : [];
          }));
        }
        return true;
      case 'getResult': {
        await flush(msg.tabId);
        const st = await load(msg.tabId);
        return { ...analyze(st.signals), nsignals: st.signals.length, probes: st.probes };
      }
      case 'probe':
        return probe(msg.tabId);
      case 'clear':
        pending.delete(msg.tabId);
        await enqueue(msg.tabId, () => save(msg.tabId, blank()));
        return true;
      case 'export': {
        await flush(msg.tabId);
        const st = await load(msg.tabId);
        return { analysis: analyze(st.signals), signals: st.signals.map(({ k, v, rt, o }) => ({ k, v, rt, o })), probes: st.probes };
      }
      default:
        return undefined;
    }
  })().then(respond, (e) => respond({ error: String(e) }));
  return true; // async response
});
