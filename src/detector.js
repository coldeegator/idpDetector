// Pure detection logic: no chrome.* APIs, so it runs in the service worker AND in node tests.
import { VENDORS } from './signatures.js';

/** origin + path + '?' + query PARAM NAMES. Values (codes, tokens, state) are never kept. */
export function sanitizeUrl(u) {
  try {
    const x = new URL(u);
    if (!/^https?:$/.test(x.protocol)) return null;
    const names = [...new Set([...x.searchParams.keys()])];
    return x.origin + x.pathname + (names.length ? '?' + names.join('&') : '');
  } catch {
    return null;
  }
}

const JWT_RE = /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;

/** Find JWT-looking strings inside arbitrary text (URL, storage value, cookie, header). */
export function findJwts(text, max = 5) {
  if (typeof text !== 'string' || text.length > 200000) return [];
  return (text.match(JWT_RE) || []).slice(0, max);
}

function b64json(s) {
  try {
    const b = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b + '==='.slice((b.length + 3) % 4));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch { return null; }
}

/**
 * THE one JWT decoder. Returns {iss, alg, kid, claims:[names]} or null.
 * Only the issuer, alg, kid and claim NAMES survive: the raw token and every claim value
 * (names, postcodes, ids...) are discarded here and never stored.
 */
export function summarizeJwt(token) {
  if (typeof token !== 'string') return null;
  const [h, p] = token.split('.');
  const header = b64json(h || '');
  const payload = b64json(p || '');
  if (!header || !payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  return {
    iss: typeof payload.iss === 'string' ? payload.iss.slice(0, 300) : undefined,
    alg: typeof header.alg === 'string' ? header.alg : undefined,
    kid: typeof header.kid === 'string' ? header.kid.slice(0, 80) : undefined,
    claims: Object.keys(payload).slice(0, 60),
  };
}

/** Signals for an OIDC discovery document (issuer + endpoint URLs). */
export function discoverySignals(doc) {
  const out = [];
  if (typeof doc?.issuer === 'string') out.push({ k: 'issuer', v: doc.issuer, rt: 'disc' });
  for (const f of [
    'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint',
    'end_session_endpoint', 'introspection_endpoint', 'registration_endpoint',
    'revocation_endpoint', 'pushed_authorization_request_endpoint',
  ]) {
    const s = typeof doc?.[f] === 'string' ? sanitizeUrl(doc[f]) : null;
    if (s) out.push({ k: 'url', v: s, rt: 'disc' });
  }
  return out;
}

/**
 * Which /.well-known/openid-configuration URLs are worth probing for this tab:
 * the tab's origin, plus the base path of any authorize-style endpoint already observed.
 * Only https, only hosts the user's own browser already talked to, capped.
 */
export function discoveryCandidates(tabUrl, signals, cap = 6) {
  const out = new Set();
  const add = (base) => out.add(base.replace(/\/+$/, '') + '/.well-known/openid-configuration');
  const origins = new Set();
  try { origins.add(new URL(tabUrl).origin); } catch { /* ignore */ }
  for (const s of signals) {
    if (s.k !== 'url') continue;
    let u;
    try { u = new URL(s.v); } catch { continue; }
    if (u.protocol !== 'https:') continue;
    const p = u.pathname;
    let m;
    if ((m = p.match(/^(.*)\/protocol\/openid-connect\/auth$/))) add(u.origin + m[1]);
    else if ((m = p.match(/^(.*)\/oauth2\/v2\.0\/authorize$/))) add(u.origin + m[1] + '/v2.0');
    else if ((m = p.match(/^(.*\/oauth2)\/authorize$/))) { add(u.origin + m[1]); add(u.origin + m[1].replace(/\/oauth2$/, '')); }
    else if ((m = p.match(/^(.*)\/v1\/authorize$/))) add(u.origin + m[1]);
    else if ((m = p.match(/^(.*)\/authorize$/))) add(u.origin + m[1]);
  }
  for (const o of origins) add(o);
  return [...out].filter((u) => u.startsWith('https://')).slice(0, cap);
}

const rulesMatch = (rule, val) => {
  if (rule.k === 'jwt') return typeof val === 'object' && !!val && !!rule.fn(val);
  if (typeof val !== 'string') return false;
  if (rule.eq !== undefined) return val === rule.eq;
  return rule.re.test(val);
};

function describe(val) {
  if (typeof val === 'string') return val.length > 140 ? val.slice(0, 140) + '…' : val;
  return `JWT iss=${val.iss ?? '?'} alg=${val.alg ?? '?'} claims=[${(val.claims || []).slice(0, 12).join(',')}]`;
}

function detectProtocols(urls) {
  const p = new Set();
  const all = urls.join('\n');
  if (/[?&]SAML(Request|Response)\b|\/saml2?\b|\.saml2\b|\/samlp\//i.test(all)) p.add('SAML');
  if (/[?&](client_id|response_type|code_challenge|redirect_uri)\b|\/\.well-known\/openid-configuration|\/oauth2?\//i.test(all)) p.add('OIDC / OAuth2');
  if (/[?&](wa|wresult|wtrealm)\b|\/wsfed\//i.test(all)) p.add('WS-Federation');
  return [...p];
}

const originOf = (u) => { try { return new URL(u).origin; } catch { return null; } };
const hostOf = (u) => { try { return new URL(u).host; } catch { return u; } };

// Resource types that count as "the login flow itself": a top-level navigation or redirect
// (nav), a form post target (form) or an OIDC discovery document the user probed (disc).
const FLOW_RT = new Set(['nav', 'form', 'disc']);

/**
 * Does this matching signal prove the vendor takes part in the login FLOW (as opposed to merely
 * being somewhere on the page)?
 *  - issuer / jwt: yes (an issuer is by definition the token authority)
 *  - sel: yes unless the rule says otherwise (login widget markup on the page)
 *  - url: yes if it is a navigation/redirect/form/discovery, or lives on an origin the tab
 *         actually navigated to; a script/xhr/iframe to a vendor host does NOT qualify
 *  - hdr / cookie / dom: never (ambient evidence)
 */
function isFlow(rule, s, loginOrigins) {
  switch (rule.k) {
    case 'issuer': case 'jwt': return true;
    case 'sel': return rule.flow !== false;
    case 'url': return rule.flow !== false && (FLOW_RT.has(s.rt) || loginOrigins.has(originOf(s.v)));
    default: return false;
  }
}

/** Ambient evidence only counts toward the IdP score if it came from a login origin. */
function ambientOnLogin(rule, s, loginOrigins) {
  if (rule.k === 'hdr' || rule.k === 'cookie') return loginOrigins.has(s.o);
  if (rule.k === 'url') return loginOrigins.has(originOf(s.v));
  return ['dom', 'sel', 'store', 'glob'].includes(rule.k); // page-level, always the top page
}

const noisyOr = (hits) => Math.min(0.99, 1 - hits.reduce((m, h) => m * (1 - h.rule.w), 1));

function evidenceOf(h, onLogin) {
  const from = h.s.k === 'url' ? hostOf(h.s.v) : h.s.o ? hostOf(h.s.o) : undefined;
  return {
    note: h.rule.note, kind: h.rule.k, sample: describe(h.s.v), w: h.rule.w,
    from, flow: h.flow, onLoginOrigin: onLogin,
  };
}

/**
 * analyze(signals) -> { results, present, protocols, loginOrigins }
 *
 * results  = vendors with FLOW evidence = candidate IdPs, scored (noisy-OR over flow evidence
 *            plus ambient evidence from login origins). Ambient evidence from other origins is
 *            ignored for the score.
 * present  = vendors seen only as ambient/third-party evidence ("on this page", not confirmed
 *            as the IdP). No score is shown for these on purpose.
 */
export function analyze(signals) {
  // Login origins: where the tab actually navigated (incl. redirect chain) + the top page.
  const loginOrigins = new Set();
  for (const s of signals) {
    if (s.k === 'url' && s.rt === 'nav') { const o = originOf(s.v); if (o) loginOrigins.add(o); }
    if ((s.k === 'dom' || s.k === 'sel') && s.o) loginOrigins.add(s.o);
  }

  const all = [...signals];
  for (const s of signals) {
    if (s.k === 'jwt' && typeof s.v?.iss === 'string') all.push({ k: 'issuer', v: s.v.iss, rt: 'jwt' });
  }
  const byKind = {};
  for (const s of all) (byKind[s.k] ||= []).push(s);

  const results = [];
  const present = [];
  for (const [id, vendor] of Object.entries(VENDORS)) {
    const flow = []; const ambient = []; const other = [];
    for (const rule of vendor.rules) {
      const matches = (byKind[rule.k] || []).filter((s) => rulesMatch(rule, s.v));
      if (!matches.length) continue;
      const f = matches.find((s) => isFlow(rule, s, loginOrigins));
      if (f) { flow.push({ rule, s: f, flow: true }); continue; }
      const a = matches.find((s) => ambientOnLogin(rule, s, loginOrigins));
      if (a) ambient.push({ rule, s: a, flow: false });
      else other.push({ rule, s: matches[0], flow: false });
    }
    const base = { id, name: vendor.name, family: vendor.family };
    if (flow.length) {
      const counted = [...flow, ...ambient];
      const score = noisyOr(counted);
      if (score < 0.2) continue;
      results.push({
        ...base, score,
        confidence: score >= 0.8 ? 'high' : score >= 0.5 ? 'medium' : 'low',
        evidence: [...flow.map((h) => evidenceOf(h, true)), ...ambient.map((h) => evidenceOf(h, true))]
          .sort((a, b) => b.w - a.w),
      });
    } else if (ambient.length || other.length) {
      present.push({
        ...base,
        evidence: [...ambient.map((h) => evidenceOf(h, true)), ...other.map((h) => evidenceOf(h, false))]
          .sort((a, b) => b.w - a.w),
      });
    }
  }
  results.sort((a, b) => b.score - a.score);
  present.sort((a, b) => b.evidence.length - a.evidence.length);
  return {
    results, present,
    protocols: detectProtocols((byKind.url || []).map((s) => s.v)),
    loginOrigins: [...loginOrigins],
  };
}
