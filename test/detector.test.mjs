import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, sanitizeUrl, discoverySignals, discoveryCandidates, summarizeJwt, findJwts } from '../src/detector.js';

// rt: 'nav' = top-level navigation/redirect, 'res' = script/xhr, 'frame' = iframe, 'form', 'disc'
const u = (v, rt = 'nav') => ({ k: 'url', v, rt });
const top = (sigs) => analyze(sigs).results[0];

// ---- REAL fixtures: signals taken from curl recon of the three sites you named (2026-11-21) ----

test('real: openam-mzimny.forgeblocks.com -> PingAM / Advanced Identity Cloud', () => {
  const sigs = [
    u('https://openam-mzimny.forgeblocks.com/'),
    u('https://openam-mzimny.forgeblocks.com/login/'),
    { k: 'dom', v: 'script:https://openam-mzimny.forgeblocks.com/js/chunk-vendors.7dbb5337.js' },
    { k: 'dom', v: 'title:Login' },
    { k: 'hdr', v: 'via: 1.1 google' },
    ...discoverySignals({
      issuer: 'https://openam-mzimny.forgeblocks.com:443/am/oauth2',
      authorization_endpoint: 'https://openam-mzimny.forgeblocks.com:443/am/oauth2/authorize',
      token_endpoint: 'https://openam-mzimny.forgeblocks.com:443/am/oauth2/access_token',
      jwks_uri: 'https://openam-mzimny.forgeblocks.com:443/am/oauth2/connect/jwk_uri',
      userinfo_endpoint: 'https://openam-mzimny.forgeblocks.com:443/am/oauth2/userinfo',
    }),
  ];
  const r = top(sigs);
  assert.equal(r.id, 'pingam');
  assert.equal(r.confidence, 'high');
  assert.equal(r.family, 'Ping Identity');
});

test('real: dock.pingidentity.com (custom domain, 302 -> apps.pingone.com) -> PingOne', () => {
  const env = 'aeb4087d-fbc8-459b-9452-dafaac5a7e2e';
  const sigs = [
    u('https://dock.pingidentity.com/'),
    u(`https://apps.pingone.com/${env}/myapps/`),
    { k: 'dom', v: 'title:PingOne' },
    { k: 'hdr', v: 'server: AmazonS3' },
    ...discoverySignals({
      issuer: `https://auth.pingone.com/${env}/as`,
      authorization_endpoint: `https://auth.pingone.com/${env}/as/authorize`,
      jwks_uri: `https://auth.pingone.com/${env}/as/jwks`,
    }),
  ];
  const r = top(sigs);
  assert.equal(r.id, 'pingone');
  assert.ok(r.score >= 0.95);
});

test('real: my.isc2.org/s/login -> Salesforce (Experience Cloud), NOT Ping/Okta', () => {
  const sigs = [
    u('https://my.isc2.org/s/login/'),
    u('https://my.isc2.org/s/sfsites/auraFW/javascript/abc/aura_prod.js'),
    { k: 'dom', v: 'script:https://salesforcesite.z13.web.core.windows.net/prod/js/session.js' },
    { k: 'hdr', v: 'x-sfdc-trace-flags: 01', o: 'https://my.isc2.org' },
    { k: 'hdr', v: 'server: volt-adc', o: 'https://my.isc2.org' },
    { k: 'cookie', v: 'renderCtx', o: 'https://my.isc2.org' },
    { k: 'cookie', v: 'LSKey-c$CookieConsentPolicy', o: 'https://my.isc2.org' },
    ...discoverySignals({
      issuer: 'https://my.isc2.org',
      authorization_endpoint: 'https://my.isc2.org/services/oauth2/authorize',
      token_endpoint: 'https://my.isc2.org/services/oauth2/token',
      jwks_uri: 'https://my.isc2.org/id/keys',
    }),
  ];
  const { results } = analyze(sigs);
  assert.equal(results[0].id, 'salesforce');
  assert.ok(!results.some((r) => r.id === 'okta' || r.id.startsWith('ping')));
});

test('real: Salesforce works from discovery alone (no page, no headers)', () => {
  const r = top(discoverySignals({
    issuer: 'https://my.isc2.org',
    authorization_endpoint: 'https://my.isc2.org/services/oauth2/authorize',
    jwks_uri: 'https://my.isc2.org/id/keys',
  }));
  assert.equal(r.id, 'salesforce');
});

// ---- SYNTHETIC fixtures (built from vendor docs; NOT yet verified against a live tenant) ----

test('synthetic: Okta authorize + widget', () => {
  const r = top([
    u('https://acme.okta.com/oauth2/default/v1/authorize?client_id&response_type&redirect_uri'),
    { k: 'sel', v: '#okta-sign-in' },
    { k: 'hdr', v: 'x-okta-request-id: abc' },
  ]);
  assert.equal(r.id, 'okta');
});

test('synthetic: Okta on a custom domain, path shape only', () => {
  const r = top([u('https://login.acme.com/oauth2/aus1a2b3c4d5e6f7g8h9/v1/authorize?client_id')]);
  assert.equal(r.id, 'okta');
  assert.equal(r.confidence, 'high');
});

test('synthetic: Auth0 universal login + SDK param', () => {
  const r = top([
    u('https://acme.eu.auth0.com/authorize?client_id&auth0Client&code_challenge'),
    u('https://acme.eu.auth0.com/u/login/identifier'),
  ]);
  assert.equal(r.id, 'auth0');
  assert.equal(r.family, 'Okta');
});

test('synthetic: Keycloak realm path', () => {
  assert.equal(top([u('https://sso.acme.com/realms/main/protocol/openid-connect/auth?client_id')]).id, 'keycloak');
});

test('synthetic: Entra v2 authorize with tenant GUID', () => {
  const r = top([u('https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/authorize?client_id')]);
  assert.equal(r.id, 'entra');
});

test('synthetic: PingFederate endpoints', () => {
  const r = top([u('https://sso.acme.com/as/authorization.oauth2?client_id'), u('https://sso.acme.com/idp/startSSO.ping?PartnerSpId')]);
  assert.equal(r.id, 'pingfederate');
});

test('synthetic: JWT summary alone identifies Cognito and Entra', () => {
  assert.equal(top([{ k: 'jwt', v: { iss: 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_AbC123', alg: 'RS256', claims: ['sub', 'cognito:groups', 'token_use'] } }]).id, 'cognito');
  assert.equal(top([{ k: 'jwt', v: { iss: 'https://login.microsoftonline.com/x/v2.0', alg: 'RS256', claims: ['tid', 'oid', 'ver'] } }]).id, 'entra');
});

// ---- REGRESSIONS from user reports (2026-11-21) ----

// Token built from the CLAIM NAMES of a real bbc.co.uk access token (values here are dummies).
const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const bbcLikeToken = () => `${enc({ alg: 'RS256', kid: 'k1' })}.${enc({
  sub: 'x', cts: 'OAUTH2_STATELESS_GRANT', auth_level: 0, auditTrackingId: 'x',
  iss: 'https://access.api.example.com/idv5/oauth2', tokenName: 'access_token', token_type: 'Bearer',
  authGrantId: 'x', aud: 'Account', acr: '0', azp: 'Account', grant_type: 'refresh_token',
  scope: ['openid'], realm: '/', exp: 1, iat: 1, jti: 'x',
  userAttributes: { postcode: 'SECRET-POSTCODE', displayName: 'SECRET-NAME' },
})}.sig`;

test('regression BBC: ForgeRock AM access token is identified from claim names alone (custom-domain issuer)', () => {
  const v = summarizeJwt(bbcLikeToken());
  const r = top([{ k: 'jwt', v, rt: 'auth', o: 'https://access.api.example.com' }]);
  assert.equal(r.id, 'pingam');
  assert.equal(r.confidence, 'high');
  assert.equal(r.family, 'Ping Identity');
});

// REAL claim names from a PingOne access token (dock.pingidentity.com); issuer deliberately on a
// custom domain to prove the claim rules work without the pingone host.
test('real: PingOne access token identified from claim names alone (custom-domain issuer)', () => {
  const tok = `${enc({ alg: 'RS256', kid: 'k' })}.${enc({
    client_id: 'x', iss: 'https://login.example.com/aeb4087d-fbc8-459b-9452-dafaac5a7e2e/as', jti: 'x', iat: 1, exp: 2,
    aud: ['https://api.pingone.com'], scope: 'openid', sub: 'x', sid: 'x', auth_time: 1, acr: 'x',
    env: 'x', org: 'x', 'p1.rid': 'x',
  })}.sig`;
  const r = top([{ k: 'jwt', v: summarizeJwt(tok), rt: 'auth', o: 'https://api.pingone.com' }]);
  assert.equal(r.id, 'pingone');
  assert.equal(r.confidence, 'high');
});

test('real: PingOne token with the pingone.com issuer scores near-certain, and is NOT mistaken for AM/Okta', () => {
  const tok = `${enc({ alg: 'RS256' })}.${enc({
    iss: 'https://auth.pingone.com/aeb4087d-fbc8-459b-9452-dafaac5a7e2e/as', env: 'x', org: 'x', sid: 'x', 'p1.rid': 'x', scope: 'openid',
  })}.s`;
  const { results } = analyze([{ k: 'jwt', v: summarizeJwt(tok), rt: 'auth', o: 'https://api.pingone.com' }]);
  assert.equal(results[0].id, 'pingone');
  assert.ok(results[0].score >= 0.98);
  assert.ok(!results.some((r) => r.id === 'pingam' || r.id === 'okta'));
});

test('summarizeJwt keeps only iss/alg/kid/claim NAMES - no claim values survive', () => {
  const v = summarizeJwt(bbcLikeToken());
  assert.equal(v.iss, 'https://access.api.example.com/idv5/oauth2');
  assert.ok(v.claims.includes('userAttributes'));
  assert.ok(!JSON.stringify(v).includes('SECRET'));
  assert.equal(summarizeJwt('not.a.jwt'), null);
});

test('findJwts finds a token inside a header / cookie string', () => {
  const t = bbcLikeToken();
  assert.deepEqual(findJwts(`Bearer ${t}`), [t]);
  assert.deepEqual(findJwts('no token here'), []);
});

test('regression Lloyds: lone x-sfdc header from a third-party origin is NOT an IdP verdict', () => {
  const { results, present } = analyze([
    u('https://online.lloydsbank.co.uk/personal/logon/login.jsp'),
    { k: 'hdr', v: 'x-sfdc-trace-flags: 01', o: 'https://chat.my.salesforce.com' },
  ]);
  assert.deepEqual(results, []);
  assert.equal(present[0].id, 'salesforce');
  assert.equal(present[0].evidence[0].onLoginOrigin, false);
});

test('regression Lloyds: even same-origin x-sfdc header alone (no flow evidence) is only "present"', () => {
  const { results, present } = analyze([
    u('https://online.lloydsbank.co.uk/personal/logon/login.jsp'),
    { k: 'hdr', v: 'x-sfdc-trace-flags: 01', o: 'https://online.lloydsbank.co.uk' },
  ]);
  assert.deepEqual(results, []);
  assert.equal(present[0].id, 'salesforce');
});

test('regression NatWest: lone x-ms-request-id (generic Azure header) gives nothing at all', () => {
  const r = analyze([
    u('https://www.onlinebanking.natwest.com/login'),
    { k: 'hdr', v: 'x-ms-request-id: abfc0743-201e-0010-7e24-34a56c000000', o: 'https://www.onlinebanking.natwest.com' },
  ]);
  assert.deepEqual(r.results, []);
  assert.deepEqual(r.present, []);
});

test('third-party script / xhr / iframe to a vendor host is "present", never the IdP', () => {
  for (const rt of ['res', 'frame']) {
    const { results, present } = analyze([
      u('https://bank.example/login'),
      u('https://acme.my.salesforce.com/services/oauth2/token', rt),
      u('https://acme.okta.com/oauth2/default/v1/token', rt),
    ]);
    assert.deepEqual(results, [], `rt=${rt}`);
    assert.ok(present.some((p) => p.id === 'salesforce'), `rt=${rt}`);
  }
});

test('ambient evidence from a login origin RAISES a vendor that already has flow evidence', () => {
  const flowOnly = top([u('https://acme.okta.com/login/login.htm')]).score;
  const withAmbient = top([
    u('https://acme.okta.com/login/login.htm'),
    { k: 'hdr', v: 'x-okta-request-id: abc', o: 'https://acme.okta.com' },
  ]).score;
  assert.ok(withAmbient > flowOnly);
});

test('ambient evidence from a NON-login origin does not raise the score', () => {
  const flowOnly = top([u('https://acme.okta.com/login/login.htm')]).score;
  const other = top([
    u('https://acme.okta.com/login/login.htm'),
    { k: 'hdr', v: 'x-okta-request-id: abc', o: 'https://tracker.example' },
  ]).score;
  assert.equal(other, flowOnly);
});

test('login widget selector on the page counts as flow evidence', () => {
  const r = top([{ k: 'sel', v: '#okta-sign-in', o: 'https://login.acme.com' }]);
  assert.equal(r.id, 'okta');
});

// ---- SDK storage keys + page globals (ambient: never a verdict on their own) ----

const PAGE = 'https://app.example.com';
const nav = u('https://app.example.com/login');

test('SDK storage keys identify the vendor as "present" but never as the IdP alone', () => {
  const cases = [
    ['okta-token-storage', 'okta'], ['okta-cache-storage', 'okta'],
    ['@@auth0spajs@@::CLIENT::aud::openid', 'auth0'], ['a0.spajs.txs.CLIENT', 'auth0'],
    ['CognitoIdentityServiceProvider.abc.user.idToken', 'cognito'],
    ['msal.token.keys.abc', 'entra'], ['kc-callback-1234', 'keycloak'],
  ];
  for (const [key, id] of cases) {
    const { results, present } = analyze([nav, { k: 'store', v: key, o: PAGE }]);
    assert.deepEqual(results, [], key);
    assert.equal(present[0]?.id, id, key);
  }
});

test('page globals from the MAIN-world probe: present, not a verdict', () => {
  for (const [g, id] of [['OktaSignIn', 'okta'], ['Auth0Lock', 'auth0'], ['auth0.WebAuth', 'auth0'],
    ['msal.PublicClientApplication', 'entra'], ['Keycloak', 'keycloak'], ['AmazonCognitoIdentity', 'cognito']]) {
    const { results, present } = analyze([nav, { k: 'glob', v: g, o: PAGE }]);
    assert.deepEqual(results, [], g);
    assert.equal(present[0]?.id, id, g);
  }
});

test('SDK evidence RAISES a vendor that already has flow evidence', () => {
  const flow = [u('https://acme.okta.com/oauth2/default/v1/authorize?client_id')];
  const base = top(flow).score;
  const boosted = top([...flow, { k: 'store', v: 'okta-token-storage', o: PAGE }, { k: 'glob', v: 'OktaAuth', o: PAGE }]).score;
  assert.ok(boosted > base);
});

test('REGRESSION (other plugin): substring look-alikes match NOTHING', () => {
  const junk = [
    'taggingMappingSession', 'shopping-cart', 'mapping', 'enforce-policy', 'workforce', 'fr-FR',
    'forge-wrapper', 'oktane-banner', 'amazonaws-config', 'duo-lingo', 'ibm-id-x', 'safe-session', 'op-state',
  ];
  const { results, present } = analyze([
    nav,
    ...junk.map((v) => ({ k: 'store', v, o: PAGE })),
    ...junk.map((v) => ({ k: 'dom', v: `script:https://app.example.com/${v}.js`, o: PAGE })),
    ...junk.map((v) => ({ k: 'cookie', v, o: PAGE })),
    ...['Ping', 'fr', 'op', 'CA', 'IBM', 'authn', 'duo', 'okta', 'adfs'].map((v) => ({ k: 'glob', v, o: PAGE })),
  ]);
  assert.deepEqual(results, []);
  assert.deepEqual(present, []);
});

test('GLOBALS allowlist is derived from the table and contains only distinctive names', async () => {
  const { GLOBALS } = await import('../src/signatures.js');
  assert.ok(GLOBALS.includes('OktaSignIn') && GLOBALS.includes('Keycloak'));
  for (const bad of ['Ping', 'fr', 'op', 'CA', 'IBM', 'authn', 'duo', 'okta', 'adfs']) assert.ok(!GLOBALS.includes(bad), bad);
});

// ---- guards / privacy ----

test('no false positive from generic signals', () => {
  assert.deepEqual(analyze([
    { k: 'cookie', v: 'JSESSIONID' }, { k: 'hdr', v: 'server: nginx' }, u('https://example.com/login'),
  ]).results, []);
});

test('sanitizeUrl keeps param NAMES only and drops fragment', () => {
  const s = sanitizeUrl('https://x.com/a/b?code=SECRET&state=ALSO&code=again#access_token=TOK');
  assert.equal(s, 'https://x.com/a/b?code&state');
  assert.ok(!/SECRET|ALSO|TOK/.test(s));
  assert.equal(sanitizeUrl('chrome://settings'), null);
});

test('detects protocols from param names', () => {
  assert.deepEqual(analyze([u('https://i.com/sso?SAMLRequest&RelayState')]).protocols, ['SAML']);
  assert.ok(analyze([u('https://i.com/authorize?client_id&response_type')]).protocols.includes('OIDC / OAuth2'));
});

test('discoveryCandidates: origin + base of authorize-style endpoints, https only, capped', () => {
  const c = discoveryCandidates('https://app.acme.com/home', [
    u('https://auth.pingone.com/aeb4087d-fbc8-459b-9452-dafaac5a7e2e/as/authorize?client_id'),
    u('https://acme.okta.com/oauth2/default/v1/authorize?client_id'),
    u('http://insecure.example/authorize'),
  ]);
  assert.ok(c.includes('https://auth.pingone.com/aeb4087d-fbc8-459b-9452-dafaac5a7e2e/as/.well-known/openid-configuration'));
  assert.ok(c.includes('https://acme.okta.com/oauth2/default/.well-known/openid-configuration'));
  assert.ok(c.includes('https://app.acme.com/.well-known/openid-configuration'));
  assert.ok(!c.some((x) => x.startsWith('http://')));
});
