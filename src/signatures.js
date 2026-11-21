// Vendor signature table. Pure data (plus tiny predicates) - no chrome APIs, so it is
// shared by the service worker, the popup and the node tests.
//
// Signal kinds a rule can target (k):
//   url      sanitized URL: origin + path + '?' + query PARAM NAMES (never values)
//   issuer   OIDC issuer (from discovery doc or a decoded JWT's `iss`)
//   hdr      response header, lowercased "name: value" (set-cookie excluded)
//   cookie   cookie NAME only (never the value)
//   dom      "script:<url>" | "link:<url>" | "title:<text>" | "form:<url>" | "input:<name>"
//   sel      a CSS selector from this table that matched in the page
//   store    web-storage KEY NAME (localStorage/sessionStorage); values are never read or kept
//   glob     a page global (dotted path) from this table that exists in the page's own JS world
//   jwt      decoded token summary {iss, alg, kid, claims:[names]} - fn(v) predicate
//
// A rule fires at most once per vendor; scores combine as noisy-OR: 1 - prod(1 - w).
// Weights: .9 = vendor-owned host / unique header, .5-.8 = strong shape, <=.4 = weak hint.
//
// FLOW vs AMBIENT (see detector.js): a vendor only becomes the IdP verdict if at least one hit is
// FLOW evidence (navigation/redirect/form/discovery URL, issuer, JWT, login-widget selector).
// Headers, cookies and asset URLs are ambient: they raise the score of a vendor that already has
// flow evidence (only if they came from a login origin) but alone only list it under
// "other vendors on this page". Set `flow: false` on a url/sel rule that is a page-framework
// marker rather than a login-protocol marker.
// Do NOT add generic cloud-platform headers (x-ms-request-id, x-amz-*, via) as rules.

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const has = (v, ...names) => names.every((n) => v.claims?.includes(n));
const hasAny = (v, ...names) => names.some((n) => v.claims?.includes(n));

export const VENDORS = {
  pingone: {
    name: 'PingOne',
    family: 'Ping Identity',
    rules: [
      { k: 'url', re: /^https?:\/\/[^/]*\.pingone\.(com|eu|asia|ca|com\.au|sg)(\/|$)/i, w: 0.9, note: 'PingOne host (*.pingone.*)' },
      { k: 'url', re: new RegExp(`\\/${UUID}\\/(as|signon|myapps)\\b`, 'i'), w: 0.45, note: 'PingOne /{envId}/as|signon|myapps path' },
      { k: 'issuer', re: /^https?:\/\/[^/]*\.pingone\./i, w: 0.9, note: 'Issuer on pingone host' },
      { k: 'dom', re: /^title:.*PingOne/i, w: 0.4, note: 'Page title mentions PingOne' },
      { k: 'dom', re: /^(script|link):[^ ]*pingone\./i, w: 0.5, note: 'Assets loaded from pingone host' },
      { k: 'cookie', re: /^ST-NO-SS$/, w: 0.25, note: 'PingOne session-state cookie' },
      // Claim names taken from a real PingOne access token (dock.pingidentity.com, 2026-11-21).
      // Work on custom domains whose issuer is not on *.pingone.*.
      { k: 'jwt', fn: (v) => hasAny(v, 'p1.rid'), w: 0.85, note: 'JWT claim p1.rid (PingOne)' },
      { k: 'jwt', fn: (v) => has(v, 'env', 'org', 'sid'), w: 0.75, note: 'JWT claims env+org+sid (PingOne environment/org IDs)' },
    ],
  },
  pingfederate: {
    name: 'PingFederate',
    family: 'Ping Identity',
    rules: [
      { k: 'url', re: /\/as\/(authorization\.oauth2|token\.oauth2|jwks|revoke_token\.oauth2|introspect\.oauth2)\b/i, w: 0.8, note: 'PingFederate /as/*.oauth2 endpoint' },
      { k: 'url', re: /\/idp\/(startSSO|SSO)\.(ping|saml2)/i, w: 0.9, note: 'PingFederate /idp/startSSO.ping|SSO.saml2' },
      { k: 'url', re: /\/sp\/(startSSO\.ping|ACS\.saml2)/i, w: 0.7, note: 'PingFederate SP endpoint' },
      { k: 'url', re: /[?&](pfidpadapterid|pf\.adapterid|pf\.username)\b/i, w: 0.7, note: 'PingFederate adapter parameter' },
      { k: 'cookie', re: /^(PF|PF\.ADMIN|PF-AUTH)$/, w: 0.35, note: 'PingFederate session cookie' },
      { k: 'dom', re: /^(script|link):[^ ]*pingfederate/i, w: 0.5, note: 'PingFederate assets' },
    ],
  },
  pingam: {
    name: 'PingAM / Advanced Identity Cloud (ex-ForgeRock)',
    family: 'Ping Identity',
    rules: [
      { k: 'url', re: /^https?:\/\/[^/]*\.forgeblocks\.com(\/|$)/i, w: 0.9, note: 'forgeblocks.com (PingOne Advanced Identity Cloud)' },
      { k: 'url', re: /\/(am|openam)\/(oauth2|json|XUI|UI)\b/i, w: 0.55, note: 'AM path (/am|/openam + oauth2|json|XUI)' },
      { k: 'url', re: /\/oauth2\/connect\/jwk_uri/i, w: 0.8, note: 'AM-specific JWKS path (connect/jwk_uri)' },
      { k: 'issuer', re: /\/(am|openam)\/oauth2(\/[^/]+)?$/i, w: 0.6, note: 'Issuer shaped like /am/oauth2[/realm]' },
      { k: 'cookie', re: /^(iPlanetDirectoryPro|amlbcookie)$/, w: 0.8, note: 'AM session/lb cookie' },
      // AM access/ID tokens carry AM-internal claims that no other IdP emits. These work on custom
      // domains whose issuer has no /am/ in the path (e.g. https://access.api.example/idv5/oauth2).
      { k: 'jwt', fn: (v) => has(v, 'cts', 'tokenName'), w: 0.9, note: 'JWT claims cts+tokenName (AM token store)' },
      { k: 'jwt', fn: (v) => hasAny(v, 'auditTrackingId', 'authGrantId'), w: 0.8, note: 'JWT claim auditTrackingId / authGrantId (AM)' },
      { k: 'jwt', fn: (v) => has(v, 'realm', 'auth_level'), w: 0.6, note: 'JWT claims realm+auth_level (AM realm model)' },
      { k: 'dom', re: /^(script|link):[^ ]*(forgerock|forgeblocks)/i, w: 0.5, note: 'ForgeRock/forgeblocks assets' },
    ],
  },
  okta: {
    name: 'Okta',
    family: 'Okta',
    rules: [
      { k: 'url', re: /^https?:\/\/[^/]*\.(okta|oktapreview|okta-emea|okta-gov)\.com(\/|$)/i, w: 0.9, note: 'Okta host' },
      { k: 'url', re: /\/oauth2\/(default|aus[a-z0-9]{8,})\/v1\/(authorize|token|keys|userinfo)|\/oauth2\/v1\/(authorize|token|keys)/i, w: 0.8, note: 'Okta /oauth2/{server}/v1/* endpoint' },
      { k: 'url', re: /\/app\/[a-z0-9_]+\/exk[a-z0-9]+\/sso\/saml/i, w: 0.8, note: 'Okta SAML SSO path (/app/*/exk*/sso/saml)' },
      { k: 'url', re: /\/(login\/(login\.htm|sessionCookieRedirect)|idp\/idx\/|api\/v1\/authn)/i, w: 0.6, note: 'Okta login/IDX/authn endpoint' },
      { k: 'issuer', re: /\.okta(preview|-emea|-gov)?\.com|\/oauth2\/(default|aus[a-z0-9]{8,})$/i, w: 0.9, note: 'Okta-shaped issuer' },
      { k: 'sel', eq: '#okta-sign-in', w: 0.8, note: 'Okta Sign-In Widget container' },
      { k: 'sel', eq: '[data-se="o-form-input-container"]', w: 0.7, note: 'Okta form data-se attribute' },
      { k: 'dom', re: /^(script|link):[^ ]*(okta-signin-widget|okta-auth-js|oktacdn\.com)/i, w: 0.8, note: 'Okta widget / SDK / CDN asset' },
      { k: 'cookie', re: /^(oktaStateToken|okta-oauth-state|okta-oauth-nonce|okta-oauth-redirect-params)$/, w: 0.7, note: 'Okta auth-js cookie' },
      { k: 'hdr', re: /^x-okta-request-id:/, w: 0.9, note: 'x-okta-request-id header' },
      { k: 'store', re: /^okta-(token|cache|shared-transaction|original-uri)-storage$/, w: 0.8, note: 'Okta auth-js storage key' },
      { k: 'glob', eq: 'OktaSignIn', w: 0.8, note: 'window.OktaSignIn (Sign-In Widget)' },
      { k: 'glob', eq: 'OktaAuth', w: 0.7, note: 'window.OktaAuth (okta-auth-js)' },
      { k: 'dom', re: /^(script|link):[^ ]*\/@okta\//i, w: 0.7, note: '@okta/ package asset' },
      { k: 'jwt', fn: (v) => has(v, 'cid', 'scp') || has(v, 'uid', 'ver', 'cid'), w: 0.5, note: 'JWT claims cid+scp / uid+ver+cid (Okta access token)' },
    ],
  },
  auth0: {
    name: 'Auth0',
    family: 'Okta',
    rules: [
      { k: 'url', re: /^https?:\/\/[^/]*\.auth0\.com(\/|$)/i, w: 0.9, note: 'auth0.com host (incl. regional)' },
      { k: 'url', re: /\/u\/(login|signup|mfa-[a-z-]+|reset-password|consent|email-verification)/i, w: 0.6, note: 'Auth0 Universal Login /u/* path' },
      { k: 'url', re: /\/samlp\//i, w: 0.6, note: 'Auth0 SAML /samlp/ endpoint' },
      { k: 'url', re: /\/oauth\/token(\?|$)|\/v2\/logout/i, w: 0.3, note: 'Auth0-style /oauth/token or /v2/logout' },
      { k: 'url', re: /[?&]auth0Client\b/i, w: 0.8, note: 'auth0Client query param (auth0 SDKs)' },
      { k: 'issuer', re: /\.auth0\.com\/$/i, w: 0.9, note: 'Issuer on auth0.com with trailing slash' },
      { k: 'issuer', re: /^https:\/\/[^/]+\/$/i, w: 0.15, note: 'Issuer is bare origin + trailing slash (Auth0 custom-domain style)' },
      { k: 'cookie', re: /^(auth0(_compat)?|did(_compat)?|auth0\.is\.authenticated|_legacy_auth0\..*)$/, w: 0.5, note: 'Auth0 cookie (auth0 / did / auth0.is.authenticated)' },
      { k: 'sel', eq: '.auth0-lock', w: 0.8, note: 'Auth0 Lock widget' },
      { k: 'sel', eq: '#auth0-lock-container', w: 0.8, note: 'Auth0 Lock container' },
      { k: 'dom', re: /^(script|link):[^ ]*(cdn\.auth0\.com|auth0-spa-js|auth0-lock|auth0\.min)/i, w: 0.8, note: 'Auth0 SDK / CDN asset' },
      { k: 'hdr', re: /^x-auth0-requestid:/, w: 0.9, note: 'x-auth0-requestid header' },
      { k: 'store', re: /^(@@auth0spajs@@|a0\.spajs\.)/, w: 0.8, note: 'auth0-spa-js storage key' },
      { k: 'glob', eq: 'auth0.WebAuth', w: 0.8, note: 'window.auth0.WebAuth (auth0-js)' },
      { k: 'glob', eq: 'Auth0Lock', w: 0.8, note: 'window.Auth0Lock' },
      { k: 'glob', eq: 'createAuth0Client', w: 0.7, note: 'window.createAuth0Client (auth0-spa-js)' },
      { k: 'glob', eq: 'auth0.createAuth0Client', w: 0.7, note: 'window.auth0.createAuth0Client (auth0-spa-js)' },
      { k: 'dom', re: /^(script|link):[^ ]*\/@auth0\//i, w: 0.7, note: '@auth0/ package asset' },
    ],
  },
  entra: {
    name: 'Microsoft Entra ID / ADFS',
    family: 'Microsoft',
    rules: [
      { k: 'url', re: /^https?:\/\/login\.(microsoftonline\.(com|us|de)|microsoft\.com|windows\.net)(\/|$)/i, w: 0.9, note: 'Microsoft login host' },
      { k: 'url', re: /^https?:\/\/[^/]*\.b2clogin\.com(\/|$)/i, w: 0.9, note: 'Azure AD B2C host' },
      { k: 'url', re: new RegExp(`\\/${UUID}\\/(oauth2\\/(v2\\.0\\/)?(authorize|token)|saml2|wsfed)`, 'i'), w: 0.5, note: 'Tenant-GUID OAuth/SAML path' },
      { k: 'url', re: /\/adfs\/(ls|oauth2|services)\b/i, w: 0.9, note: 'ADFS endpoint (/adfs/ls|oauth2)' },
      { k: 'issuer', re: /login\.microsoftonline\.com|sts\.windows\.net|\/adfs$/i, w: 0.9, note: 'Microsoft issuer' },
      { k: 'cookie', re: /^(ESTSAUTH|ESTSAUTHPERSISTENT|ESTSAUTHLIGHT|esctx|buid|fpc|x-ms-gateway-slice)$/, w: 0.7, note: 'Entra ESTS cookie' },
      { k: 'hdr', re: /^x-ms-ests-server:/, w: 0.85, note: 'x-ms-ests-server header' },
      { k: 'store', re: /^msal\.|-login\.windows\.net-|-login\.microsoftonline\.com-/i, w: 0.75, note: 'MSAL cache key' },
      { k: 'glob', eq: 'msal.PublicClientApplication', w: 0.8, note: 'window.msal.PublicClientApplication (msal-browser)' },
      { k: 'dom', re: /^(script|link):[^ ]*(msal-browser|msal-react|msal\.js|@azure\/msal)/i, w: 0.7, note: 'MSAL library asset' },
      { k: 'jwt', fn: (v) => has(v, 'tid', 'oid') || has(v, 'tid', 'ver'), w: 0.7, note: 'JWT claims tid+oid / tid+ver (Entra)' },
    ],
  },
  cognito: {
    name: 'AWS Cognito',
    family: 'AWS',
    rules: [
      { k: 'url', re: /\.auth\.[a-z0-9-]+\.amazoncognito\.com(\/|$)/i, w: 0.9, note: 'Cognito hosted UI host' },
      { k: 'url', re: /cognito-idp\.[a-z0-9-]+\.amazonaws\.com/i, w: 0.9, note: 'cognito-idp API host' },
      { k: 'url', re: /\/oauth2\/idpresponse/i, w: 0.6, note: 'Cognito /oauth2/idpresponse' },
      { k: 'issuer', re: /cognito-idp\.[a-z0-9-]+\.amazonaws\.com\/[a-z0-9-]+_[A-Za-z0-9]+/i, w: 0.9, note: 'Cognito user-pool issuer' },
      { k: 'cookie', re: /^(cognito|CognitoIdentityServiceProvider\.)/i, w: 0.5, note: 'Cognito cookie' },
      { k: 'store', re: /^CognitoIdentityServiceProvider\./, w: 0.85, note: 'Cognito SDK storage key' },
      { k: 'store', re: /^amplify-signin-with-hostedUI$/, w: 0.6, note: 'Amplify hosted-UI storage key' },
      { k: 'glob', eq: 'AmazonCognitoIdentity', w: 0.7, note: 'window.AmazonCognitoIdentity' },
      { k: 'glob', eq: 'AWSCognito', w: 0.7, note: 'window.AWSCognito' },
      { k: 'jwt', fn: (v) => hasAny(v, 'cognito:username', 'cognito:groups') || has(v, 'token_use'), w: 0.8, note: 'JWT claims cognito:* / token_use' },
    ],
  },
  keycloak: {
    name: 'Keycloak (Red Hat SSO)',
    family: 'Open source',
    rules: [
      { k: 'url', re: /\/realms\/[^/]+\/protocol\/(openid-connect|saml)/i, w: 0.9, note: 'Keycloak /realms/{r}/protocol/* path' },
      { k: 'url', re: /\/resources\/[a-z0-9]+\/login\/(keycloak|keycloak\.v2)/i, w: 0.8, note: 'Keycloak login theme resources' },
      { k: 'issuer', re: /\/realms\/[^/]+$/i, w: 0.8, note: 'Issuer shaped like /realms/{realm}' },
      { k: 'cookie', re: /^(KEYCLOAK_(IDENTITY|SESSION)(_LEGACY)?|AUTH_SESSION_ID(_LEGACY)?|KC_RESTART|KC_AUTH_SESSION_HASH)$/, w: 0.9, note: 'Keycloak cookie' },
      { k: 'sel', eq: '#kc-form-login', w: 0.8, note: 'Keycloak login form (#kc-form-login)' },
      { k: 'store', re: /^kc-callback-/, w: 0.85, note: 'keycloak-js callback storage key' },
      { k: 'glob', eq: 'Keycloak', w: 0.7, note: 'window.Keycloak (keycloak-js)' },
      { k: 'dom', re: /^(script|link):[^ ]*keycloak/i, w: 0.6, note: 'keycloak-js / keycloak assets' },
      { k: 'jwt', fn: (v) => hasAny(v, 'realm_access', 'resource_access'), w: 0.7, note: 'JWT claims realm_access/resource_access' },
    ],
  },
  salesforce: {
    name: 'Salesforce (Experience Cloud / Identity)',
    family: 'Salesforce',
    rules: [
      { k: 'url', re: /^https?:\/\/[^/]*\.(my\.salesforce|lightning\.force|force|salesforce|my\.site|salesforce-sites)\.com(\/|$)|^https?:\/\/(login|test)\.salesforce\.com/i, w: 0.9, note: 'Salesforce host' },
      { k: 'url', re: /\/services\/(oauth2|auth\/(idp|sp))\//i, w: 0.8, note: 'Salesforce /services/oauth2|auth endpoint' },
      { k: 'url', re: /\/id\/keys(\?|$)/i, w: 0.4, note: 'Salesforce JWKS path (/id/keys)' },
      { k: 'url', re: /\/s\/sfsites\/|\/auraFW\/|\/sfsites\/aura/i, w: 0.7, flow: false, note: 'Experience Cloud / Aura framework path' },
      { k: 'url', re: /\/s\/login\/?(\?|$)/i, w: 0.25, flow: false, note: 'Experience Cloud /s/login' },
      { k: 'issuer', re: /salesforce\.com|force\.com/i, w: 0.7, note: 'Issuer on salesforce host' },
      { k: 'hdr', re: /^x-sfdc-(trace-flags|request-id):/, w: 0.9, note: 'x-sfdc-* header' },
      { k: 'hdr', re: /^server: (sfdcedge|sfdc)/, w: 0.8, note: 'Server: sfdc*' },
      { k: 'cookie', re: /^(renderCtx|BrowserId|sfdc-stream)$/, w: 0.5, note: 'Salesforce cookie' },
      { k: 'cookie', re: /^LSKey-c\$/, w: 0.5, note: 'Lightning Locker-Service cookie (LSKey-c$*)' },
      { k: 'dom', re: /^(script|link):[^ ]*(aura_prod|sfsites|salesforce)/i, w: 0.6, note: 'Aura / Salesforce assets' },
    ],
  },
  google: {
    name: 'Google Identity',
    family: 'Google',
    rules: [
      { k: 'url', re: /^https?:\/\/accounts\.google\.com\/(o\/oauth2|signin\/oauth|o\/saml2|v3\/signin)/i, w: 0.9, note: 'accounts.google.com OAuth/SAML' },
      { k: 'issuer', re: /^https:\/\/accounts\.google\.com$/i, w: 0.9, note: 'Issuer accounts.google.com' },
    ],
  },
  onelogin: {
    name: 'OneLogin',
    family: 'OneLogin',
    rules: [
      { k: 'url', re: /^https?:\/\/[^/]*\.onelogin\.com(\/|$)/i, w: 0.9, note: 'onelogin.com host' },
      { k: 'url', re: /\/oidc\/2\/(auth|token)|\/trust\/saml2\/http-post\/sso\//i, w: 0.7, note: 'OneLogin OIDC/SAML path' },
      { k: 'issuer', re: /\.onelogin\.com\/oidc/i, w: 0.9, note: 'OneLogin issuer' },
    ],
  },
  cyberark: {
    name: 'CyberArk Identity',
    family: 'CyberArk',
    rules: [
      { k: 'url', re: /^https?:\/\/[^/]*\.(id\.cyberark\.(cloud|com)|my\.idaptive\.(app|com))(\/|$)/i, w: 0.9, note: 'CyberArk Identity / Idaptive host' },
      { k: 'url', re: /\/OAuth2\/(Authorize|Token)\//, w: 0.4, note: 'Idaptive-style /OAuth2/Authorize/{app}' },
    ],
  },
};

// Selectors the content script probes (collected from the table so there is one source of truth).
export const SELECTORS = [
  ...new Set(
    Object.values(VENDORS).flatMap((v) => v.rules.filter((r) => r.k === 'sel').map((r) => r.eq)),
  ),
];

// Page globals the MAIN-world probe looks for (only names listed in rules; the service worker
// also drops any reported name that is not in this list).
export const GLOBALS = [
  ...new Set(
    Object.values(VENDORS).flatMap((v) => v.rules.filter((r) => r.k === 'glob').map((r) => r.eq)),
  ),
];

// Cheap prefilter for non-frame requests (scripts/xhr/css) so we only store relevant URLs.
export const INTERESTING_URL =
  /oauth|authorize|saml|login|signon|signin|sso|openid|\.well-known|realms|\/as\/|\/am\/|\/idp\/|\/u\/|\/id\/keys|okta|auth0|ping|forge|microsoftonline|b2clogin|cognito|salesforce|force\.com|aura|\/services\/|adfs|keycloak|onelogin|cyberark|idaptive|accounts\.google/i;
