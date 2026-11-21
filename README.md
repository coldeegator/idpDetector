# IdP Detector

Chrome (MV3) extension that tells you which identity provider a site's login flow uses
(PingOne, PingFederate, PingAM/ForgeRock, Okta, Auth0, Entra/ADFS, Cognito, Keycloak,
Salesforce, Google, OneLogin, CyberArk). It shows a ranked verdict **with the evidence**.

## Load it
1. `chrome://extensions` → enable Developer mode → **Load unpacked** → pick this folder.
2. Open a login page (or reload it so the redirect chain is captured), click the toolbar icon.
3. Custom domain with no vendor hints? Click **Probe discovery** (see below).

## What it looks at (all passive, all local)
| Signal | Examples |
|---|---|
| Redirect / request hosts + paths | `*.pingone.com`, `/{envId}/as/authorize`, `/oauth2/default/v1/authorize`, `/realms/x/protocol/openid-connect` |
| Response headers | `x-okta-request-id`, `x-auth0-requestid`, `x-sfdc-trace-flags`, `x-ms-ests-server` |
| Cookie **names** | `iPlanetDirectoryPro`, `ESTSAUTH`, `KEYCLOAK_IDENTITY`, `renderCtx` |
| Page DOM | Okta Sign-In Widget, Auth0 Lock, `#kc-form-login`, SDK/asset URLs |
| JWTs in the URL, JS-readable cookies, web storage, and `Authorization: Bearer` request headers | decoded once in the service worker (`summarizeJwt`); only `iss`, `alg`, `kid` and claim **names** are kept, the raw token and all claim values are dropped. Claim names are vendor-specific (e.g. AM: `cts`, `tokenName`, `authGrantId`, `auditTrackingId`, `realm`) |
| Web-storage **key names** | SDK keys only: `okta-token-storage`, `@@auth0spajs@@…`, `CognitoIdentityServiceProvider.*`, `msal.*`, `kc-callback-*`. Anchored regexes on the key; values are never read or sent |
| Page globals (MAIN-world probe) | `OktaSignIn`, `OktaAuth`, `Auth0Lock`, `auth0.WebAuth`, `msal.PublicClientApplication`, `Keycloak`, … A tiny `world: "MAIN"` script checks only the allowlist derived from `signatures.js`; generic names (`fr`, `op`, `CA`, `IBM`, `Ping`) are deliberately excluded |
| OIDC discovery (opt-in) | issuer + endpoint shapes from `/.well-known/openid-configuration` |

Privacy: URL query **values**, cookie **values**, tokens, bodies and fragments are never stored.
Nothing is sent anywhere. Observe-only: no request is blocked or modified.
The only outbound requests the extension makes are the opt-in **Probe discovery** GETs, to
hosts your tab already contacted. Use it on systems you are authorised to examine.

## Flow vs ambient evidence (why a stray header can't make a verdict)
Every signal is tagged with its resource type (navigation / redirect / script / xhr / iframe /
form / discovery) and the origin that produced it. A vendor becomes the **IdP verdict** only with
*flow* evidence: a navigation, redirect, form or discovery URL, an issuer, a JWT, or login-widget
markup. Headers, cookies, asset URLs and third-party calls are *ambient*: they raise the score of a
vendor that already has flow evidence (only if they came from a login origin), otherwise the vendor
is listed under **Other vendors on this page** with no score. If nothing has flow evidence the popup
says no external IdP was identified (first-party or server-side login).
Regressions covered by tests: Lloyds (`x-sfdc-*` from a chat/third-party origin), NatWest
(`x-ms-request-id`, a generic Azure header, no longer implies Entra).

## Scoring
Each vendor has weighted rules in `src/signatures.js`; scores combine as noisy-OR
(`1 - ∏(1 - w)`): a vendor host ≈ 0.9, a unique header ≈ 0.9, a path shape 0.5–0.8,
a weak hint ≤ 0.4. ≥80 % high, ≥50 % medium, else low. Add a vendor = add an entry there.

## Tests
`npm test` runs `test/detector.test.mjs` (pure logic, no browser).
Fixtures marked **real** came from curl recon of live sites; **synthetic** ones are written
from vendor docs and should be confirmed against your Okta / Auth0 sandboxes.

## Known limits
- SDK storage keys and page globals are *ambient* evidence: alone they list a vendor under
  "Other vendors on this page"; with flow evidence they raise its score. Their names come from the
  SDKs' documented behaviour and are covered by unit tests, but have not all been confirmed against
  live sandbox tenants yet. Bundled SDKs that never expose a global will not show up there.
- Fully custom-domain + custom-UI setups can only be identified by path shape / discovery / tokens.
- Token fingerprinting only works on readable, signed JWTs (JWS). Opaque tokens and encrypted
  ones (JWE: 5 dot-separated parts, empty/ciphertext payload) reveal nothing: the header's
  `alg`/`enc`/`kid` is generic and not vendor-specific, so JWEs are deliberately ignored. For those
  sites the verdict has to come from redirects, endpoints, discovery, markup, cookies and headers.
  Tokens also only exist after login.
- A typed URL or reload starts a fresh capture; JS-initiated redirects keep the chain.
- Not yet loaded and exercised in a real Chrome profile (only unit-tested + syntax-checked).
