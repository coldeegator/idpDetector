// Runs in the PAGE's own JS world ("world": "MAIN"), so it can see globals like window.OktaSignIn
// that the isolated content script cannot. It has no chrome.* access and knows no signature list:
// the isolated content script sends it the allowlist of dotted global paths to test, and it replies
// with the subset that exist. It never reads values, only whether a path resolves to something.
(() => {
  const resolve = (path) => {
    try {
      return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), window);
    } catch {
      return undefined;
    }
  };

  document.addEventListener('__idpd_probe', (e) => {
    let names;
    try { names = JSON.parse(e.detail); } catch { return; }
    if (!Array.isArray(names)) return;
    const present = names.filter((n) => typeof n === 'string' && n.length < 80 && resolve(n) !== undefined);
    document.dispatchEvent(new CustomEvent('__idpd_globals', { detail: JSON.stringify(present) }));
  });

  // Tell the isolated script we are listening (covers the case where it probed before we loaded).
  document.dispatchEvent(new CustomEvent('__idpd_ready'));
})();
