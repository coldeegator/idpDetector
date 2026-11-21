// Popup UI. Renders with textContent only (evidence strings come from web pages: never innerHTML).
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const ask = (msg) => chrome.runtime.sendMessage(msg);

let tabId;

function render(res) {
  const out = $('out');
  out.replaceChildren();
  if (res.error) { out.append(el('div', 'empty', 'Error: ' + res.error)); return; }
  $('sub').textContent = `${res.nsignals} signals observed on this tab`;

  if (!res.results.length) {
    out.append(el('div', 'empty', res.present?.length
      ? 'No external IdP identified in the login flow. It may be first-party or server-side (or not exercised yet: ' +
        'reload the login page, or try “Probe discovery”). Vendors seen on the page are listed below.'
      : 'No identity provider recognised yet. Open a login page (or reload it) and reopen this popup. ' +
        'For a custom domain, try “Probe discovery”.'));
  }
  res.results.forEach((r, i) => {
    const v = el('div', 'vendor');
    const row = el('div', 'row');
    row.append(el('span', 'name', (i === 0 ? '★ ' : '') + r.name));
    row.append(el('span', 'pct ' + r.confidence, `${Math.round(r.score * 100)}% · ${r.confidence}`));
    const bar = el('div', 'bar'); const fill = el('i'); fill.style.width = `${Math.round(r.score * 100)}%`; bar.append(fill);
    v.append(row, bar);
    if (r.family && r.family !== r.name) v.append(el('div', 'sub', 'Vendor family: ' + r.family));
    const d = el('details'); if (i === 0) d.open = true;
    d.append(el('summary', '', `${r.evidence.length} piece(s) of evidence`));
    const ul = el('ul');
    for (const e of r.evidence) {
      const li = el('li'); li.append(el('span', '', e.note + (e.from ? ` [${e.from}] ` : ' ')), el('code', '', e.sample)); ul.append(li);
    }
    d.append(ul); v.append(d); out.append(v);
  });

  if (res.present?.length) {
    out.append(el('h1', '', 'Other vendors on this page'));
    out.append(el('div', 'sub', 'Seen as headers, cookies, assets or third-party calls. Not confirmed as the login IdP.'));
    for (const p of res.present) {
      const v = el('div', 'vendor');
      v.append(el('div', 'name', p.name));
      const d = el('details');
      d.append(el('summary', '', `${p.evidence.length} piece(s) of evidence`));
      const ul = el('ul');
      for (const e of p.evidence) {
        const li = el('li');
        li.append(el('span', '', `${e.note} [${e.from || '?'}${e.onLoginOrigin ? '' : ', third-party'}] `), el('code', '', e.sample));
        ul.append(li);
      }
      d.append(ul); v.append(d); out.append(v);
    }
  }

  $('proto').textContent = res.protocols?.length ? 'Protocols seen: ' + res.protocols.join(', ') : '';
  $('probes').textContent = res.probes?.length
    ? 'Discovery probe: ' + res.probes.map((p) => `${new URL(p.url).host}${new URL(p.url).pathname.replace('/.well-known/openid-configuration', '') || ''} → ${p.ok ? 'found' : p.status || 'fail'}`).join(' · ')
    : '';
}

async function refresh() { render(await ask({ type: 'getResult', tabId })); }

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab?.id;
  if (tabId === undefined) { $('sub').textContent = 'No active tab'; return; }
  await refresh();

  $('probe').onclick = async () => { $('probe').textContent = 'Probing…'; await ask({ type: 'probe', tabId }); $('probe').textContent = 'Probe discovery'; refresh(); };
  $('clear').onclick = async () => { await ask({ type: 'clear', tabId }); refresh(); };
  $('copy').onclick = async () => {
    await navigator.clipboard.writeText(JSON.stringify(await ask({ type: 'export', tabId }), null, 2));
    $('copy').textContent = 'Copied ✓'; setTimeout(() => ($('copy').textContent = 'Copy JSON'), 1200);
  };
})();
