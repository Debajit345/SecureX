const $ = (selector) => document.querySelector(selector);
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));
const offlineDemo = location.protocol === 'file:' || new URLSearchParams(location.search).has('demo');
if (offlineDemo) $('#demo-banner').classList.remove('hidden');

async function post(path, data) {
  const response = await fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.detail || 'Request failed');
  return payload;
}
function demoScan(raw) {
  let url;
  try { url = new URL(raw.includes('://') ? raw : `https://${raw}`); }
  catch { throw new Error('Enter a valid website URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname.includes('.')) throw new Error('Enter a valid public website URL.');
  const reports = JSON.parse(localStorage.getItem('securex-demo-reports') || '[]').filter((item) => item.url === url.origin);
  const findings = [];
  if (url.protocol !== 'https:') findings.push({ severity: 'medium', title: 'Connection does not use HTTPS', detail: 'The URL uses HTTP, so traffic is not protected by TLS.' });
  const labels = url.hostname.split('.');
  const label = labels.length > 1 ? labels[labels.length - 2] : url.hostname;
  const brands = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'facebook', 'instagram', 'netflix', 'linkedin'];
  if (brands.some((brand) => label !== brand && label.replaceAll('-', '').length > 3 && (brand.includes(label.replaceAll('-', '')) || label.replaceAll('-', '').includes(brand)))) findings.push({ severity: 'medium', title: 'Possible brand lookalike', detail: 'The domain resembles a well-known brand. This demo heuristic can produce false positives.' });
  if (/login|verify|secure|account|payment|password|wallet/i.test(url.href)) findings.push({ severity: 'low', title: 'Sensitive-action wording in URL', detail: 'This URL contains wording commonly used in account or payment flows. This is a weak signal.' });
  if (reports.length) findings.push({ severity: reports.length >= 3 ? 'high' : 'medium', title: `Community reports (${reports.length})`, detail: 'Categories: ' + [...new Set(reports.map((r) => r.category))].join(', ') + '. These local demo reports are not verified.' });
  findings.push({ severity: 'info', title: 'Live certificate and security checks unavailable', detail: 'Offline demo mode does not contact websites, inspect TLS, or query Certificate Transparency.' });
  const score = Math.min(100, findings.reduce((sum, finding) => sum + ({ high: 35, medium: 18, low: 7 }[finding.severity] || 0), 0));
  return { url: url.origin + url.pathname, scanned_at: new Date().toISOString(), score, risk: score >= 50 ? 'High risk' : score >= 20 ? 'Caution' : 'Low indicators found', findings, errors: [] };
}

$('#scan-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const box = $('#result');
  box.classList.remove('hidden');
  box.innerHTML = '<p>Checking URL, certificate, response headers, and community signals…</p>';
  try {
    const report = offlineDemo ? demoScan($('#url').value) : await post('/api/scan', { url: $('#url').value });
    const findings = report.findings.length
      ? report.findings.map((finding) => `<div class="finding"><span class="pill">${esc(finding.severity)}</span><strong>${esc(finding.title)}</strong><p>${esc(finding.detail)}</p></div>`).join('')
      : '<div class="finding"><strong>No notable indicators from available checks.</strong><p>A low score does not guarantee a site is safe.</p></div>';
    const errors = (report.errors || []).map((message) => `<div class="finding error">${esc(message)}</div>`).join('');
    box.innerHTML = `<div class="result-head"><div><div class="eyebrow">${esc(report.risk)}</div><h2>${esc(report.url)}</h2><div class="micro">${offlineDemo ? 'Illustrative demo' : 'Scanned'} · ${new Date(report.scanned_at).toLocaleString()}</div></div><div class="score">Risk score ${report.score}/100</div></div>${findings}${errors}<button id="copy-summary" type="button">Copy report summary</button>`;
    $('#copy-summary').onclick = () => navigator.clipboard?.writeText(`SecureX: ${report.risk} (${report.score}/100) — ${report.url}\n${report.findings.map((item) => `• ${item.title}: ${item.detail}`).join('\n')}`);
  } catch (error) {
    box.innerHTML = `<div class="error">${esc(error.message)}</div>`;
  }
});

$('#report-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const data = { url: form.get('url'), category: form.get('category'), note: form.get('note') };
  try {
    if (offlineDemo) {
      const url = new URL(data.url.includes('://') ? data.url : `https://${data.url}`);
      if (!['http:', 'https:'].includes(url.protocol) || !url.hostname.includes('.')) throw new Error('Enter a valid website URL.');
      const reports = JSON.parse(localStorage.getItem('securex-demo-reports') || '[]');
      reports.push({ url: url.origin, category: data.category, note: data.note, created_at: new Date().toISOString() });
      localStorage.setItem('securex-demo-reports', JSON.stringify(reports));
      alert('Saved in this browser’s offline demo only.');
    } else {
      const result = await post('/api/reports', data);
      alert(result.message);
    }
    event.currentTarget.reset();
  } catch (error) { alert(error.message); }
});
