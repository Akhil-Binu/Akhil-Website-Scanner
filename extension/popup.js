const WEBGUARD_URL = 'http://localhost:3000';

async function init() {
  // Get the current tab's URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const pageUrl = tab.url || '';

  let domain = '';
  try {
    const parsed = new URL(pageUrl);
    domain = parsed.hostname;
  } catch (e) {
    showError();
    return;
  }

  document.getElementById('domainBar').textContent = domain;
  document.getElementById('fullScanBtn').href = `${WEBGUARD_URL}/?prefill=${encodeURIComponent(domain)}`;

  try {
    const response = await fetch(`${WEBGUARD_URL}/api/quick-score?domain=${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(10000)
    });

    if (!response.ok) throw new Error('Server error');
    const data = await response.json();

    if (!data.success) throw new Error(data.error || 'Failed');

    renderResult(data, pageUrl);
  } catch (e) {
    showError();
  }
}

function renderResult(data, pageUrl) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('result').style.display = 'block';

  const ring = document.getElementById('scoreRing');
  const grade = data.grade || 'F';
  ring.className = `score-ring grade-${grade}`;
  document.getElementById('scoreNum').textContent = data.score;
  document.getElementById('gradeLabel').textContent = `Grade ${grade}`;
  document.getElementById('scoreDisplay').textContent = `${data.score}/100`;
  document.getElementById('gradeDisplay').textContent = grade;

  const isHttps = pageUrl.startsWith('https');
  const httpsBadge = document.getElementById('httpsDisplay');
  httpsBadge.textContent = isHttps ? '✓ HTTPS' : '✗ HTTP Only';
  httpsBadge.className = `badge ${isHttps ? 'badge-green' : 'badge-red'}`;
}

function showError() {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('error').style.display = 'block';
}

document.addEventListener('DOMContentLoaded', init);
