const express = require('express');
const axios = require('axios');
const https = require('https');
const tls = require('tls');
const path = require('path');
const urlModule = require('url');
const dns = require('dns').promises;
const cheerio = require('cheerio');
const net = require('net');

const app = express();
const PORT = process.env.PORT || 3000;
const GEMINI_API_KEY = "AIzaSyC9HpL3Wj7HLpbUNhKD2WE84XkLEFXvW1E";

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Security Headers Reference
const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    description: 'Ensures the browser only communicates with the server via HTTPS.',
    score: 15,
    nginx: 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
    apache: 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
    express: 'app.use(helmet.hsts({ maxAge: 63072000, includeSubDomains: true, preload: true }));',
    nextjs: '{\n  key: "Strict-Transport-Security",\n  value: "max-age=63072000; includeSubDomains; preload"\n}'
  },
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    description: 'Restricts resource loading to trusted origins, preventing XSS.',
    score: 25,
    nginx: 'add_header Content-Security-Policy "default-src \'self\';" always;',
    apache: 'Header always set Content-Security-Policy "default-src \'self\';"',
    express: 'app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["\'self\'"] } }));',
    nextjs: '{\n  key: "Content-Security-Policy",\n  value: "default-src \'self\';"\n}'
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    description: 'Protects visitors against clickjacking by controlling iframe embedding.',
    score: 15,
    nginx: 'add_header X-Frame-Options "DENY" always;',
    apache: 'Header always set X-Frame-Options "DENY"',
    express: 'app.use(helmet.frameguard({ action: "deny" }));',
    nextjs: '{\n  key: "X-Frame-Options",\n  value: "DENY"\n}'
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    description: 'Prevents browsers from MIME-sniffing a response.',
    score: 10,
    nginx: 'add_header X-Content-Type-Options "nosniff" always;',
    apache: 'Header always set X-Content-Type-Options "nosniff"',
    express: 'app.use(helmet.noSniff());',
    nextjs: '{\n  key: "X-Content-Type-Options",\n  value: "nosniff"\n}'
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'Controls referrer information sent with requests.',
    score: 10,
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    express: 'app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));',
    nextjs: '{\n  key: "Referrer-Policy",\n  value: "strict-origin-when-cross-origin"\n}'
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    description: 'Restricts browser features and APIs (camera, mic).',
    score: 10,
    nginx: 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
    apache: 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
    express: 'app.use(helmet.permissionsPolicy({ features: { geolocation: ["\'none\'"], microphone: ["\'none\'"], camera: ["\'none\'"] } }));',
    nextjs: '{\n  key: "Permissions-Policy",\n  value: "geolocation=(), microphone=(), camera=()"\n}'
  }
};

function calculateGrade(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function getTlsDetails(hostname) {
  return new Promise((resolve) => {
    const options = { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false };
    try {
      const socket = tls.connect(options, () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.destroy();

        if (!cert || Object.keys(cert).length === 0) return resolve({ success: false, error: 'No certificate' });

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isExpired = now > validTo || now < validFrom;

        let tlsStatus = 'Secure';
        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') tlsStatus = 'Weak (Deprecated)';

        let sans = [];
        if (cert.subjectaltname) sans = cert.subjectaltname.split(', ').map(s => s.replace('DNS:', ''));
        let ocsp = [];
        if (cert.infoAccess && cert.infoAccess['OCSP - URI']) ocsp = cert.infoAccess['OCSP - URI'];
        
        // Basic Chain verification
        const issuerName = cert.issuer.O || cert.issuer.CN || 'Unknown';
        const subjectName = cert.subject.O || cert.subject.CN || 'Unknown';
        const isSelfSigned = issuerName === subjectName;
        const supportsHttp2 = socket.alpnProtocol === 'h2';

        resolve({
          success: true, issuer: issuerName, subject: subjectName,
          validFrom: cert.valid_from, validTo: cert.valid_to,
          daysRemaining, isExpired, protocol, cipherName: cipher.name, cipherVersion: cipher.version,
          tlsStatus, sans, ocsp, isSelfSigned, supportsHttp2
        });
      });
      socket.on('error', (err) => { socket.destroy(); resolve({ success: false, error: err.message }); });
      socket.setTimeout(6000, () => { socket.destroy(); resolve({ success: false, error: 'Timeout' }); });
    } catch (e) { resolve({ success: false, error: e.message }); }
  });
}

function analyzeCookies(setCookieHeaders) {
  const cookies = [];
  if (!setCookieHeaders) return cookies;
  const headersArray = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  headersArray.forEach(cookieStr => {
    const parts = cookieStr.split(';').map(p => p.trim());
    const name = parts[0].split('=')[0];
    cookies.push({
      name, secure: cookieStr.toLowerCase().includes('secure'),
      httpOnly: cookieStr.toLowerCase().includes('httponly'),
      sameSite: (cookieStr.match(/samesite=(strict|lax|none)/i) || [, 'Missing'])[1]
    });
  });
  return cookies;
}

function evaluateDeepCSP(cspHeader) {
  const issues = [];
  let hasFrameAncestors = false;
  if (!cspHeader) return { issues, hasFrameAncestors };
  
  const cspLower = cspHeader.toLowerCase();
  if (cspLower.includes('unsafe-inline')) issues.push({ severity: 'High', issue: 'Uses unsafe-inline (Allows inline scripts/styles)' });
  if (cspLower.includes('unsafe-eval')) issues.push({ severity: 'High', issue: 'Uses unsafe-eval (Allows code execution from strings)' });
  if (cspLower.includes('http:')) issues.push({ severity: 'Medium', issue: 'Allows loading resources over insecure HTTP' });
  if (cspLower.includes('frame-ancestors')) hasFrameAncestors = true;
  
  cspLower.split(';').map(d => d.trim()).forEach(dir => {
    if ((dir.startsWith('default-src') || dir.startsWith('script-src') || dir.startsWith('object-src')) && dir.includes('*')) {
       issues.push({ severity: 'High', issue: `Wildcard source (*) found in directive: ${dir.split(' ')[0]}` });
    }
  });
  return { issues, hasFrameAncestors };
}

async function checkDnsSecurity(hostname) {
  const results = { spf: { found: false, record: null }, dmarc: { found: false, record: null } };
  try {
    const txtRecords = await dns.resolveTxt(hostname);
    for (const recordArray of txtRecords) {
      if (recordArray.join('').startsWith('v=spf1')) { results.spf.found = true; results.spf.record = recordArray.join(''); }
    }
  } catch (e) { }
  try {
    const dmarcRecords = await dns.resolveTxt('_dmarc.' + hostname);
    for (const recordArray of dmarcRecords) {
      if (recordArray.join('').startsWith('v=DMARC1')) { results.dmarc.found = true; results.dmarc.record = recordArray.join(''); }
    }
  } catch (e) { }
  return results;
}

async function checkInfrastructure(baseUrl) {
    const infra = { robots: false, sitemap: false, crossdomain: false };
    const ping = async (path) => {
        try {
            const res = await axios.get(baseUrl + path, { timeout: 2500, validateStatus: () => true });
            return res.status === 200;
        } catch(e) { return false; }
    };
    
    infra.robots = await ping('/robots.txt');
    infra.sitemap = await ping('/sitemap.xml');
    infra.crossdomain = await ping('/crossdomain.xml') || await ping('/clientaccesspolicy.xml');
    
    return infra;
}

async function checkHstsPreload(domain) {
    try {
        const res = await axios.get(`https://hstspreload.org/api/v2/status?domain=${domain}`, { timeout: 3000, validateStatus: () => true });
        if (res.data && res.data.status === 'preloaded') return true;
    } catch(e) {}
    return false;
}

async function getSubdomains(domain) {
    try {
        const res = await axios.get(`https://crt.sh/?q=%.${domain}&output=json`, { timeout: 5000, validateStatus: () => true });
        if (res.data && Array.isArray(res.data)) {
            const subs = new Set(res.data.map(d => d.name_value.toLowerCase().trim()));
            const targets = Array.from(subs).slice(0, 15); // limit to 15
            
            const results = await Promise.all(targets.map(async sub => {
                let status = 'Active';
                let vulnerable = false;
                try { await dns.resolve(sub); } catch(e) {
                    if (e.code === 'ENOTFOUND') { status = 'Dangling DNS'; vulnerable = true; } 
                    else { status = 'Unreachable'; }
                }
                return { domain: sub, status, vulnerable };
            }));
            return results;
        }
    } catch(e) {}
    return [];
}

function analyzeCacheSecurity(headers) {
    const cacheControl = headers['cache-control'] || '';
    const pragma = headers['pragma'] || '';
    const expires = headers['expires'] || '';
    let isCached = true;
    let posture = 'Public / Cached';
    if (cacheControl.includes('no-store') || cacheControl.includes('private')) {
        isCached = false; posture = 'Private / No-Store';
    }
    return {
        cacheControl: cacheControl || 'Missing', pragma: pragma || 'Missing', expires: expires || 'Missing',
        isCached, posture, message: (isCached && cacheControl) ? 'Response is cacheable.' : 'Securely restricts downstream caching.'
    };
}

async function checkHttpMethods(targetUrl) {
    try {
        const res = await axios.options(targetUrl, { timeout: 3000, validateStatus: () => true });
        const allowed = res.headers['access-control-allow-methods'] || res.headers['allow'] || '';
        if (!allowed) return { methods: 'Not defined', vulnerable: false };
        const vulnMethods = ['TRACE', 'PUT', 'DELETE', 'TRACK'];
        const foundVuln = vulnMethods.filter(m => allowed.toUpperCase().includes(m));
        return { methods: allowed, vulnerable: foundVuln.length > 0 };
    } catch (e) { return { methods: 'Failed', vulnerable: false }; }
}

async function checkDirectoryListing(baseUrl) {
    try {
        const res = await axios.get(`${baseUrl}/assets/`, { timeout: 3000, validateStatus: () => true });
        const dataStr = String(res.data);
        if (res.status === 200 && (dataStr.includes('<title>Index of') || dataStr.includes('Index of /assets'))) return true;
    } catch (e) {}
    return false;
}

async function checkCors(baseUrl) {
    try {
        const res = await axios.options(baseUrl, { headers: { 'Origin': 'https://evil-origin.com' }, timeout: 3000, validateStatus: () => true });
        const acao = res.headers['access-control-allow-origin'];
        if (acao === '*' || acao === 'https://evil-origin.com') return { vulnerable: true, message: `Reflected/Wildcard CORS: ${acao}` };
    } catch(e) {}
    return { vulnerable: false, message: 'CORS policy secure.' };
}

function checkInfoLeakage(headers) {
    const leaks = [];
    if (headers['x-powered-by']) leaks.push(`X-Powered-By: ${headers['x-powered-by']}`);
    if (headers['server']) leaks.push(`Server version: ${headers['server']}`);
    return leaks;
}

async function checkSecurityTxt(baseUrl) {
    try {
        const res = await axios.get(`${baseUrl}/.well-known/security.txt`, { timeout: 2000, validateStatus: () => true });
        if (res.status === 200 && String(res.data).toLowerCase().includes('contact')) return { found: true };
    } catch(e) {}
    return { found: false };
}

// New Module: WAF Fingerprinter
function checkWaf(headers) {
    const wafs = [];
    const h = JSON.stringify(headers).toLowerCase();
    if (h.includes('cf-ray') || h.includes('cloudflare')) wafs.push('Cloudflare');
    if (h.includes('x-sucuri')) wafs.push('Sucuri');
    if (h.includes('x-amz-cf-id')) wafs.push('AWS WAF / CloudFront');
    if (h.includes('akamai')) wafs.push('Akamai');
    if (h.includes('incap_ses')) wafs.push('Imperva');
    return wafs.length > 0 ? wafs.join(', ') : 'No prominent WAF detected';
}

// New Module: Open Port Scanner
async function checkPorts(hostname) {
    const ports = [21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080];
    const openPorts = [];
    const scanPort = (port) => new Promise(resolve => {
        const s = new net.Socket();
        s.setTimeout(1500);
        s.on('connect', () => { s.destroy(); resolve(port); });
        s.on('timeout', () => { s.destroy(); resolve(null); });
        s.on('error', () => { s.destroy(); resolve(null); });
        s.connect(port, hostname);
    });
    const results = await Promise.all(ports.map(p => scanPort(p)));
    return results.filter(p => p !== null);
}

// New Module: Broken Link Hijacking
async function checkBrokenLinks(html, hostname) {
    if (!html) return [];
    const $ = cheerio.load(html);
    const externalLinks = new Set();
    $('a[href^="http"]').each((i, el) => {
        try {
            const u = new urlModule.URL($(el).attr('href'));
            if (u.hostname && !u.hostname.includes(hostname)) externalLinks.add(u.hostname);
        } catch(e){}
    });
    const targets = Array.from(externalLinks).slice(0, 15);
    const deadLinks = [];
    await Promise.all(targets.map(async domain => {
        try { await dns.resolve(domain); } catch(e) { if (e.code === 'ENOTFOUND') deadLinks.push(domain); }
    }));
    return deadLinks;
}

// New Module: Directory Fuzzer & Sensitive Files
async function checkDirectoryFuzzing(baseUrl) {
    const paths = [
        '/.env', '/.git/config', '/.DS_Store', '/docker-compose.yml', '/config.json',
        '/admin', '/wp-admin', '/backup', '/backup.zip', '/old', '/test', '/staging',
        '/graphql', '/api/docs', '/swagger-ui.html', '/openapi.json', '/server-status'
    ];
    const results = { exposedFiles: [], hiddenDirs: [], apis: [] };
    const ping = async (path) => {
        try {
            const res = await axios.head(baseUrl + path, { timeout: 2000, validateStatus: () => true });
            if (res.status === 200 || res.status === 401 || res.status === 403) return { path, status: res.status };
        } catch(e) {}
        return null;
    };
    const hits = await Promise.all(paths.map(p => ping(p)));
    hits.filter(h => h !== null).forEach(hit => {
        if (hit.path.match(/\.(env|git|DS|yml|json)$/)) results.exposedFiles.push(hit);
        else if (hit.path.match(/(graphql|api|swagger|openapi)/)) results.apis.push(hit);
        else results.hiddenDirs.push(hit);
    });
    return results;
}

// New Module: AI Scraper Defenses
async function checkAiScrapers(baseUrl) {
    try {
        const res = await axios.get(`${baseUrl}/robots.txt`, { timeout: 2500, validateStatus: () => true });
        if (res.status === 200) {
            const txt = String(res.data).toLowerCase();
            const blocksAi = txt.includes('gptbot') || txt.includes('anthropic-ai') || txt.includes('ccbot') || txt.includes('google-extended');
            return { foundRobots: true, blocksAi };
        }
    } catch(e) {}
    return { foundRobots: false, blocksAi: false };
}

// New Module: Active DAST Injection (SQLi, XSS, SSRF, LFI)
async function checkActiveVulnerabilities(targetUrlObj) {
    const results = { sqli: [], xss: [], ssrf: [], lfi: [] };
    if (!targetUrlObj.search) return results; // Only scan if parameters exist
    
    const params = Array.from(targetUrlObj.searchParams.keys());
    if (params.length === 0) return results;

    const testParam = async (param, payload, type, checkFn) => {
        try {
            const testUrl = new urlModule.URL(targetUrlObj.href);
            testUrl.searchParams.set(param, payload);
            const res = await axios.get(testUrl.toString(), { timeout: 3000, validateStatus: () => true });
            if (checkFn(String(res.data), res.status, res.headers)) {
                results[type].push({ param, payload, url: testUrl.toString() });
            }
        } catch(e) {}
    };

    const injectPromises = [];
    params.forEach(param => {
        // SQLi
        injectPromises.push(testParam(param, "1' OR '1'='1", 'sqli', (data) => data.match(/(SQL syntax|mysql_fetch_array|ORA-|PostgreSQL query failed)/i)));
        
        // XSS
        const xssPayload = `"><script>alert('AkhilWebGuardXSS')</script>`;
        injectPromises.push(testParam(param, xssPayload, 'xss', (data) => data.includes(xssPayload)));
        
        // LFI (Directory Traversal)
        injectPromises.push(testParam(param, "../../../../../../etc/passwd", 'lfi', (data) => data.match(/root:x:0:0:/i)));
        injectPromises.push(testParam(param, "..\\..\\..\\windows\\win.ini", 'lfi', (data) => data.match(/\[extensions\]/i)));
        
        // SSRF
        if (param.toLowerCase().match(/(url|path|site|domain|redirect|api)/)) {
             injectPromises.push(testParam(param, "http://169.254.169.254/latest/meta-data/", 'ssrf', (data) => data.includes('ami-id') || data.includes('instance-id')));
        }
    });

    await Promise.all(injectPromises);
    return results;
}

// Gemini Helper
async function callGemini(apiKey, prompt) {
    try {
        const res = await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`, {
            contents: [{ parts: [{ text: prompt }] }]
        }, { timeout: 15000 });
        return res.data.candidates[0].content.parts[0].text;
    } catch(e) { return "AI Analysis Failed: Ensure your API key is valid or try again."; }
}

function identifyTech(headers, html) {
    const tech = [];
    if (headers['x-powered-by']) tech.push(`X-Powered-By: ${headers['x-powered-by']}`);
    if (headers['server']) tech.push(`Server: ${headers['server']}`);
    if (html) {
        const $ = cheerio.load(html);
        const gen = $('meta[name="generator"]').attr('content');
        if (gen) tech.push(`Generator: ${gen}`);
        if (html.includes('wp-content')) tech.push('WordPress (implied)');
        if (html.includes('__NEXT_DATA__')) tech.push('Next.js (implied)');
        if (html.includes('data-reactroot')) tech.push('React (implied)');
    }
    return [...new Set(tech)];
}

function parseHtmlSecurity(html, targetHostname, protocol) {
  const results = { 
      sri: { total: 0, missing: 0 }, mixedContent: [], libraries: [], seo: [], 
      domSec: { formsInsecure: 0, pwdInsecure: 0, hiddenLeaks: 0, sinks: 0, secrets: [] },
      auth: { missingCsrf: 0, insecureAction: 0, plaintextPasswords: 0 },
      sourceMaps: false, homeText: '', inlineScripts: ''
  };
  
  if (!html) return results;
  const $ = cheerio.load(html);
  
  results.homeText = $('body').text().replace(/\s+/g, ' ').trim();

  // Secrets Heuristic
  if (html.match(/AKIA[0-9A-Z]{16}/)) results.domSec.secrets.push('AWS Access Key (AKIA) Pattern Found');
  if (html.match(/AIza[0-9A-Za-z-_]{35}/)) results.domSec.secrets.push('Google API Key Pattern Found');
  if (html.match(/eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/)) results.domSec.secrets.push('JWT Pattern Found');
  
  // DOM Sinks & Source Maps
  if (html.includes('//# sourceMappingURL=')) results.sourceMaps = true;
  $('script:not([src])').each((i, el) => {
      const code = $(el).html();
      if (code) {
          results.inlineScripts += code + '\n';
          if (code.includes('innerHTML') || code.includes('document.write') || code.match(/eval\s*\(/)) {
              results.domSec.sinks++;
          }
      }
  });

  // Forms & Authentication
  $('form').each((i, el) => {
      const action = $(el).attr('action') || '';
      const formHtml = $(el).html().toLowerCase();
      
      if (action.startsWith('http://') && protocol === 'https:') {
          results.domSec.formsInsecure++;
          results.auth.insecureAction++;
      }
      
      // CSRF Check on POST forms
      const method = $(el).attr('method') ? $(el).attr('method').toLowerCase() : 'get';
      if (method === 'post') {
          if (!formHtml.includes('csrf') && !formHtml.includes('token') && !formHtml.includes('authenticity_token')) {
              results.auth.missingCsrf++;
          }
      }
  });

  // Passwords
  $('input[type="password"]').each((i, el) => {
      const auto = $(el).attr('autocomplete');
      if (!auto || (auto !== 'off' && auto !== 'new-password')) results.domSec.pwdInsecure++;
      
      const formMethod = $(el).closest('form').attr('method') ? $(el).closest('form').attr('method').toLowerCase() : 'get';
      if (formMethod === 'get') results.auth.plaintextPasswords++; // GET puts pass in URL
  });

  // Hidden Inputs
  $('input[type="hidden"]').each((i, el) => {
      const val = $(el).attr('value');
      if (val && val.length > 100) results.domSec.hiddenLeaks++;
  });

  // Mixed Content & SRI & Libraries
  const checkMixed = (url) => { if (protocol === 'https:' && url && url.startsWith('http://')) results.mixedContent.push(url); };
  
  const sriAnalysis = { scriptsMissingSRI: 0, stylesMissingSRI: 0, totalExternalScripts: 0, totalExternalStyles: 0 };
  
  $('img[src], iframe[src], script[src], link[rel="stylesheet"]').each((i, el) => {
    const src = $(el).attr('src') || $(el).attr('href');
    if (!src) return;
    checkMixed(src);
    if (el.tagName.toLowerCase() === 'script') {
        if (src.match(/^https?:\/\//) && !src.includes(targetHostname)) {
            sriAnalysis.totalExternalScripts++;
            if (!$(el).attr('integrity')) sriAnalysis.scriptsMissingSRI++;
        }
        const fn = src.split('/').pop().toLowerCase();
        [{n:'jQuery',r:/jquery[-.]([0-9.]+)/}, {n:'React',r:/react(?:-dom)?[-.@]([0-9.]+)/}, {n:'Vue',r:/vue[-.@]([0-9.]+)/}].forEach(p => {
            const m = fn.match(p.r); if (m) results.libraries.push({ name: p.n, version: m[1] });
        });
    }
    if (el.tagName.toLowerCase() === 'link') {
        if (src.match(/^https?:\/\//) && !src.includes(targetHostname)) {
            sriAnalysis.totalExternalStyles++;
            if (!$(el).attr('integrity')) sriAnalysis.stylesMissingSRI++;
        }
    }
  });
  results.sriAnalysis = sriAnalysis;

  // SEO
  $('meta').each((i, el) => {
      const prop = $(el).attr('property') || $(el).attr('name');
      const content = $(el).attr('content');
      if (prop && content && (prop.startsWith('og:') || prop.startsWith('twitter:'))) {
          const spillage = !!content.match(/(Exception|Error:|Stack trace|10\.\d\.\d\.\d)/i);
          results.seo.push({ property: prop, spillage });
      }
  });
  
  return results;
}

app.post('/api/analyze', async (req, res) => {
  let targetUrl = req.body.url;
  if (!targetUrl) return res.status(400).json({ error: 'URL required' });
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  let parsedUrl;
  try { parsedUrl = new urlModule.URL(targetUrl); } catch (err) { return res.status(400).json({ error: 'Invalid URL' }); }

  const hostname = parsedUrl.hostname;
  const protocol = parsedUrl.protocol;
  const baseUrl = `${protocol}//${hostname}`;

  try {
    const response = await axios.get(parsedUrl.toString(), {
      headers: { 'User-Agent': 'Mozilla/5.0 AkhilWebGuardAuditor/5.0 Ultimate', 'Origin': 'https://evil-origin.com' },
      timeout: 15000, maxRedirects: 5, validateStatus: () => true
    });

    const headers = response.headers;
    const auditResults = [];
    let currentScore = 10; 
    const isHttps = protocol === 'https:';
    if (isHttps) currentScore += 15;

    for (const [headerKey, config] of Object.entries(SECURITY_HEADERS)) {
      const present = !!headers[headerKey];
      if (present) currentScore += config.score;
      auditResults.push({ 
        key: headerKey, name: config.name, description: config.description,
        status: present ? 'Configured' : 'Missing', 
        scorePoints: present ? config.score : 0, maxPoints: config.score,
        nginx: config.nginx, apache: config.apache, express: config.express, nextjs: config.nextjs
      });
    }

    // 15 Modules + Legacy Pro + Advanced + Red Team + DAST execution
    const [
      infra, hstsPreloaded, subdomains, dnsSecurity, httpMethods, dirListing, cors, securityTxt, openPorts, brokenLinks, fuzzer, aiScrapers, dast
    ] = await Promise.all([
      checkInfrastructure(baseUrl),
      isHttps ? checkHstsPreload(hostname) : false,
      getSubdomains(hostname),
      checkDnsSecurity(hostname),
      checkHttpMethods(baseUrl),
      checkDirectoryListing(baseUrl),
      checkCors(baseUrl),
      checkSecurityTxt(baseUrl),
      checkPorts(hostname),
      checkBrokenLinks(String(response.data), hostname),
      checkDirectoryFuzzing(baseUrl),
      checkAiScrapers(baseUrl),
      checkActiveVulnerabilities(parsedUrl)
    ]);

    const cookieAnalysis = analyzeCookies(headers['set-cookie']);
    const cspEval = evaluateDeepCSP(headers['content-security-policy']);
    const cacheSecurity = analyzeCacheSecurity(headers);
    const htmlSecurity = parseHtmlSecurity(String(response.data), hostname, protocol);
    const techStack = identifyTech(headers, String(response.data));
    const leaks = checkInfoLeakage(headers);
    const waf = checkWaf(headers);
    
    // Header specific checks
    const refPolicy = headers['referrer-policy'] || 'Missing';
    const refInsecure = refPolicy === 'unsafe-url';

    let tlsDetails = null;
    if (isHttps) {
      tlsDetails = await getTlsDetails(hostname);
      if (tlsDetails.success && tlsDetails.isExpired) currentScore -= 30;
    }

    // Penalties & Scoring Adjustments
    if (hstsPreloaded) currentScore += 5;
    if (infra.robots) currentScore += 2;
    if (htmlSecurity.domSec.secrets.length > 0) currentScore -= 20;
    if (htmlSecurity.domSec.sinks > 0) currentScore -= 10;
    if (htmlSecurity.mixedContent.length > 0) currentScore -= 10;

    // AI Insights Module
    let aiInsights = null;
    if (GEMINI_API_KEY) {
       const phishingPrompt = `Analyze this text extracted from a website homepage and determine if it sounds like a phishing site, scam, or highly suspicious. Reply with a brief 2-sentence analysis and a scam probability score (0-100%). Text:\n${htmlSecurity.homeText.substring(0, 3000)}`;
       const attackChainPrompt = `You are a security expert. The following vulnerabilities were found on ${hostname}: Missing CSP, ${openPorts.length > 0 ? 'Open ports: ' + openPorts.join(', ') : ''}, Missing HSTS: ${!hstsPreloaded}. Write a 3-sentence narrative explaining a potential attack chain hackers could use based on these specific flaws.`;
       
       let jsPrompt = "No inline scripts to analyze.";
       if (htmlSecurity.inlineScripts.length > 0) {
           jsPrompt = `Analyze this inline JavaScript snippet for potential obfuscation, keylogging, or crypto-mining malware. Reply with a short 2-sentence verdict. JS:\n${htmlSecurity.inlineScripts.substring(0, 1500)}`;
       }
       
       const [phishingAnalysis, attackNarrative, jsAnalysis] = await Promise.all([
           callGemini(GEMINI_API_KEY, phishingPrompt),
           callGemini(GEMINI_API_KEY, attackChainPrompt),
           callGemini(GEMINI_API_KEY, jsPrompt)
       ]);
       aiInsights = { phishingAnalysis, attackNarrative, jsAnalysis };
    }

    const grade = calculateGrade(Math.min(100, Math.max(0, currentScore)));

    return res.json({
      success: true, domain: hostname, score: Math.min(100, Math.max(0, currentScore)), grade,
      headersFound: auditResults.filter(h => h.status === 'Configured').length,
      isHttps, headers: auditResults, tlsDetails, aiInsights,
      advanced: {
        cookies: cookieAnalysis, cspIssues: cspEval.issues, hasFrameAncestors: cspEval.hasFrameAncestors,
        dnsSecurity, infra, hstsPreloaded, subdomains, cacheSecurity, httpMethods, dirListing,
        domSec: htmlSecurity.domSec, sourceMaps: htmlSecurity.sourceMaps, sriAnalysis: htmlSecurity.sriAnalysis,
        mixedContent: htmlSecurity.mixedContent, libraries: htmlSecurity.libraries, seo: htmlSecurity.seo,
        auth: htmlSecurity.auth,
        techStack, refPolicy, refInsecure, cors, leaks, securityTxt, openPorts, brokenLinks, waf,
        fuzzer, aiScrapers, dast
      }
    });
  } catch (error) { return res.status(500).json({ error: `Connection failed: ${error.message}` }); }
});

app.post('/api/chat', async (req, res) => {
    const { message, context } = req.body;
    if (!GEMINI_API_KEY || !message) return res.status(400).json({ error: 'Missing key or message' });
    const prompt = `You are Akhil WebGuard AI, a cybersecurity assistant helping a user understand their website audit.
Context Data: ${JSON.stringify(context).substring(0, 3000)}
User Question: ${message}
Reply concisely and practically in 2-3 sentences. Do not use markdown backticks for formatting, just plain text.`;
    const reply = await callGemini(GEMINI_API_KEY, prompt);
    res.json({ reply });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Akhil WebGuard Auditor server running on port ${PORT}`));
