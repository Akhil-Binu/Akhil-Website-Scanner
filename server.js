const express = require('express');
const axios = require('axios');
const https = require('https');
const tls = require('tls');
const path = require('path');
const urlModule = require('url');
const dns = require('dns').promises;
const cheerio = require('cheerio');

const app = express();
const PORT = process.env.PORT || 3000;

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

        if (!cert || Object.keys(cert).length === 0) {
          return resolve({ success: false, error: 'No certificate returned' });
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isExpired = now > validTo || now < validFrom;

        let tlsStatus = 'Secure';
        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') tlsStatus = 'Weak (Deprecated)';

        // Deep TLS: SAN and OCSP extraction
        let sans = [];
        if (cert.subjectaltname) {
            sans = cert.subjectaltname.split(', ').map(s => s.replace('DNS:', ''));
        }
        let ocsp = [];
        if (cert.infoAccess && cert.infoAccess['OCSP - URI']) {
            ocsp = cert.infoAccess['OCSP - URI'];
        }

        resolve({
          success: true,
          issuer: cert.issuer.O || cert.issuer.CN || 'Unknown',
          subject: cert.subject.CN || 'Unknown',
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysRemaining,
          isExpired,
          protocol,
          cipherName: cipher.name,
          cipherVersion: cipher.version,
          tlsStatus,
          sans,
          ocsp
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
      name,
      secure: cookieStr.toLowerCase().includes('secure'),
      httpOnly: cookieStr.toLowerCase().includes('httponly'),
      sameSite: (cookieStr.match(/samesite=(strict|lax|none)/i) || [, 'Missing'])[1]
    });
  });
  return cookies;
}

function evaluateDeepCSP(cspHeader) {
  const issues = [];
  if (!cspHeader) return issues;
  const cspLower = cspHeader.toLowerCase();
  if (cspLower.includes('unsafe-inline')) issues.push({ severity: 'High', issue: 'Uses unsafe-inline (Allows inline scripts/styles)' });
  if (cspLower.includes('unsafe-eval')) issues.push({ severity: 'High', issue: 'Uses unsafe-eval (Allows code execution from strings)' });
  if (cspLower.includes('http:')) issues.push({ severity: 'Medium', issue: 'Allows loading resources over insecure HTTP' });
  
  cspLower.split(';').map(d => d.trim()).forEach(dir => {
    if ((dir.startsWith('default-src') || dir.startsWith('script-src') || dir.startsWith('object-src')) && dir.includes('*')) {
       issues.push({ severity: 'High', issue: `Wildcard source (*) found in directive: ${dir.split(' ')[0]}` });
    }
  });
  return issues;
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

async function checkSecurityTxt(targetProtocol, hostname) {
  try {
    const res = await axios.get(`${targetProtocol}//${hostname}/.well-known/security.txt`, { timeout: 3000, validateStatus: () => true });
    if (res.status === 200 && (res.data.includes('Contact:') || res.data.includes('contact:'))) return { found: true };
  } catch (e) { }
  return { found: false };
}

function checkInfoLeakage(headers) {
  const leaks = [];
  if (headers['x-powered-by']) leaks.push(`X-Powered-By reveals backend stack: ${headers['x-powered-by']}`);
  if (headers['server']) leaks.push(`Server header reveals software version: ${headers['server']}`);
  if (headers['x-aspnet-version']) leaks.push(`X-AspNet-Version reveals .NET version: ${headers['x-aspnet-version']}`);
  return leaks;
}

function checkCors(headers, evilOrigin) {
  const corsHeader = headers['access-control-allow-origin'];
  if (!corsHeader) return { vulnerable: false, message: 'No CORS headers detected (Safe default)' };
  if (corsHeader === evilOrigin) return { vulnerable: true, message: `Server reflected malicious origin ${evilOrigin}` };
  if (corsHeader === '*') return { vulnerable: true, message: `Server allows any origin (*).` };
  return { vulnerable: false, message: `CORS header restricted to: ${corsHeader}` };
}

function analyzeCacheSecurity(headers) {
    const cacheControl = headers['cache-control'] || '';
    const pragma = headers['pragma'] || '';
    const expires = headers['expires'] || '';
    
    let isCached = true;
    let posture = 'Public / Cached';
    let vulnerable = false;

    if (cacheControl.includes('no-store') || cacheControl.includes('private')) {
        isCached = false;
        posture = 'Private / No-Store';
    }

    if (isCached && (cacheControl.includes('public') || cacheControl === '')) {
        // Just flag as generally cached, warning if it was meant to be sensitive
        vulnerable = true; 
    }

    return {
        cacheControl: cacheControl || 'Missing',
        pragma: pragma || 'Missing',
        expires: expires || 'Missing',
        isCached,
        posture,
        message: vulnerable ? 'Response is cacheable. Ensure this page contains no sensitive/authenticated data.' : 'Securely restricts downstream caching.'
    };
}

async function checkHttpMethods(targetUrl) {
    try {
        const res = await axios.options(targetUrl, { timeout: 3000, validateStatus: () => true });
        const allowed = res.headers['access-control-allow-methods'] || res.headers['allow'] || '';
        if (!allowed) return { methods: 'Not explicitly defined', vulnerable: false };
        
        const vulnMethods = ['TRACE', 'PUT', 'DELETE', 'TRACK'];
        const foundVuln = vulnMethods.filter(m => allowed.toUpperCase().includes(m));
        
        return { 
            methods: allowed, 
            vulnerable: foundVuln.length > 0, 
            message: foundVuln.length > 0 ? `Dangerous methods enabled: ${foundVuln.join(', ')}` : 'No dangerous HTTP methods detected.'
        };
    } catch (e) {
        return { methods: 'Failed to retrieve', vulnerable: false, message: 'Server blocked OPTIONS request.' };
    }
}

async function checkDirectoryListing(targetProtocol, hostname) {
    try {
        const res = await axios.get(`${targetProtocol}//${hostname}/assets/`, { timeout: 3000, validateStatus: () => true });
        const dataStr = String(res.data);
        if (res.status === 200 && (dataStr.includes('<title>Index of') || dataStr.includes('Index of /assets'))) {
            return { found: true, message: 'Directory listing is enabled on /assets/ exposing internal file structures.' };
        }
    } catch (e) {}
    return { found: false, message: 'Directory listing is securely disabled.' };
}

function parseHtmlSecurity(html, targetHostname, protocol) {
  const results = { sri: { totalExternalScripts: 0, scriptsMissingSRI: 0, totalExternalStyles: 0, stylesMissingSRI: 0 }, mixedContent: [], libraries: [], seo: [] };
  if (!html) return results;
  const $ = cheerio.load(html);
  
  const checkMixed = (url, tag) => {
    if (protocol === 'https:' && url && url.startsWith('http://')) results.mixedContent.push(`Insecure ${tag} loaded over HTTP: ${url}`);
  };

  $('img[src]').each((i, el) => checkMixed($(el).attr('src'), 'image'));
  $('iframe[src]').each((i, el) => checkMixed($(el).attr('src'), 'iframe'));
  
  $('script[src]').each((i, el) => {
    const src = $(el).attr('src');
    if (!src) return;
    checkMixed(src, 'script');
    
    if (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//')) {
      if (!src.includes(targetHostname)) {
        results.sri.totalExternalScripts++;
        if (!$(el).attr('integrity')) results.sri.scriptsMissingSRI++;
      }
    }
    
    const filename = src.split('/').pop().toLowerCase();
    const libPatterns = [
      { name: 'jQuery', regex: /jquery[-.]([0-9.]+)/ },
      { name: 'React', regex: /react(?:-dom)?[-.@]([0-9.]+)/ },
      { name: 'Vue', regex: /vue[-.@]([0-9.]+)/ },
      { name: 'Bootstrap', regex: /bootstrap[-.@]([0-9.]+)/ },
      { name: 'Angular', regex: /angular[-.@]([0-9.]+)/ }
    ];
    libPatterns.forEach(pattern => {
      const match = filename.match(pattern.regex);
      if (match) results.libraries.push({ name: pattern.name, version: match[1], file: filename });
    });
  });
  
  $('link[rel="stylesheet"][href]').each((i, el) => {
    const href = $(el).attr('href');
    if (!href) return;
    checkMixed(href, 'stylesheet');
    if (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//')) {
      if (!href.includes(targetHostname)) {
        results.sri.totalExternalStyles++;
        if (!$(el).attr('integrity')) results.sri.stylesMissingSRI++;
      }
    }
  });

  // SEO & Social Graph Metadata Spillage Check
  $('meta').each((i, el) => {
      const prop = $(el).attr('property') || $(el).attr('name');
      const content = $(el).attr('content');
      if (prop && content && (prop.startsWith('og:') || prop.startsWith('twitter:'))) {
          let hasSpillage = false;
          if (content.match(/(Exception|Error:|Stack trace|sql syntax|10\.\d\.\d\.\d|192\.168\.\d)/i)) {
              hasSpillage = true;
          }
          results.seo.push({ property: prop, content: content.substring(0, 80) + (content.length > 80 ? '...' : ''), spillage: hasSpillage });
      }
  });
  
  return results;
}

app.post('/api/analyze', async (req, res) => {
  let targetUrl = req.body.url;
  if (!targetUrl) return res.status(400).json({ error: 'URL parameter is required.' });
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = 'https://' + targetUrl;

  let parsedUrl;
  try {
    parsedUrl = new urlModule.URL(targetUrl);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  const hostname = parsedUrl.hostname;
  const protocol = parsedUrl.protocol;
  const evilOrigin = 'https://evil-domain-test.com';

  try {
    const response = await axios.get(parsedUrl.toString(), {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebGuardAuditor/4.0', 'Origin': evilOrigin },
      timeout: 15000, maxRedirects: 5, validateStatus: () => true
    });

    const headers = response.headers;
    const auditResults = [];
    let currentScore = 10; 

    const isHttps = protocol.toLowerCase() === 'https:';
    if (isHttps) currentScore += 15;

    for (const [headerKey, config] of Object.entries(SECURITY_HEADERS)) {
      const headerVal = headers[headerKey];
      const present = !!headerVal;
      if (present) currentScore += config.score;

      auditResults.push({
        key: headerKey, name: config.name, description: config.description, status: present ? 'Configured' : 'Missing',
        value: headerVal || null, scorePoints: present ? config.score : 0, maxPoints: config.score,
        nginx: config.nginx, apache: config.apache, express: config.express, nextjs: config.nextjs
      });
    }

    // Advanced Checks
    const cookieAnalysis = analyzeCookies(headers['set-cookie']);
    const cspIssues = evaluateDeepCSP(headers['content-security-policy']);
    const dnsSecurity = await checkDnsSecurity(hostname);
    const securityTxt = await checkSecurityTxt(protocol, hostname);
    const leaks = checkInfoLeakage(headers);
    const cors = checkCors(headers, evilOrigin);
    const cacheSecurity = analyzeCacheSecurity(headers);
    const httpMethods = await checkHttpMethods(parsedUrl.toString());
    const dirListing = await checkDirectoryListing(protocol, hostname);
    
    // HTML checks
    let htmlData = '';
    if (typeof response.data === 'string') htmlData = response.data;
    else if (Buffer.isBuffer(response.data)) htmlData = response.data.toString();
    const htmlSecurity = parseHtmlSecurity(htmlData, hostname, protocol);

    let tlsDetails = null;
    if (isHttps) {
      tlsDetails = await getTlsDetails(hostname);
      if (tlsDetails.success) {
        if (tlsDetails.isExpired) currentScore -= 30;
        else if (tlsDetails.tlsStatus.includes('Weak')) currentScore -= 15;
      } else currentScore -= 20;
    } else currentScore -= 30;

    // Score adjustments for features
    if (securityTxt.found) currentScore += 5;
    if (dnsSecurity.spf.found) currentScore += 5;
    if (dnsSecurity.dmarc.found) currentScore += 5;
    
    cookieAnalysis.forEach(c => { if (!c.secure || !c.httpOnly || c.sameSite === 'Missing') currentScore -= 2; });
    if (leaks.length > 0) currentScore -= 5;
    if (cors.vulnerable) currentScore -= 10;
    if (htmlSecurity.mixedContent.length > 0) currentScore -= 10;
    if (httpMethods.vulnerable) currentScore -= 15;
    if (dirListing.found) currentScore -= 15;

    const finalScore = Math.min(100, Math.max(0, currentScore));
    const grade = calculateGrade(finalScore);

    return res.json({
      success: true, domain: hostname, score: finalScore, grade,
      headersFound: auditResults.filter(h => h.status === 'Configured').length,
      headersMissing: auditResults.filter(h => h.status === 'Missing').length,
      totalHeadersCount: auditResults.length, isHttps, headers: auditResults, tlsDetails,
      advanced: {
        cookies: cookieAnalysis, cspIssues, dnsSecurity, securityTxt, leaks, cors,
        sriAnalysis: htmlSecurity.sri, mixedContent: htmlSecurity.mixedContent, libraries: htmlSecurity.libraries,
        cacheSecurity, httpMethods, dirListing, seo: htmlSecurity.seo
      }
    });

  } catch (error) { return res.status(500).json({ error: `Could not connect to target server. Error: ${error.message}` }); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`WebGuard Auditor server running on port ${PORT}`));
