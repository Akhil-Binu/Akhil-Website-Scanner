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

// List of security headers to audit with definitions and recommendations
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
    description: 'Restricts resource loading (JavaScript, CSS, Images) to trusted origins, preventing XSS and injection attacks.',
    score: 25,
    nginx: 'add_header Content-Security-Policy "default-src \'self\';" always;',
    apache: 'Header always set Content-Security-Policy "default-src \'self\';"',
    express: 'app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["\'self\'"] } }));',
    nextjs: '{\n  key: "Content-Security-Policy",\n  value: "default-src \'self\';"\n}'
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    description: 'Protects visitors against clickjacking by controlling whether the site can be embedded in an iframe.',
    score: 15,
    nginx: 'add_header X-Frame-Options "DENY" always;',
    apache: 'Header always set X-Frame-Options "DENY"',
    express: 'app.use(helmet.frameguard({ action: "deny" }));',
    nextjs: '{\n  key: "X-Frame-Options",\n  value: "DENY"\n}'
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    description: 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
    score: 10,
    nginx: 'add_header X-Content-Type-Options "nosniff" always;',
    apache: 'Header always set X-Content-Type-Options "nosniff"',
    express: 'app.use(helmet.noSniff());',
    nextjs: '{\n  key: "X-Content-Type-Options",\n  value: "nosniff"\n}'
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information is sent along with requests made from your site.',
    score: 10,
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    apache: 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    express: 'app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));',
    nextjs: '{\n  key: "Referrer-Policy",\n  value: "strict-origin-when-cross-origin"\n}'
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    description: 'Restricts the browser features and APIs (e.g. camera, microphone, geolocation) that the page can use.',
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
    const options = {
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false
    };

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
        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          tlsStatus = 'Weak (Deprecated)';
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
          tlsStatus
        });
      });

      socket.on('error', (err) => {
        socket.destroy();
        resolve({ success: false, error: err.message });
      });

      socket.setTimeout(6000, () => {
        socket.destroy();
        resolve({ success: false, error: 'TLS connection timeout' });
      });
    } catch (e) {
      resolve({ success: false, error: e.message });
    }
  });
}

// 1. Cookie Security Analyzer
function analyzeCookies(setCookieHeaders) {
  const cookies = [];
  if (!setCookieHeaders) return cookies;
  
  const headersArray = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  
  headersArray.forEach(cookieStr => {
    const parts = cookieStr.split(';').map(p => p.trim());
    const nameValue = parts[0].split('=');
    const name = nameValue[0];
    const isSecure = cookieStr.toLowerCase().includes('secure');
    const isHttpOnly = cookieStr.toLowerCase().includes('httponly');
    const samesiteMatch = cookieStr.match(/samesite=(strict|lax|none)/i);
    const sameSite = samesiteMatch ? samesiteMatch[1] : 'Missing';
    
    cookies.push({
      name: name,
      secure: isSecure,
      httpOnly: isHttpOnly,
      sameSite: sameSite
    });
  });
  return cookies;
}

// 2. Deep CSP Evaluator
function evaluateDeepCSP(cspHeader) {
  const issues = [];
  if (!cspHeader) return issues;
  
  const cspLower = cspHeader.toLowerCase();
  if (cspLower.includes('unsafe-inline')) {
    issues.push({ severity: 'High', issue: 'Uses unsafe-inline (Allows inline scripts/styles, risking XSS)' });
  }
  if (cspLower.includes('unsafe-eval')) {
    issues.push({ severity: 'High', issue: 'Uses unsafe-eval (Allows code execution from strings, risking XSS)' });
  }
  if (cspLower.includes('http:')) {
    issues.push({ severity: 'Medium', issue: 'Allows loading resources over insecure HTTP' });
  }
  
  // Basic check for wildcard in important directives
  const directives = cspLower.split(';').map(d => d.trim());
  directives.forEach(dir => {
    if ((dir.startsWith('default-src') || dir.startsWith('script-src') || dir.startsWith('object-src')) && dir.includes('*')) {
       issues.push({ severity: 'High', issue: `Wildcard source (*) found in directive: ${dir.split(' ')[0]}` });
    }
  });
  
  return issues;
}

// 3. DNS Security Checks (SPF & DMARC)
async function checkDnsSecurity(hostname) {
  const results = {
    spf: { found: false, record: null },
    dmarc: { found: false, record: null }
  };
  
  try {
    const txtRecords = await dns.resolveTxt(hostname);
    for (const recordArray of txtRecords) {
      const recordStr = recordArray.join('');
      if (recordStr.startsWith('v=spf1')) {
        results.spf.found = true;
        results.spf.record = recordStr;
      }
    }
  } catch (e) { /* Ignore DNS errors */ }
  
  try {
    const dmarcRecords = await dns.resolveTxt('_dmarc.' + hostname);
    for (const recordArray of dmarcRecords) {
      const recordStr = recordArray.join('');
      if (recordStr.startsWith('v=DMARC1')) {
        results.dmarc.found = true;
        results.dmarc.record = recordStr;
      }
    }
  } catch (e) { /* Ignore DNS errors */ }
  
  return results;
}

// 4. Security.txt Discovery
async function checkSecurityTxt(targetProtocol, hostname) {
  try {
    const res = await axios.get(`${targetProtocol}//${hostname}/.well-known/security.txt`, {
      timeout: 3000,
      validateStatus: () => true
    });
    if (res.status === 200 && (res.data.includes('Contact:') || res.data.includes('contact:'))) {
      return { found: true };
    }
  } catch (e) { /* Ignore errors */ }
  return { found: false };
}

// 5. Subresource Integrity (SRI) Check
function checkSRI(html, targetHostname) {
  const results = {
    totalExternalScripts: 0,
    scriptsMissingSRI: 0,
    totalExternalStyles: 0,
    stylesMissingSRI: 0
  };
  
  if (!html) return results;
  
  const $ = cheerio.load(html);
  
  $('script[src]').each((i, el) => {
    const src = $(el).attr('src');
    if (src && (src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//'))) {
      // Check if it's truly external (not a subpath or matching hostname)
      if (!src.includes(targetHostname)) {
        results.totalExternalScripts++;
        if (!$(el).attr('integrity')) {
          results.scriptsMissingSRI++;
        }
      }
    }
  });
  
  $('link[rel="stylesheet"][href]').each((i, el) => {
    const href = $(el).attr('href');
    if (href && (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//'))) {
      if (!href.includes(targetHostname)) {
        results.totalExternalStyles++;
        if (!$(el).attr('integrity')) {
          results.stylesMissingSRI++;
        }
      }
    }
  });
  
  return results;
}

app.post('/api/analyze', async (req, res) => {
  let targetUrl = req.body.url;
  if (!targetUrl) {
    return res.status(400).json({ error: 'URL parameter is required.' });
  }

  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = 'https://' + targetUrl;
  }

  let parsedUrl;
  try {
    parsedUrl = new urlModule.URL(targetUrl);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format.' });
  }

  const hostname = parsedUrl.hostname;
  const protocol = parsedUrl.protocol;

  try {
    const response = await axios.get(parsedUrl.toString(), {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebGuardAuditor/2.0'
      },
      timeout: 8000,
      maxRedirects: 5,
      validateStatus: () => true
    });

    const headers = response.headers;
    const auditResults = [];
    let currentScore = 10; 

    const isHttps = protocol.toLowerCase() === 'https:';
    if (isHttps) currentScore += 15;

    for (const [headerKey, config] of Object.entries(SECURITY_HEADERS)) {
      const headerVal = headers[headerKey];
      const present = !!headerVal;

      if (present) {
        currentScore += config.score;
      }

      auditResults.push({
        key: headerKey,
        name: config.name,
        description: config.description,
        status: present ? 'Configured' : 'Missing',
        value: headerVal || null,
        scorePoints: present ? config.score : 0,
        maxPoints: config.score,
        nginx: config.nginx,
        apache: config.apache,
        express: config.express,
        nextjs: config.nextjs
      });
    }

    // Advanced Checks
    const cookieAnalysis = analyzeCookies(headers['set-cookie']);
    const cspIssues = evaluateDeepCSP(headers['content-security-policy']);
    const dnsSecurity = await checkDnsSecurity(hostname);
    const securityTxt = await checkSecurityTxt(protocol, hostname);
    
    // Grab HTML Data
    let htmlData = '';
    if (typeof response.data === 'string') {
        htmlData = response.data;
    } else if (Buffer.isBuffer(response.data)) {
        htmlData = response.data.toString();
    }
    const sriAnalysis = checkSRI(htmlData, hostname);

    let tlsDetails = null;
    if (isHttps) {
      tlsDetails = await getTlsDetails(hostname);
      if (tlsDetails.success) {
        if (tlsDetails.isExpired) currentScore = Math.max(0, currentScore - 30);
        else if (tlsDetails.tlsStatus.includes('Weak')) currentScore = Math.max(0, currentScore - 15);
      } else {
        currentScore = Math.max(0, currentScore - 20);
      }
    } else {
      currentScore = Math.max(0, currentScore - 30);
    }

    // Score adjustments for new features
    if (securityTxt.found) currentScore += 5;
    if (dnsSecurity.spf.found) currentScore += 5;
    if (dnsSecurity.dmarc.found) currentScore += 5;
    if (cspIssues.length === 0 && headers['content-security-policy']) currentScore += 5;
    
    // Penalties
    cookieAnalysis.forEach(c => {
      if (!c.secure || !c.httpOnly || c.sameSite === 'Missing') {
        currentScore -= 2; // minor penalty for each insecure cookie
      }
    });

    const finalScore = Math.min(100, Math.max(0, currentScore));
    const grade = calculateGrade(finalScore);

    return res.json({
      success: true,
      domain: hostname,
      score: finalScore,
      grade,
      headersFound: auditResults.filter(h => h.status === 'Configured').length,
      headersMissing: auditResults.filter(h => h.status === 'Missing').length,
      totalHeadersCount: auditResults.length,
      isHttps,
      headers: auditResults,
      tlsDetails,
      advanced: {
        cookies: cookieAnalysis,
        cspIssues: cspIssues,
        dnsSecurity: dnsSecurity,
        securityTxt: securityTxt,
        sriAnalysis: sriAnalysis
      }
    });

  } catch (error) {
    return res.status(500).json({
      error: `Could not connect to target server. Error: ${error.message}`
    });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`WebGuard Auditor server running on port ${PORT}`);
});
