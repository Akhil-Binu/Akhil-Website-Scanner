document.addEventListener('DOMContentLoaded', () => {
    const auditForm = document.getElementById('auditForm');
    const targetUrlInput = document.getElementById('targetUrl');
    const submitBtn = document.getElementById('submitBtn');
    const loader = submitBtn.querySelector('.loader');
    const btnText = submitBtn.querySelector('.btn-text');
    const errorMessage = document.getElementById('errorMessage');
    
    const loadingSkeleton = document.getElementById('loadingSkeleton');
    const resultsSection = document.getElementById('resultsSection');
    
    // Result details element references
    const gradeRing = document.getElementById('gradeRing');
    const gradeValue = document.getElementById('gradeValue');
    const resultDomain = document.getElementById('resultDomain');
    const sslBadge = document.getElementById('sslBadge');
    const scoreBadge = document.getElementById('scoreBadge');
    const scorePercentage = document.getElementById('scorePercentage');
    const scoreBar = document.getElementById('scoreBar');
    const headersFoundCount = document.getElementById('headersFoundCount');
    const headersMissingCount = document.getElementById('headersMissingCount');
    
    // SSL Grid Elements
    const sslInfoCard = document.getElementById('sslInfoCard');
    const sslIssuer = document.getElementById('sslIssuer');
    const sslSubject = document.getElementById('sslSubject');
    const sslProtocol = document.getElementById('sslProtocol');
    const sslCipher = document.getElementById('sslCipher');
    const sslExpiry = document.getElementById('sslExpiry');
    const sslStatusBadge = document.getElementById('sslStatusBadge');
    
    const headersList = document.getElementById('headersList');

    // Tab Controls
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            button.classList.add('active');
            document.getElementById(`tab-${targetTab}`).classList.add('active');
        });
    });

    // Form Submit Handler
    auditForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        let url = targetUrlInput.value.trim();
        if (!url) return;

        // Reset visibility states
        errorMessage.classList.add('hidden');
        resultsSection.classList.add('hidden');
        loadingSkeleton.classList.remove('hidden');
        
        // Show loader state
        submitBtn.disabled = true;
        btnText.classList.add('hidden');
        loader.classList.remove('hidden');

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to complete configuration audit.');
            }

            renderResults(data);

        } catch (error) {
            errorMessage.textContent = error.message;
            errorMessage.classList.remove('hidden');
        } finally {
            loadingSkeleton.classList.add('hidden');
            submitBtn.disabled = false;
            btnText.classList.remove('hidden');
            loader.classList.add('hidden');
        }
    });

    function renderResults(data) {
        // Domain and Status Grade
        resultDomain.textContent = data.domain;
        gradeValue.textContent = data.grade;
        scoreBadge.textContent = `Score: ${data.score}/100`;
        scorePercentage.textContent = `${data.score}%`;
        scoreBar.style.width = `${data.score}%`;

        // Update Grade Ring colors based on security level
        updateGradeRingStyle(data.grade);

        headersFoundCount.textContent = data.headersFound;
        headersMissingCount.textContent = data.headersMissing;

        // SSL certificate parsing details
        if (data.isHttps && data.tlsDetails && data.tlsDetails.success) {
            sslInfoCard.classList.remove('hidden');
            sslBadge.classList.remove('hidden');
            sslBadge.textContent = 'SSL Protected';
            sslBadge.className = 'badge secure';

            sslIssuer.textContent = data.tlsDetails.issuer;
            sslSubject.textContent = data.tlsDetails.subject;
            sslProtocol.textContent = data.tlsDetails.protocol;
            sslCipher.textContent = data.tlsDetails.cipherName;
            
            if (data.tlsDetails.isExpired) {
                sslExpiry.textContent = 'Expired Certificate';
                sslStatusBadge.textContent = 'Expired';
                sslStatusBadge.className = 'ssl-badge expired';
            } else {
                sslExpiry.textContent = `In ${data.tlsDetails.daysRemaining} Days (${new Date(data.tlsDetails.validTo).toLocaleDateString()})`;
                sslStatusBadge.textContent = `Active & Secure (${data.tlsDetails.tlsStatus})`;
                sslStatusBadge.className = 'ssl-badge secure';
            }
        } else {
            sslBadge.textContent = 'No SSL Connection';
            sslBadge.className = 'badge insecure';
            sslInfoCard.classList.add('hidden');
        }

        // Render HTTP Headers check list cards
        headersList.innerHTML = '';
        data.headers.forEach(header => {
            const row = document.createElement('div');
            row.className = 'header-row';

            const configured = header.status === 'Configured';
            const statusClass = configured ? 'configured' : 'missing';
            const valueText = configured ? header.value : 'Not Configured';

            row.innerHTML = `
                <div class="header-summary">
                    <div class="header-title-block">
                        <span class="header-name">${header.name}</span>
                        <span class="header-tagline">${configured ? 'Correctly implemented' : 'Gaps detected in protection'}</span>
                    </div>
                    <div class="header-status-block">
                        <span class="status-indicator ${statusClass}">${header.status}</span>
                        <span class="arrow-icon">▼</span>
                    </div>
                </div>
                <div class="header-detail">
                    <div class="detail-content">
                        <p class="detail-desc">${header.description}</p>
                        <div class="detail-value-block">
                            <div class="detail-value-label">Current Configuration Value</div>
                            <div class="detail-value-content">${escapeHTML(valueText)}</div>
                        </div>
                    </div>
                </div>
            `;

            // Toggle Expand Accordion
            row.querySelector('.header-summary').addEventListener('click', () => {
                const isOpen = row.classList.contains('open');
                // Close others if open
                document.querySelectorAll('.header-row').forEach(r => r.classList.remove('open'));
                if (!isOpen) {
                    row.classList.add('open');
                }
            });

            headersList.appendChild(row);
        });

        // Set up Remediation Code tabs templates
        generateRemediationConfig(data.headers);
        
        // Render Advanced Audits (DNS, Cookies, SRI, CSP)
        if (data.advanced) {
            renderAdvancedAudits(data.advanced);
        }

        // Transition results into view
        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function renderAdvancedAudits(advanced) {
        // 1. Render DNS Security
        const dnsGrid = document.getElementById('dnsGrid');
        dnsGrid.innerHTML = '';
        
        const spfStatus = advanced.dnsSecurity.spf.found ? 'Configured' : 'Missing';
        const spfClass = advanced.dnsSecurity.spf.found ? 'configured' : 'missing';
        dnsGrid.innerHTML += `
            <div class="dns-record">
                <div class="dns-record-header">
                    <span class="dns-record-title">SPF Record (Email Sender Policy)</span>
                    <span class="status-indicator ${spfClass}">${spfStatus}</span>
                </div>
                <div class="dns-record-content">${advanced.dnsSecurity.spf.record || 'No SPF TXT record found'}</div>
            </div>`;
            
        const dmarcStatus = advanced.dnsSecurity.dmarc.found ? 'Configured' : 'Missing';
        const dmarcClass = advanced.dnsSecurity.dmarc.found ? 'configured' : 'missing';
        dnsGrid.innerHTML += `
            <div class="dns-record">
                <div class="dns-record-header">
                    <span class="dns-record-title">DMARC Record (Email Authentication)</span>
                    <span class="status-indicator ${dmarcClass}">${dmarcStatus}</span>
                </div>
                <div class="dns-record-content">${advanced.dnsSecurity.dmarc.record || 'No DMARC TXT record found'}</div>
            </div>`;

        // 2. Render Cookie Security
        const cookieList = document.getElementById('cookieList');
        cookieList.innerHTML = '';
        if (!advanced.cookies || advanced.cookies.length === 0) {
            cookieList.innerHTML = '<div class="cookie-item" style="text-align:center; color: var(--text-secondary);">No cookies detected in response headers.</div>';
        } else {
            advanced.cookies.forEach(c => {
                const secClass = c.secure ? 'good' : 'bad';
                const httpClass = c.httpOnly ? 'good' : 'bad';
                const sameClass = c.sameSite !== 'Missing' ? 'good' : 'bad';
                
                cookieList.innerHTML += `
                    <div class="cookie-item">
                        <div class="cookie-name">${escapeHTML(c.name)}</div>
                        <div class="cookie-flags">
                            <span class="flag ${secClass}">Secure: ${c.secure ? 'Yes' : 'No'}</span>
                            <span class="flag ${httpClass}">HttpOnly: ${c.httpOnly ? 'Yes' : 'No'}</span>
                            <span class="flag ${sameClass}">SameSite: ${c.sameSite}</span>
                        </div>
                    </div>`;
            });
        }

        // 3. Render Advanced Inspections (Deep CSP, Security.txt, SRI)
        const advancedList = document.getElementById('advancedList');
        advancedList.innerHTML = '';

        // Security.txt
        const secTxtStatus = advanced.securityTxt.found ? 'Found' : 'Missing';
        const secTxtClass = advanced.securityTxt.found ? 'configured' : 'missing';
        advancedList.innerHTML += `
            <li class="advanced-item">
                <div class="advanced-item-title">
                    <span>/.well-known/security.txt</span>
                    <span class="status-indicator ${secTxtClass}">${secTxtStatus}</span>
                </div>
                <div class="advanced-item-desc">A standardized file for vulnerability disclosure policies.</div>
            </li>`;

        // SRI
        const sriIssues = advanced.sriAnalysis.scriptsMissingSRI + advanced.sriAnalysis.stylesMissingSRI;
        const sriTotal = advanced.sriAnalysis.totalExternalScripts + advanced.sriAnalysis.totalExternalStyles;
        let sriStatus = 'N/A';
        let sriClass = 'configured';
        if (sriTotal > 0) {
            sriStatus = sriIssues === 0 ? 'Passed' : 'Issues Found';
            sriClass = sriIssues === 0 ? 'configured' : 'missing';
        }
        
        advancedList.innerHTML += `
            <li class="advanced-item">
                <div class="advanced-item-title">
                    <span>Subresource Integrity (SRI)</span>
                    <span class="status-indicator ${sriClass}">${sriStatus}</span>
                </div>
                <div class="advanced-item-desc">
                    Detected ${sriTotal} external scripts/styles. 
                    ${sriIssues > 0 ? `<strong style="color:var(--danger)">${sriIssues} missing integrity hash.</strong>` : 'All secure or none found.'}
                </div>
            </li>`;

        // Deep CSP
        if (advanced.cspIssues && advanced.cspIssues.length > 0) {
            advanced.cspIssues.forEach(issue => {
                advancedList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>CSP Misconfiguration</span>
                            <span class="status-indicator missing">${issue.severity} Risk</span>
                        </div>
                        <div class="advanced-item-desc" style="color:var(--warning)">${issue.issue}</div>
                    </li>`;
            });
        } else {
             advancedList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>Deep CSP Evaluator</span>
                            <span class="status-indicator configured">No Issues</span>
                        </div>
                        <div class="advanced-item-desc">No insecure directives (e.g., unsafe-inline, *) detected.</div>
                    </li>`;
        }
    }

    function updateGradeRingStyle(grade) {
        let colors = {
            'A+': '#10B981',
            'A': '#34D399',
            'B': '#60A5FA',
            'C': '#F59E0B',
            'D': '#F97316',
            'F': '#EF4444'
        };
        const color = colors[grade] || '#FFFFFF';
        gradeRing.style.border = `4px solid ${color}40`;
        gradeRing.style.boxShadow = `0 0 20px ${color}30`;
        gradeValue.style.color = color;
    }

    function generateRemediationConfig(headers) {
        const missingHeaders = headers.filter(h => h.status === 'Missing');

        if (missingHeaders.length === 0) {
            document.getElementById('code-nginx').textContent = '# Excellent! All security headers are already configured.';
            document.getElementById('code-apache').textContent = '# Excellent! All security headers are already configured.';
            document.getElementById('code-express').textContent = '// Excellent! All security headers are already configured.';
            document.getElementById('code-nextjs').textContent = '// Excellent! All security headers are already configured.';
            return;
        }

        // Generate Config Block based on platform
        let nginxConfig = '# Nginx Web Server Configuration\n# Put these directives inside your server {} blocks:\n\n';
        let apacheConfig = '# Apache HTTP Server Configuration\n# Add these directives to your .htaccess or httpd.conf:\n\n<IfModule mod_headers.c>\n';
        let expressConfig = '// Node.js Express Server Setup\n// Install helmet: npm install helmet\n// Then use these middleware configurations:\n\nconst express = require(\'express\');\nconst helmet = require(\'helmet\');\nconst app = express();\n\n';
        let nextjsConfig = '// Next.js Security Headers Config\n// Add this object setup in your next.config.js headers config:\n\nmodule.exports = {\n  async headers() {\n    return [\n      {\n        source: \'/(.*)\',\n        headers: [\n';

        missingHeaders.forEach(h => {
            nginxConfig += `  ${h.nginx}\n`;
            apacheConfig += `  ${h.apache}\n`;
            expressConfig += `// Remediation for ${h.name}\n${h.express}\n\n`;
            nextjsConfig += `          // Remediation for ${h.name}\n          ${h.nextjs.replace(/\n/g, '\n          ')},\n`;
        });

        apacheConfig += '</IfModule>\n';
        nextjsConfig += '        ]\n      }\n    ];\n  }\n};';

        document.getElementById('code-nginx').textContent = nginxConfig;
        document.getElementById('code-apache').textContent = apacheConfig;
        document.getElementById('code-express').textContent = expressConfig;
        document.getElementById('code-nextjs').textContent = nextjsConfig;
    }

    function escapeHTML(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
});

// Clipboard Helper
function copyConfig(elementId) {
    const code = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(code).then(() => {
        const btn = document.querySelector(`.tab-pane.active .copy-btn`);
        const originalText = btn.textContent;
        btn.textContent = 'Copied!';
        btn.style.background = 'var(--accent)';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = 'rgba(255, 255, 255, 0.08)';
        }, 2000);
    });
}
