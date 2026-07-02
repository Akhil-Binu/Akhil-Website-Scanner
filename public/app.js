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

    // PDF Export functionality
    const exportPdfBtn = document.getElementById('exportPdfBtn');
    if (exportPdfBtn) {
        exportPdfBtn.addEventListener('click', async () => {
            if (!window.lastScanData) return;
            const data = window.lastScanData;
            
            const originalText = exportPdfBtn.textContent;
            exportPdfBtn.textContent = 'Generating Professional PDF...';
            exportPdfBtn.disabled = true;

            try {
                // Populate the hidden template
                document.getElementById('pdfTargetDomain').textContent = data.domain;
                document.getElementById('pdfScanDate').textContent = new Date().toISOString().split('T')[0];
                const gradeElem = document.getElementById('pdfGrade');
                gradeElem.textContent = data.grade;
                gradeElem.style.background = data.grade === 'A' || data.grade === 'B' ? '#10b981' : (data.grade === 'C' ? '#eab308' : '#ef4444');
                document.getElementById('pdfScore').textContent = data.score + '/100';
                
                // AI Insights
                document.getElementById('pdfAiPhishing').textContent = data.aiInsights?.phishingAnalysis || 'No AI data available.';
                document.getElementById('pdfAiAttack').textContent = data.aiInsights?.attackNarrative || 'No AI data available.';
                document.getElementById('pdfAiJs').textContent = data.aiInsights?.jsAnalysis || 'No JS analysis available.';
                
                // Active Exploits
                const dastTable = document.getElementById('pdfDastTableBody');
                dastTable.innerHTML = '';
                let hasDast = false;
                if (data.advanced && data.advanced.dast) {
                    const d = data.advanced.dast;
                    const addVulns = (arr, type) => {
                        if(arr && arr.length > 0) {
                            hasDast = true;
                            arr.forEach(hit => dastTable.innerHTML += `<tr><td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; color: #ef4444;">${type}</td><td style="padding: 10px; border: 1px solid #e2e8f0;">?${escapeHTML(hit.param)}= <br><code style="background: #f1f5f9; padding: 2px 4px; display: block; margin-top: 5px;">${escapeHTML(hit.payload)}</code></td></tr>`);
                        }
                    };
                    addVulns(d.sqli, 'SQL Injection');
                    addVulns(d.xss, 'Reflected XSS');
                    addVulns(d.lfi, 'Directory Traversal');
                    addVulns(d.ssrf, 'SSRF');
                }
                if (!hasDast) dastTable.innerHTML = '<tr><td colspan="2" style="padding: 10px; border: 1px solid #e2e8f0;">No active vulnerabilities detected.</td></tr>';
                
                // Headers Table
                const headersTable = document.getElementById('pdfHeadersTableBody');
                headersTable.innerHTML = '';
                if (data.headers && data.headers.length > 0) {
                    data.headers.forEach(h => {
                        const statusColor = h.status === 'Configured' ? '#10b981' : '#ef4444';
                        headersTable.innerHTML += `<tr>
                            <td style="padding: 10px; border: 1px solid #cbd5e1; font-weight: bold;">${escapeHTML(h.name)}</td>
                            <td style="padding: 10px; border: 1px solid #cbd5e1; color: ${statusColor}; font-weight: bold;">${h.status}</td>
                            <td style="padding: 10px; border: 1px solid #cbd5e1; color: #475569;">${escapeHTML(h.description)}</td>
                        </tr>`;
                    });
                } else {
                    headersTable.innerHTML = '<tr><td colspan="3" style="padding: 10px; border: 1px solid #cbd5e1;">No headers analyzed.</td></tr>';
                }

                // SSL/TLS Details
                const tlsTable = document.getElementById('pdfTlsTableBody');
                tlsTable.innerHTML = '';
                if (data.tlsDetails && data.tlsDetails.success) {
                    const tls = data.tlsDetails;
                    tlsTable.innerHTML += `<tr><td style="padding: 10px; border: 1px solid #cbd5e1; font-weight: bold; width: 30%; background: #f8fafc;">Issuer</td><td style="padding: 10px; border: 1px solid #cbd5e1;">${escapeHTML(tls.issuer)}</td></tr>`;
                    tlsTable.innerHTML += `<tr><td style="padding: 10px; border: 1px solid #cbd5e1; font-weight: bold; background: #f8fafc;">Valid Until</td><td style="padding: 10px; border: 1px solid #cbd5e1;">${escapeHTML(tls.validTo)} (${tls.daysRemaining} days remaining)</td></tr>`;
                    tlsTable.innerHTML += `<tr><td style="padding: 10px; border: 1px solid #cbd5e1; font-weight: bold; background: #f8fafc;">Protocol & Cipher</td><td style="padding: 10px; border: 1px solid #cbd5e1;">${escapeHTML(tls.protocol)} / ${escapeHTML(tls.cipherName)}</td></tr>`;
                } else {
                    tlsTable.innerHTML = '<tr><td style="padding: 10px; border: 1px solid #cbd5e1; color: #ef4444; font-weight: bold;">Connection is not secure (HTTP or Invalid SSL)</td></tr>';
                }

                // Compliance
                const compList = document.getElementById('pdfComplianceList');
                compList.innerHTML = '';
                const missingHeaders = data.headers ? data.headers.filter(h => h.status === 'Missing').length : 0;
                compList.innerHTML += `<li style="margin-bottom: 8px;"><strong>OWASP Top 10 A05:2021 (Security Misconfiguration):</strong> <span style="color: ${missingHeaders > 0 ? '#ef4444' : '#10b981'}; font-weight: bold;">${missingHeaders > 0 ? 'FAIL ('+missingHeaders+' missing headers)' : 'PASS'}</span></li>`;
                const tlsFail = !data.tlsDetails || data.tlsDetails.success === false;
                compList.innerHTML += `<li style="margin-bottom: 8px;"><strong>PCI-DSS Req 4.1 (Strong Cryptography):</strong> <span style="color: ${tlsFail ? '#ef4444' : '#10b981'}; font-weight: bold;">${tlsFail ? 'FAIL' : 'PASS'}</span></li>`;
                if (hasDast) {
                    compList.innerHTML += `<li style="margin-bottom: 8px;"><strong>OWASP Top 10 A03:2021 (Injection):</strong> <span style="color: #ef4444; font-weight: bold;">FAIL (Active exploits found)</span></li>`;
                }
                
                // Infra
                document.getElementById('pdfOpenPorts').textContent = (data.advanced && data.advanced.openPorts && data.advanced.openPorts.length > 0) ? data.advanced.openPorts.join(', ') : 'None / Filtered';
                document.getElementById('pdfTechStack').textContent = (data.advanced && data.advanced.infra) ? data.advanced.infra.server : 'Unknown';
                document.getElementById('pdfSubdomains').textContent = (data.advanced && data.advanced.subdomains && data.advanced.subdomains.length > 0) ? data.advanced.subdomains.join(', ') : 'None found';
                document.getElementById('pdfWaf').textContent = (data.advanced && data.advanced.waf) ? (data.advanced.waf.detected ? data.advanced.waf.provider : data.advanced.waf) : 'Not Detected';

                // --- Extended Multi-Page Data Population ---
                if (data.advanced) {
                    const adv = data.advanced;
                    
                    // CSP
                    const cspList = document.getElementById('pdfCspList');
                    cspList.innerHTML = '';
                    if (adv.cspIssues && adv.cspIssues.length > 0) {
                        adv.cspIssues.forEach(iss => cspList.innerHTML += `<li style="margin-bottom: 5px; color: #ef4444;">❌ ${escapeHTML(iss)}</li>`);
                    } else {
                        cspList.innerHTML = '<li style="color: #10b981;">✅ CSP is strictly configured.</li>';
                    }

                    // Cookies
                    const cookiesTable = document.getElementById('pdfCookiesTableBody');
                    cookiesTable.innerHTML = '';
                    if (adv.cookies && adv.cookies.details && adv.cookies.details.length > 0) {
                        adv.cookies.details.forEach(c => {
                            cookiesTable.innerHTML += `<tr>
                                <td style="padding: 8px; border: 1px solid #cbd5e1; word-break: break-all;">${escapeHTML(c.name)}</td>
                                <td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; color: ${c.httpOnly ? '#10b981' : '#ef4444'}">${c.httpOnly ? 'Yes' : 'No'}</td>
                                <td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; color: ${c.secure ? '#10b981' : '#ef4444'}">${c.secure ? 'Yes' : 'No'}</td>
                                <td style="padding: 8px; border: 1px solid #cbd5e1; text-align: center; color: ${c.sameSite !== 'None' ? '#10b981' : '#ef4444'}">${escapeHTML(c.sameSite)}</td>
                            </tr>`;
                        });
                    } else {
                        cookiesTable.innerHTML = '<tr><td colspan="4" style="padding: 8px; border: 1px solid #cbd5e1; text-align: center;">No cookies detected.</td></tr>';
                    }

                    // DNS (SPF/DMARC)
                    const dnsTable = document.getElementById('pdfDnsTableBody');
                    dnsTable.innerHTML = '';
                    if (adv.dnsSecurity) {
                        const spf = adv.dnsSecurity.spf;
                        const dmarc = adv.dnsSecurity.dmarc;
                        dnsTable.innerHTML += `<tr><td style="padding: 8px; border: 1px solid #cbd5e1; background: #f8fafc; font-weight: bold; width: 20%;">SPF Record</td><td style="padding: 8px; border: 1px solid #cbd5e1; color: ${spf.present ? '#10b981' : '#ef4444'}">${spf.present ? 'Present' : 'Missing'}</td><td style="padding: 8px; border: 1px solid #cbd5e1; word-break: break-all;">${spf.record ? escapeHTML(spf.record) : 'N/A'}</td></tr>`;
                        dnsTable.innerHTML += `<tr><td style="padding: 8px; border: 1px solid #cbd5e1; background: #f8fafc; font-weight: bold;">DMARC Record</td><td style="padding: 8px; border: 1px solid #cbd5e1; color: ${dmarc.present ? '#10b981' : '#ef4444'}">${dmarc.present ? 'Present' : 'Missing'}</td><td style="padding: 8px; border: 1px solid #cbd5e1; word-break: break-all;">${dmarc.record ? escapeHTML(dmarc.record) : 'N/A'}</td></tr>`;
                    }

                    // Fuzzer
                    const fuzzerList = document.getElementById('pdfFuzzerList');
                    fuzzerList.innerHTML = '';
                    let fuzzCount = 0;
                    if (adv.fuzzer) {
                        const addFuzz = (arr, prefix) => {
                            if(arr && arr.length > 0) {
                                arr.forEach(f => {
                                    fuzzCount++;
                                    fuzzerList.innerHTML += `<li><span style="color: #ef4444; font-weight: bold; margin-right: 10px;">HTTP ${f.status}</span> <span style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px;">${prefix}${escapeHTML(f.path)}</span></li>`;
                                });
                            }
                        };
                        addFuzz(adv.fuzzer.exposedFiles, 'File: ');
                        addFuzz(adv.fuzzer.hiddenDirs, 'Dir: ');
                        addFuzz(adv.fuzzer.apis, 'API: ');
                    }
                    if (fuzzCount === 0) fuzzerList.innerHTML = '<li>No sensitive exposed paths detected.</li>';

                    // Leaks & Secrets
                    const leaksList = document.getElementById('pdfLeaksList');
                    const secretsList = document.getElementById('pdfSecretsList');
                    leaksList.innerHTML = '';
                    secretsList.innerHTML = '';
                    
                    if (adv.leaks && adv.leaks.length > 0) {
                        adv.leaks.forEach(l => leaksList.innerHTML += `<li style="color: #ef4444;">${escapeHTML(l)}</li>`);
                    } else {
                        leaksList.innerHTML = '<li style="color: #64748b;">No header information leaks detected.</li>';
                    }
                    
                    if (adv.domSec && adv.domSec.secrets && adv.domSec.secrets.length > 0) {
                        adv.domSec.secrets.forEach(s => secretsList.innerHTML += `<li style="color: #ef4444; word-break: break-all;"><code>${escapeHTML(s)}</code></li>`);
                    } else {
                        secretsList.innerHTML = '<li style="color: #64748b;">No hardcoded secrets detected in HTML source.</li>';
                    }
                }


                // Temporarily show for rendering
                const element = document.getElementById('pdfReportTemplate');
                element.style.display = 'block';

                const opt = {
                  margin:       [0.4, 0.4, 0.4, 0.4],
                  filename:     `Akhil_WebGuard_Executive_Report_${data.domain}.pdf`,
                  image:        { type: 'jpeg', quality: 0.98 },
                  html2canvas:  { scale: 2, useCORS: true, letterRendering: true },
                  jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' },
                  pagebreak:    { mode: ['css', 'legacy'] }
                };

                await html2pdf().set(opt).from(element).save();
                
                element.style.display = 'none';

            } catch (err) {
                console.error("Failed to export PDF", err);
            } finally {
                exportPdfBtn.textContent = originalText;
                exportPdfBtn.disabled = false;
            }
        });
    }

    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            button.classList.add('active');
            document.getElementById(`tab-${targetTab}`).classList.add('active');
        });
    });

    const dastModeBtn = document.getElementById('dastModeBtn');
    const sastModeBtn = document.getElementById('sastModeBtn');
    const dastModeContainer = document.getElementById('dastModeContainer');
    const sastModeContainer = document.getElementById('sastModeContainer');
    const toggleHeadersBtn = document.getElementById('toggleHeadersBtn');
    const customHeadersContainer = document.getElementById('customHeadersContainer');
    const customHeadersInput = document.getElementById('customHeadersInput');
    const sastSubmitBtn = document.getElementById('sastSubmitBtn');
    const sastCodeInput = document.getElementById('sastCodeInput');
    const sastResults = document.getElementById('sastResults');

    // UI Toggles
    const bulkModeBtn = document.getElementById('bulkModeBtn');
    const scheduleModeBtn = document.getElementById('scheduleModeBtn');
    const bulkModeContainer = document.getElementById('bulkModeContainer');
    const scheduleModeContainer = document.getElementById('scheduleModeContainer');

    const switchTab = (activeBtn, activeContainer) => {
        if(dastModeBtn) dastModeBtn.classList.remove('active');
        if(sastModeBtn) sastModeBtn.classList.remove('active');
        if(bulkModeBtn) bulkModeBtn.classList.remove('active');
        if(scheduleModeBtn) scheduleModeBtn.classList.remove('active');
        
        if(dastModeContainer) dastModeContainer.classList.add('hidden');
        if(sastModeContainer) sastModeContainer.classList.add('hidden');
        if(bulkModeContainer) bulkModeContainer.classList.add('hidden');
        if(scheduleModeContainer) scheduleModeContainer.classList.add('hidden');
        
        activeBtn.classList.add('active');
        activeContainer.classList.remove('hidden');
    };

    if(dastModeBtn) dastModeBtn.addEventListener('click', () => switchTab(dastModeBtn, dastModeContainer));
    if(sastModeBtn) sastModeBtn.addEventListener('click', () => switchTab(sastModeBtn, sastModeContainer));
    if(bulkModeBtn) bulkModeBtn.addEventListener('click', () => switchTab(bulkModeBtn, bulkModeContainer));
    if(scheduleModeBtn) scheduleModeBtn.addEventListener('click', () => { switchTab(scheduleModeBtn, scheduleModeContainer); loadWatchlist(); });
    
    if(toggleHeadersBtn) toggleHeadersBtn.addEventListener('click', () => { customHeadersContainer.classList.toggle('hidden'); document.getElementById('headerToggleIcon').textContent = customHeadersContainer.classList.contains('hidden') ? '▶' : '▼'; });


    // SAST Submit Logic
    if(sastSubmitBtn) sastSubmitBtn.addEventListener('click', async () => {
        const code = sastCodeInput.value.trim();
        if(!code) return;
        sastSubmitBtn.querySelector('.btn-text').classList.add('hidden');
        sastSubmitBtn.querySelector('.loader').classList.remove('hidden');
        sastSubmitBtn.disabled = true;
        sastResults.classList.add('hidden');
        try {
            const res = await fetch('/api/sast', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) });
            const data = await res.json();
            sastResults.textContent = data.report || data.error;
            sastResults.classList.remove('hidden');
        } catch (e) {
            sastResults.textContent = "Error communicating with AI engine.";
            sastResults.classList.remove('hidden');
        }
        sastSubmitBtn.querySelector('.btn-text').classList.remove('hidden');
        sastSubmitBtn.querySelector('.loader').classList.add('hidden');
        sastSubmitBtn.disabled = false;
    });

    // Form Submit Handler
    auditForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        let url = targetUrlInput.value.trim();
        let headers = customHeadersInput ? customHeadersInput.value.trim() : '';
        if (!url) return;

        // Reset visibility states
        errorMessage.classList.add('hidden');
        resultsSection.classList.add('hidden');
        loadingSkeleton.classList.remove('hidden');
        submitBtn.querySelector('.btn-text').classList.add('hidden');
        submitBtn.querySelector('.loader').classList.remove('hidden');
        submitBtn.disabled = true;

        try {
            const sessionCookie = document.getElementById('sessionCookieInput') ? document.getElementById('sessionCookieInput').value.trim() : '';
            const bearerToken = document.getElementById('bearerTokenInput') ? document.getElementById('bearerTokenInput').value.trim() : '';
            const authToken = localStorage.getItem('wg_token');
            const fetchHeaders = { 'Content-Type': 'application/json' };
            if (authToken) fetchHeaders['Authorization'] = `Bearer ${authToken}`;

            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: fetchHeaders,
                body: JSON.stringify({ url, headers, sessionCookie: sessionCookie || undefined, bearerToken: bearerToken || undefined })
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
        window.lastScanData = data;
        
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
                const sslStatus = `Valid • Exp: ${data.tlsDetails.daysRemaining || 0}d • ${data.tlsDetails.supportsHttp2 ? 'HTTP/2 Supported' : 'HTTP/1.1 Only'}`;
                sslStatusBadge.textContent = `Active & Secure (${sslStatus})`;
                sslStatusBadge.className = 'ssl-badge secure';
            }
            
            document.getElementById('sslSans').textContent = (data.tlsDetails.sans && data.tlsDetails.sans.length > 0) ? data.tlsDetails.sans.join(', ') : 'None Detected';
            document.getElementById('sslOcsp').textContent = (data.tlsDetails.tlsDetails && data.tlsDetails.ocsp && data.tlsDetails.ocsp.length > 0) ? data.tlsDetails.ocsp.join(', ') : 'None Detected';
            
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
            renderAdvancedAudits(data.advanced, data);
        }

        // Render AI Insights
        const aiContainer = document.getElementById('aiInsightsContainer');
        const chatBtn = document.getElementById('openChatBtn');
        if (data.aiInsights && aiContainer) {
            aiContainer.classList.remove('hidden');
            document.getElementById('aiPhishingText').textContent = data.aiInsights.phishingAnalysis;
            document.getElementById('aiAttackText').textContent = data.aiInsights.attackNarrative;
            document.getElementById('aiJsText').textContent = data.aiInsights.jsAnalysis;
            
            // Enable Chat Button
            if (chatBtn) {
                chatBtn.classList.remove('hidden');
                window.lastAuditContext = data; // store globally for chat
            }
        } else if (aiContainer) {
            aiContainer.classList.add('hidden');
        }

        // Transition results into view
        resultsSection.classList.remove('hidden');
        if (advanced) {
            window.renderD3Map(advanced, data.domain);
        }
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function renderAdvancedAudits(advanced, data) {
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

        // 4. Render Leakage, CORS, and Mixed Content
        const leakageList = document.getElementById('leakageList');
        if (leakageList) leakageList.innerHTML = '';

        // CORS
        if (advanced.cors) {
            const corsClass = advanced.cors.vulnerable ? 'missing' : 'configured';
            const corsText = advanced.cors.vulnerable ? 'Vulnerable' : 'Safe';
            leakageList.innerHTML += `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>CORS Configuration</span>
                        <span class="status-indicator ${corsClass}">${corsText}</span>
                    </div>
                    <div class="advanced-item-desc">${advanced.cors.message}</div>
                </li>`;
        }

        // Info Leaks
        if (advanced.leaks && advanced.leaks.length > 0) {
            advanced.leaks.forEach(leak => {
                leakageList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>Information Leakage</span>
                            <span class="status-indicator missing">Warning</span>
                        </div>
                        <div class="advanced-item-desc" style="color:var(--warning)">${leak}</div>
                    </li>`;
            });
        } else {
            leakageList.innerHTML += `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>Information Leakage</span>
                        <span class="status-indicator configured">No Leaks</span>
                    </div>
                    <div class="advanced-item-desc">No sensitive server/stack version headers detected.</div>
                </li>`;
        }

        // Mixed Content
        if (advanced.mixedContent && advanced.mixedContent.length > 0) {
            advanced.mixedContent.forEach(mc => {
                leakageList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>Mixed Content</span>
                            <span class="status-indicator missing">Insecure Resource</span>
                        </div>
                        <div class="advanced-item-desc" style="color:var(--warning)">${escapeHTML(mc)}</div>
                    </li>`;
            });
        }

        // 5. Third-Party Libraries Audit
        const libraryList = document.getElementById('libraryList');
        if (libraryList) {
            libraryList.innerHTML = '';
            if (!advanced.libraries || advanced.libraries.length === 0) {
                libraryList.innerHTML = `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>Library Check</span>
                            <span class="status-indicator configured">Clean</span>
                        </div>
                        <div class="advanced-item-desc">No common vulnerable frontend libraries detected in HTML source.</div>
                    </li>`;
            } else {
                libraryList.innerHTML = advanced.libraries.map(lib => `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>${lib.name} Detected</span>
                            <span class="status-indicator">Version: ${lib.version}</span>
                        </div>
                        <div class="advanced-item-desc">Found file: ${escapeHTML(lib.file)}</div>
                    </li>`).join('');
            }
        }

        // 6. Network & Routing
        const networkList = document.getElementById('networkList');
        if (networkList) {
            networkList.innerHTML = '';
            
            // HTTP Methods
            const methClass = advanced.httpMethods.vulnerable ? 'missing' : 'configured';
            const methStatus = advanced.httpMethods.vulnerable ? 'Vulnerable' : 'Safe';
            networkList.innerHTML += `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>HTTP Methods (OPTIONS)</span>
                        <span class="status-indicator ${methClass}">${methStatus}</span>
                    </div>
                    <div class="advanced-item-desc">
                        Allowed: ${escapeHTML(advanced.httpMethods.methods)}<br>
                        <span style="color:var(--text-secondary)">${escapeHTML(advanced.httpMethods.message)}</span>
                    </div>
                </li>`;
                
            // Directory Listing
            const dirClass = advanced.dirListing.found ? 'missing' : 'configured';
            const dirStatus = advanced.dirListing.found ? 'Exposed' : 'Safe';
            networkList.innerHTML += `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>Directory Listing</span>
                        <span class="status-indicator ${dirClass}">${dirStatus}</span>
                    </div>
                    <div class="advanced-item-desc">${escapeHTML(advanced.dirListing.message)}</div>
                </li>`;
        }

        // 7. Cache Security
        const cacheList = document.getElementById('cacheList');
        if (cacheList && advanced.cacheSecurity) {
            const cacheSecClass = advanced.cacheSecurity.isCached ? (advanced.cacheSecurity.message.includes('sensitive') ? 'missing' : 'configured') : 'configured';
            cacheList.innerHTML = `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>Cache Directives</span>
                        <span class="status-indicator ${cacheSecClass}">${advanced.cacheSecurity.posture}</span>
                    </div>
                    <div class="advanced-item-desc">
                        <strong>Cache-Control:</strong> ${escapeHTML(advanced.cacheSecurity.cacheControl)}<br>
                        <strong>Pragma:</strong> ${escapeHTML(advanced.cacheSecurity.pragma)}<br>
                        <strong>Expires:</strong> ${escapeHTML(advanced.cacheSecurity.expires)}<br><br>
                        <span style="color:var(--text-secondary)">${escapeHTML(advanced.cacheSecurity.message)}</span>
                    </div>
                </li>`;
        }

        // 8. SEO Metadata Spillage
        const seoList = document.getElementById('seoList');
        if (seoList && advanced.seo) {
            seoList.innerHTML = '';
            if (advanced.seo.length === 0) {
                seoList.innerHTML = '<li class="advanced-item"><div class="advanced-item-desc">No Open Graph or Twitter metadata found.</div></li>';
            } else {
                advanced.seo.forEach(meta => {
                    const seoClass = meta.spillage ? 'missing' : 'configured';
                    const seoStatus = meta.spillage ? 'Spillage Detected' : 'Safe';
                    seoList.innerHTML += `
                        <li class="advanced-item">
                            <div class="advanced-item-title">
                                <span>${escapeHTML(meta.property)}</span>
                                <span class="status-indicator ${seoClass}">${seoStatus}</span>
                            </div>
                            <div class="advanced-item-desc">${escapeHTML(meta.content)}</div>
                        </li>`;
                });
            }
        }

        // 9. Infrastructure Assets
        const infraList = document.getElementById('infraList');
        if (infraList && advanced.infra) {
            infraList.innerHTML = '';
            const addInfra = (name, found) => {
                infraList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>${name}</span>
                            <span class="status-indicator ${found ? 'missing' : 'configured'}">${found ? 'Found' : 'Missing'}</span>
                        </div>
                    </li>`;
            };
            addInfra('robots.txt', advanced.infra.robots);
            addInfra('sitemap.xml', advanced.infra.sitemap);
            addInfra('crossdomain/clientaccess', advanced.infra.crossdomain);

            if (advanced.brokenLinks) {
                const bClass = advanced.brokenLinks.length > 0 ? 'missing' : 'configured';
                const bStatus = advanced.brokenLinks.length > 0 ? `${advanced.brokenLinks.length} Dead Links` : 'Clean';
                infraList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>Broken Link Hijacking</span>
                            <span class="status-indicator ${bClass}">${bStatus}</span>
                        </div>
                        <div class="advanced-item-desc">${advanced.brokenLinks.length > 0 ? escapeHTML(advanced.brokenLinks.join(', ')) : 'No hijackable outbound links detected.'}</div>
                    </li>`;
            }
        }

        // 10. Tech Fingerprint
        const techList = document.getElementById('techList');
        if (techList) {
            techList.innerHTML = '';
            if (advanced.techStack && advanced.techStack.length > 0) {
                advanced.techStack.forEach(t => {
                    techList.innerHTML += `
                        <li class="advanced-item">
                            <div class="advanced-item-title">
                                <span>Detected Stack</span>
                                <span class="status-indicator configured">Confirmed</span>
                            </div>
                            <div class="advanced-item-desc">${escapeHTML(t)}</div>
                        </li>`;
                });
            } else {
                techList.innerHTML = '<li class="advanced-item"><div class="advanced-item-desc">No distinct technology signatures found.</div></li>';
            }
        }

        // 11. Subdomains & Preload
        const subList = document.getElementById('subdomainList');
        if (subList) {
            subList.innerHTML = `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>HSTS Preload Status</span>
                        <span class="status-indicator ${advanced.hstsPreloaded ? 'configured' : 'missing'}">${advanced.hstsPreloaded ? 'Preloaded' : 'Not Preloaded'}</span>
                    </div>
                </li>
            `;
            if (advanced.subdomains && advanced.subdomains.length > 0) {
                const subStr = advanced.subdomains.map(s => escapeHTML(s)).join('<br>');
                subList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>Discovered Subdomains (crt.sh)</span>
                            <span class="status-indicator configured">${advanced.subdomains.length} Found</span>
                        </div>
                        <div class="advanced-item-desc" style="max-height: 120px; overflow-y: auto;">${subStr}</div>
                    </li>`;
            }
        }

        // 12. DOM Vulnerabilities & Secrets
        const domList = document.getElementById('domList');
        if (domList && advanced.domSec) {
            domList.innerHTML = '';
            const addDom = (name, count, bad) => {
                const cls = (count > 0 && bad) ? 'missing' : 'configured';
                domList.innerHTML += `
                    <div class="cookie-item">
                        <div class="cookie-name">${name}</div>
                        <div class="cookie-flags">
                            <span class="flag ${cls}">Instances: ${count}</span>
                        </div>
                    </div>`;
            };
            addDom('Insecure/Missing Form Actions', advanced.domSec.formsInsecure, true);
            addDom('Insecure Password Inputs', advanced.domSec.pwdInsecure, true);
            addDom('Large Hidden Inputs (Leaks)', advanced.domSec.hiddenLeaks, true);
            addDom('Dangerous DOM Sinks (eval, innerHTML)', advanced.domSec.sinks, true);
            addDom('Source Maps Exposed', advanced.sourceMaps ? 1 : 0, true);

            if (advanced.domSec.secrets.length > 0) {
                advanced.domSec.secrets.forEach(sec => {
                    domList.innerHTML += `
                        <div class="cookie-item" style="border-left: 3px solid var(--danger)">
                            <div class="cookie-name" style="color:var(--danger)">CRITICAL: Hardcoded Secret</div>
                            <div class="cookie-flags">
                                <span>${escapeHTML(sec)}</span>
                            </div>
                        </div>`;
                });
            }
        }
        
        // Add Referrer Policy and Frame Ancestors to Network List if networkList exists
        const netList = document.getElementById('networkList');
        if (netList) {
             netList.innerHTML += `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>Referrer-Policy Posture</span>
                        <span class="status-indicator ${advanced.refInsecure ? 'missing' : 'configured'}">${advanced.refInsecure ? 'Vulnerable' : 'Safe'}</span>
                    </div>
                    <div class="advanced-item-desc">${escapeHTML(advanced.refPolicy)}</div>
                </li>
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>Anti-Clickjacking (CSP Frame-Ancestors)</span>
                        <span class="status-indicator ${advanced.hasFrameAncestors ? 'configured' : 'missing'}">${advanced.hasFrameAncestors ? 'Configured' : 'Missing'}</span>
                    </div>
                </li>`;

             if (advanced.openPorts) {
                 const pClass = advanced.openPorts.length > 0 ? 'missing' : 'configured';
                 const pStatus = advanced.openPorts.length > 0 ? 'Exposed' : 'Filtered';
                 netList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>Open Ports Scanner</span>
                            <span class="status-indicator ${pClass}">${pStatus}</span>
                        </div>
                        <div class="advanced-item-desc">${advanced.openPorts.length > 0 ? escapeHTML(advanced.openPorts.join(', ')) : 'All core database/admin ports filtered.'}</div>
                    </li>`;
             }
             if (advanced.waf) {
                 netList.innerHTML += `
                    <li class="advanced-item">
                        <div class="advanced-item-title">
                            <span>WAF / CDN Fingerprint</span>
                            <span class="status-indicator configured">Detected</span>
                        </div>
                        <div class="advanced-item-desc">${escapeHTML(advanced.waf)}</div>
                    </li>`;
             }
        }

        // 12. Red Team Modules
        const fuzzerList = document.getElementById('fuzzerList');
        const apiList = document.getElementById('apiList');
        const aiDefenseList = document.getElementById('aiDefenseList');

        if (fuzzerList && advanced.fuzzer) {
            fuzzerList.innerHTML = '';
            if (advanced.fuzzer.exposedFiles.length > 0) {
                advanced.fuzzer.exposedFiles.forEach(hit => {
                    fuzzerList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span style="color: #ef4444; font-weight: bold;">[CRITICAL] ${escapeHTML(hit.path)}</span><span class="status-indicator missing">HTTP ${hit.status}</span></div></li>`;
                });
            }
            if (advanced.fuzzer.hiddenDirs.length > 0) {
                advanced.fuzzer.hiddenDirs.forEach(hit => {
                    fuzzerList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span>[DIR] ${escapeHTML(hit.path)}</span><span class="status-indicator missing" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.5);">HTTP ${hit.status}</span></div></li>`;
                });
            }
            if (advanced.fuzzer.exposedFiles.length === 0 && advanced.fuzzer.hiddenDirs.length === 0) {
                fuzzerList.innerHTML = `<li class="advanced-item">No sensitive files or common directories exposed.</li>`;
            }
        }

        if (apiList && advanced.fuzzer) {
            apiList.innerHTML = '';
            if (advanced.fuzzer.apis.length > 0) {
                advanced.fuzzer.apis.forEach(hit => {
                    apiList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span style="color: #ef4444; font-weight: bold;">[API EXPOSED] ${escapeHTML(hit.path)}</span><span class="status-indicator missing">HTTP ${hit.status}</span></div></li>`;
                });
            } else {
                apiList.innerHTML = `<li class="advanced-item">No exposed GraphQL or Swagger endpoints found.</li>`;
            }
        }

        if (aiDefenseList && advanced.aiScrapers) {
            aiDefenseList.innerHTML = '';
            const statusClass = advanced.aiScrapers.blocksAi ? 'configured' : 'missing';
            const statusText = advanced.aiScrapers.blocksAi ? 'Protected' : 'Vulnerable';
            
            // 13. Active DAST Engine & PoC Gen
            const sqliList = document.getElementById('sqliList');
            const xssList = document.getElementById('xssList');
            const lfiList = document.getElementById('lfiList');
            const ssrfList = document.getElementById('ssrfList');
            const authList = document.getElementById('authList');

            window.generatePoc = async (vulnContext) => {
                const modal = document.getElementById('pocModal');
                const content = document.getElementById('pocModalContent');
                modal.classList.remove('hidden');
                content.textContent = "Loading exploit generation from AI...";
                try {
                    const res = await fetch('/api/generate-poc', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ vulnContext }) });
                    const data = await res.json();
                    content.textContent = data.poc || data.error;
                } catch(e) { content.textContent = "Error generating PoC."; }
            };

            if (advanced.dast) {
                const populateDastCard = (listElem, dataArr, vulnName) => {
                    if (!listElem) return;
                    listElem.innerHTML = '';
                    if (!dataArr || dataArr.length === 0) {
                        listElem.innerHTML = `<li class="advanced-item">No ${vulnName} vulnerabilities detected.</li>`;
                    } else {
                        dataArr.forEach(hit => {
                            const context = `${vulnName} on parameter ?${hit.param}= with payload: ${hit.payload}`;
                            listElem.innerHTML += `
                                <li class="advanced-item" style="display:flex; justify-content:space-between; align-items:center;">
                                    <div>
                                        <div class="advanced-item-title">
                                            <span style="color: #ef4444; font-weight: bold;">Exploitable Param: ?${escapeHTML(hit.param)}=</span>
                                            <span class="status-indicator missing">VULNERABLE</span>
                                        </div>
                                        <div class="advanced-item-desc">Payload: <code>${escapeHTML(hit.payload)}</code></div>
                                    </div>
                                    <button onclick="window.generatePoc('${escapeHTML(context)}')" class="btn primary" style="padding: 5px 10px; font-size: 0.8rem; background: #ef4444; border-color: #ef4444;">Generate PoC</button>
                                </li>`;
                        });
                    }
                };

                populateDastCard(sqliList, advanced.dast.sqli, 'SQLi');
                populateDastCard(xssList, advanced.dast.xss, 'Reflected XSS');
                populateDastCard(lfiList, advanced.dast.lfi, 'Directory Traversal');
                populateDastCard(ssrfList, advanced.dast.ssrf, 'SSRF');
            } else {
                const noParamsMsg = `<li class="advanced-item">No URL parameters found to fuzz. Test URLs like ?id=1 to activate DAST engine.</li>`;
                if (sqliList) sqliList.innerHTML = noParamsMsg;
                if (xssList) xssList.innerHTML = noParamsMsg;
                if (lfiList) lfiList.innerHTML = noParamsMsg;
                if (ssrfList) ssrfList.innerHTML = noParamsMsg;
            }

            if (authList && advanced.auth) {
                authList.innerHTML = '';
                const addAuthItem = (title, count, severity, safeMsg, vulnMsg) => {
                    const isVuln = count > 0;
                    const badgeClass = isVuln ? 'missing' : 'configured';
                    authList.innerHTML += `
                        <li class="advanced-item">
                            <div class="advanced-item-title">
                                <span>${title}</span>
                                <span class="status-indicator ${badgeClass}">${isVuln ? severity : 'Secure'}</span>
                            </div>
                            <div class="advanced-item-desc">${isVuln ? `${count} ${vulnMsg}` : safeMsg}</div>
                        </li>`;
                };
                addAuthItem('Missing CSRF Tokens', advanced.auth.missingCsrf, 'HIGH RISK', 'All POST forms appear protected or no forms detected.', 'POST form(s) missing anti-CSRF tokens.');
                addAuthItem('Plaintext Password Transmission', advanced.auth.plaintextPasswords, 'CRITICAL', 'No passwords transmitted via GET requests.', 'password input(s) transmitting data insecurely via URL (GET).');
                addAuthItem('Insecure Form Actions', advanced.auth.insecureAction, 'HIGH RISK', 'All form actions use HTTPS.', 'form(s) submitting data to unencrypted HTTP endpoints.');
            }

            // 14. Compliance Mapping
            const complianceList = document.getElementById('complianceList');
            if (complianceList) {
                complianceList.innerHTML = '';
                const missingHeaders = data.headers.filter(h => h.status === 'Missing');
                if (missingHeaders.length > 0) {
                    complianceList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span>OWASP Top 10: A05:2021-Security Misconfiguration</span><span class="status-indicator missing">FAIL</span></div><div class="advanced-item-desc">Missing ${missingHeaders.length} security headers violates standard hardening guidelines.</div></li>`;
                } else {
                    complianceList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span>OWASP Top 10: A05:2021-Security Misconfiguration</span><span class="status-indicator configured">PASS</span></div><div class="advanced-item-desc">Basic HTTP Header configuration complies with standard guidelines.</div></li>`;
                }

                if (data.tlsDetails && data.tlsDetails.success === false) {
                     complianceList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span>PCI-DSS Requirement 4.1</span><span class="status-indicator missing">FAIL</span></div><div class="advanced-item-desc">Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks.</div></li>`;
                } else {
                     complianceList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span>PCI-DSS Requirement 4.1</span><span class="status-indicator configured">PASS</span></div><div class="advanced-item-desc">Valid TLS connection established protecting data in transit.</div></li>`;
                }

                if (advanced.dast && (advanced.dast.sqli.length > 0 || advanced.dast.xss.length > 0)) {
                     complianceList.innerHTML += `<li class="advanced-item"><div class="advanced-item-title"><span>OWASP Top 10: A03:2021-Injection</span><span class="status-indicator missing">CRITICAL FAIL</span></div><div class="advanced-item-desc">Active injection vulnerabilities detected (SQLi/XSS). Code is highly vulnerable to data exfiltration.</div></li>`;
                }
            }

            aiDefenseList.innerHTML += `
                <li class="advanced-item">
                    <div class="advanced-item-title">
                        <span>LLM Scraper Protections</span>
                        <span class="status-indicator ${statusClass}">${statusText}</span>
                    </div>
                    <div class="advanced-item-desc">${advanced.aiScrapers.blocksAi ? 'Site actively blocks known AI scrapers (e.g., GPTBot) in robots.txt.' : 'Site does not explicitly block AI scrapers. Content may be harvested for model training.'}</div>
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
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
    window.escapeHTML = escapeHTML;

    // Chat & PoC Modal Event Listeners
    if (document.getElementById('openChatBtn')) {
        document.getElementById('openChatBtn').addEventListener('click', () => { document.getElementById('chatWidget').classList.remove('hidden'); document.getElementById('openChatBtn').classList.add('hidden'); });
        document.getElementById('closeChatBtn').addEventListener('click', () => { document.getElementById('chatWidget').classList.add('hidden'); document.getElementById('openChatBtn').classList.remove('hidden'); });
    }
    
    if (document.getElementById('closePocBtn')) {
        document.getElementById('closePocBtn').addEventListener('click', () => { document.getElementById('pocModal').classList.add('hidden'); });
    }

    const sendChatBtn = document.getElementById('sendChatBtn');
    const chatInput = document.getElementById('chatInput');
    const chatMessages = document.getElementById('chatMessages');


        const appendMsg = (txt, isUser) => {
            const div = document.createElement('div');
            div.style.padding = '10px';
            div.style.borderRadius = '8px';
            div.style.fontSize = '14px';
            if (isUser) {
                div.style.background = 'rgba(59, 130, 246, 0.2)';
                div.style.alignSelf = 'flex-end';
                div.style.color = '#fff';
            } else {
                div.style.background = 'rgba(255, 255, 255, 0.05)';
                div.style.alignSelf = 'flex-start';
                div.style.color = 'var(--text-secondary)';
            }
            div.textContent = txt;
            chatMessages.appendChild(div);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        };

        const sendMsg = async () => {
            const msg = chatInput.value.trim();
            if (!msg) return;
            appendMsg(msg, true);
            chatInput.value = '';

            try {
                const res = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: msg, context: window.lastAuditContext })
                });
                const data = await res.json();
                appendMsg(data.reply || 'No response.', false);
            } catch (e) {
                appendMsg('Error reaching AI server.', false);
            }
        };

        sendChatBtn.addEventListener('click', sendMsg);
        chatInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMsg(); });
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

// --- NEW ENTERPRISE FEATURES LOGIC ---

// Bulk Analysis
const bulkSubmitBtn = document.getElementById('bulkSubmitBtn');
if (bulkSubmitBtn) {
    bulkSubmitBtn.addEventListener('click', async () => {
        const rawUrls = document.getElementById('bulkUrlsInput').value;
        const urls = rawUrls.split('\n').map(u => u.trim()).filter(u => u);
        if(urls.length === 0) return alert('Enter at least one URL');
        if(urls.length > 20) return alert('Max 20 URLs allowed for bulk scan.');
        
        bulkSubmitBtn.disabled = true;
        bulkSubmitBtn.querySelector('.btn-text').textContent = 'Scanning Batch...';
        
        try {
            const res = await fetch('/api/bulk-analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls })
            });
            const data = await res.json();
            const bulkResults = document.getElementById('bulkResults');
            bulkResults.innerHTML = '<h3 style="margin-bottom:15px; border-bottom:1px solid var(--border); padding-bottom:5px;">Bulk Scan Results</h3>';
            if (data.results) {
                data.results.forEach(r => {
                    const color = r.status === 'Success' ? '#10b981' : '#ef4444';
                    bulkResults.innerHTML += `<div style="padding: 10px; border: 1px solid var(--border); margin-bottom: 5px; border-radius: 4px;">
                        <strong>${window.escapeHTML(r.url)}</strong> - <span style="color: ${color}">${r.status}</span>
                        ${r.grade ? `(Grade: ${r.grade}, Score: ${r.score})` : ''}
                    </div>`;
                });
            }
            bulkResults.classList.remove('hidden');
        } catch (e) {
            alert('Bulk scan failed.');
        } finally {
            bulkSubmitBtn.disabled = false;
            bulkSubmitBtn.querySelector('.btn-text').textContent = 'Run Bulk Scan';
        }
    });
}

// Schedule Watchlist
const scheduleAddBtn = document.getElementById('scheduleAddBtn');
if (scheduleAddBtn) {
    scheduleAddBtn.addEventListener('click', async () => {
        const url = document.getElementById('scheduleUrlInput').value.trim();
        const freq = document.getElementById('scheduleFreq').value;
        if(!url) return;
        scheduleAddBtn.disabled = true;
        try {
            await fetch('/api/schedule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, freq })
            });
            document.getElementById('scheduleUrlInput').value = '';
            loadWatchlist();
        } catch(e) {
            alert('Failed to add to watchlist.');
        }
        scheduleAddBtn.disabled = false;
    });
}

async function loadWatchlist() {
    try {
        const res = await fetch('/api/watchlist');
        const data = await res.json();
        const list = document.getElementById('watchlistItems');
        list.innerHTML = '';
        if (data.watchlist && data.watchlist.length > 0) {
            data.watchlist.forEach(item => {
                list.innerHTML += `<li style="padding: 10px; border: 1px solid var(--border); margin-bottom: 5px; border-radius: 4px; display: flex; justify-content: space-between;">
                    <span><strong>${window.escapeHTML(item.url)}</strong> (${item.freq})</span>
                    <span style="color: ${item.status === 'Healthy' ? '#10b981' : '#eab308'}">${item.status}</span>
                </li>`;
            });
        } else {
            list.innerHTML = '<li style="color: var(--text-secondary); text-align: center;">No targets in watchlist.</li>';
        }
    } catch(e) {}
}

// Interactive 3D D3.js Map Rendering
window.renderD3Map = function(advancedData, rootDomain) {
    const mapContainer = document.getElementById('d3MapContainer');
    mapContainer.innerHTML = ''; // clear previous
    if (!advancedData) return;
    
    const nodes = [];
    const links = [];
    
    // Root Node
    nodes.push({ id: rootDomain, group: 1, radius: 25 });
    
    // Subdomains
    if (advancedData.subdomains) {
        advancedData.subdomains.forEach(sub => {
            nodes.push({ id: sub, group: 2, radius: 15 });
            links.push({ source: rootDomain, target: sub });
        });
    }
    
    // Open Ports
    if (advancedData.openPorts) {
        advancedData.openPorts.forEach(port => {
            const portId = 'Port ' + port;
            nodes.push({ id: portId, group: 3, radius: 10 });
            links.push({ source: rootDomain, target: portId });
        });
    }
    
    // Tech Stack
    if (advancedData.techStack) {
        advancedData.techStack.forEach(tech => {
            nodes.push({ id: tech, group: 4, radius: 10 });
            links.push({ source: rootDomain, target: tech });
        });
    }

    const width = mapContainer.clientWidth || 800;
    const height = mapContainer.clientHeight || 500;

    const svg = d3.select("#d3MapContainer").append("svg")
        .attr("width", "100%")
        .attr("height", "100%")
        .attr("viewBox", [0, 0, width, height]);

    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2));

    const link = svg.append("g")
        .attr("stroke", "#334155")
        .attr("stroke-opacity", 0.6)
        .selectAll("line")
        .data(links)
        .join("line")
        .attr("stroke-width", 2);

    const color = d3.scaleOrdinal().domain([1, 2, 3, 4]).range(["#3b82f6", "#10b981", "#ef4444", "#eab308"]);

    const node = svg.append("g")
        .attr("stroke", "#fff")
        .attr("stroke-width", 1.5)
        .selectAll("circle")
        .data(nodes)
        .join("circle")
        .attr("r", d => d.radius)
        .attr("fill", d => color(d.group))
        .call(drag(simulation));

    const labels = svg.append("g")
        .selectAll("text")
        .data(nodes)
        .join("text")
        .text(d => d.id)
        .attr("font-size", "10px")
        .attr("fill", "#cbd5e1")
        .attr("dx", 12)
        .attr("dy", 4);

    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node
            .attr("cx", d => d.x)
            .attr("cy", d => d.y);
            
        labels
            .attr("x", d => d.x)
            .attr("y", d => d.y);
    });

    function drag(simulation) {
        function dragstarted(event) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }
        function dragged(event) {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }
        function dragended(event) {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }
        return d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended);
    }
    
    document.getElementById('attackSurfaceSection').classList.remove('hidden');
};

// ════════════════════════════════════════════════════════════════════════════
// ENTERPRISE FEATURE SUITE — Auth, Dashboard, Settings, OWASP, GDPR, CMS
// ════════════════════════════════════════════════════════════════════════════

// ─── Auth State ─────────────────────────────────────────────────────────────
let currentUser = null;
let trendChartInstance = null;

function getToken() { return localStorage.getItem('wg_token'); }
function setToken(t) { localStorage.setItem('wg_token', t); }
function clearToken() { localStorage.removeItem('wg_token'); localStorage.removeItem('wg_user'); }

function updateNavAuth(user) {
    currentUser = user;
    if (user) {
        document.getElementById('navAuthArea').style.display = 'none';
        document.getElementById('navUserMenu').style.display = 'block';
        document.getElementById('navHistoryBtn').style.display = 'block';
        document.getElementById('navSettingsBtn').style.display = 'block';
        document.getElementById('userNameDisplay').textContent = user.name || user.email;
        document.getElementById('userEmailDisplay').textContent = user.email;
    } else {
        document.getElementById('navAuthArea').style.display = 'block';
        document.getElementById('navUserMenu').style.display = 'none';
        document.getElementById('navHistoryBtn').style.display = 'none';
        document.getElementById('navSettingsBtn').style.display = 'none';
    }
}

async function checkAuthOnLoad() {
    const token = getToken();
    if (!token) return;
    try {
        const res = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } });
        if (res.ok) {
            const d = await res.json();
            updateNavAuth(d.user);
            applyWhiteLabel();
        } else { clearToken(); }
    } catch (e) { /* server offline, silent fail */ }
}

// ─── White-Label ─────────────────────────────────────────────────────────────
function applyWhiteLabel() {
    const name = localStorage.getItem('wl_name');
    const logo = localStorage.getItem('wl_logo');
    if (name) {
        const titleEl = document.getElementById('appTitle');
        if (titleEl) titleEl.innerHTML = name;
        document.title = name + ' // Security Auditor';
    }
    if (logo) {
        const iconEl = document.getElementById('appIcon');
        if (iconEl) { iconEl.innerHTML = `<img src="${logo}" style="height:32px;vertical-align:middle;" onerror="this.style.display='none';">`; }
    }
}

// ─── Auth Modal ───────────────────────────────────────────────────────────────
function showAuthModal(tab = 'login') {
    document.getElementById('authModal').classList.remove('hidden');
    switchAuthTab(tab);
}
function hideAuthModal() { 
    document.getElementById('authModal').classList.add('hidden'); 
    clearAuthFields();
}

function clearAuthFields() {
    ['loginEmail', 'loginPassword', 'loginTotpCode', 'registerName', 'registerEmail', 'registerPassword', 'forgotEmail', 'forgotRecoveryKey', 'forgotNewPassword'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    ['authLoginError', 'authRegisterError', 'authForgotError'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('hidden');
    });
}

function switchAuthTab(tab) {
    const panes = ['login', 'register', 'forgot', 'recovery'];
    panes.forEach(p => {
        const el = document.getElementById('auth' + p.charAt(0).toUpperCase() + p.slice(1) + 'Pane');
        if (el) el.classList.toggle('hidden', p !== tab);
    });
    // Tab highlight
    ['Login', 'Register', 'Forgot'].forEach(t => {
        const btn = document.getElementById('authTab' + t);
        if (!btn) return;
        const active = tab === t.toLowerCase();
        btn.style.color = active ? 'var(--primary)' : 'var(--text-secondary)';
        btn.style.borderBottom = active ? '2px solid var(--primary)' : '2px solid transparent';
        btn.style.fontWeight = active ? '700' : '400';
    });
}

document.getElementById('navLoginBtn').addEventListener('click', () => showAuthModal('login'));
document.getElementById('authTabLogin').addEventListener('click', () => switchAuthTab('login'));
document.getElementById('authTabRegister').addEventListener('click', () => switchAuthTab('register'));
document.getElementById('authTabForgot').addEventListener('click', () => switchAuthTab('forgot'));
document.getElementById('authModalCloseBtn').addEventListener('click', hideAuthModal);
document.getElementById('switchToForgotBtn').addEventListener('click', () => switchAuthTab('forgot'));
document.getElementById('afterResetLoginBtn').addEventListener('click', () => switchAuthTab('login'));

// Copy recovery key
document.getElementById('copyRecoveryKeyBtn').addEventListener('click', () => {
    const key = document.getElementById('recoveryKeyDisplay').textContent;
    navigator.clipboard.writeText(key).then(() => { document.getElementById('copyRecoveryKeyBtn').textContent = '✓ Copied!'; setTimeout(() => { document.getElementById('copyRecoveryKeyBtn').textContent = '📋 Copy Recovery Key'; }, 2000); });
});
document.getElementById('doneRecoveryBtn').addEventListener('click', () => { hideAuthModal(); });

document.getElementById('loginSubmitBtn').addEventListener('click', async () => {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const totp_code = document.getElementById('loginTotpCode') ? document.getElementById('loginTotpCode').value.trim() : '';
    const errEl = document.getElementById('authLoginError');
    errEl.classList.add('hidden');
    try {
        const res = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, totp_code: totp_code || undefined }) });
        const d = await res.json();
        if (d.requires2FA) { document.getElementById('login2FAField').classList.remove('hidden'); errEl.textContent = 'Enter your 2FA code below.'; errEl.style.color = '#f59e0b'; errEl.classList.remove('hidden'); return; }
        if (!d.success) { errEl.textContent = d.error || 'Login failed.'; errEl.classList.remove('hidden'); return; }
        setToken(d.token);
        localStorage.setItem('wg_user', JSON.stringify(d.user));
        updateNavAuth(d.user);
        hideAuthModal();
    } catch (e) { errEl.textContent = 'Server error. Is the server running?'; errEl.classList.remove('hidden'); }
});

document.getElementById('registerSubmitBtn').addEventListener('click', async () => {
    const name = document.getElementById('registerName').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;
    const errEl = document.getElementById('authRegisterError');
    errEl.classList.add('hidden');
    try {
        const res = await fetch('/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, email, password }) });
        const d = await res.json();
        if (!d.success) { errEl.textContent = d.error || 'Registration failed.'; errEl.classList.remove('hidden'); return; }
        setToken(d.token);
        localStorage.setItem('wg_user', JSON.stringify(d.user));
        updateNavAuth(d.user);
        // Show recovery key pane — MUST be acknowledged before dismissing
        if (d.recoveryKey) {
            document.getElementById('recoveryKeyDisplay').textContent = d.recoveryKey;
            switchAuthTab('recovery');
        } else {
            hideAuthModal();
        }
    } catch (e) { errEl.textContent = 'Server error.'; errEl.classList.remove('hidden'); }
});

// ─── Forgot Password ─────────────────────────────────────────────────────────
document.getElementById('forgotSubmitBtn').addEventListener('click', async () => {
    const email = document.getElementById('forgotEmail').value.trim();
    const recoveryKey = document.getElementById('forgotRecoveryKey').value.trim();
    const newPassword = document.getElementById('forgotNewPassword').value;
    const errEl = document.getElementById('authForgotError');
    errEl.classList.add('hidden');
    document.getElementById('forgotSuccessPane').classList.add('hidden');
    if (!email || !recoveryKey || !newPassword) { errEl.textContent = 'All fields are required.'; errEl.classList.remove('hidden'); return; }
    try {
        const res = await fetch('/api/auth/reset-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, recoveryKey, newPassword }) });
        const d = await res.json();
        if (!d.success) { errEl.textContent = d.error || 'Reset failed.'; errEl.classList.remove('hidden'); return; }
        // Show success + new recovery key
        document.getElementById('newRecoveryKeyDisplay').textContent = d.newRecoveryKey || '';
        document.getElementById('forgotSuccessPane').classList.remove('hidden');
        document.getElementById('forgotNewPassword').value = '';
        document.getElementById('forgotRecoveryKey').value = '';
    } catch (e) { errEl.textContent = 'Server error.'; errEl.classList.remove('hidden'); }
});

// ─── User Menu Dropdown ───────────────────────────────────────────────────────
document.getElementById('userMenuBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    const d = document.getElementById('userDropdown');
    d.style.display = d.style.display === 'none' ? 'block' : 'none';
});
document.addEventListener('click', () => { const d = document.getElementById('userDropdown'); if (d) d.style.display = 'none'; });

document.getElementById('dropLogoutBtn').addEventListener('click', () => { 
    clearToken(); 
    updateNavAuth(null); 
    clearAuthFields();
    document.getElementById('userDropdown').style.display = 'none'; 
});

// ─── API Key Modal ────────────────────────────────────────────────────────────
document.getElementById('dropApiKeyBtn').addEventListener('click', async () => {
    document.getElementById('userDropdown').style.display = 'none';
    document.getElementById('apiKeyModal').classList.remove('hidden');
    // Load existing key info
    try {
        const res = await fetch('/api/my-api-key', { headers: { Authorization: `Bearer ${getToken()}` } });
        const d = await res.json();
        if (d.keyInfo) {
            document.getElementById('apiKeyDisplay').textContent = `${d.keyInfo.key_prefix}... (created ${new Date(d.keyInfo.created_at).toLocaleDateString()})`;
        }
    } catch (e) {}
});
document.getElementById('closeApiKeyModal').addEventListener('click', () => document.getElementById('apiKeyModal').classList.add('hidden'));
document.getElementById('generateKeyBtn').addEventListener('click', async () => {
    const res = await fetch('/api/generate-api-key', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` } });
    const d = await res.json();
    if (d.apiKey) document.getElementById('apiKeyDisplay').textContent = d.apiKey;
});
document.getElementById('copyKeyBtn').addEventListener('click', () => {
    const text = document.getElementById('apiKeyDisplay').textContent;
    navigator.clipboard.writeText(text).then(() => { document.getElementById('copyKeyBtn').textContent = '✓ Copied!'; setTimeout(() => { document.getElementById('copyKeyBtn').textContent = 'Copy Key'; }, 2000); });
});

// ─── 2FA Modal ────────────────────────────────────────────────────────────────
document.getElementById('drop2FABtn').addEventListener('click', async () => {
    document.getElementById('userDropdown').style.display = 'none';
    document.getElementById('twoFAModal').classList.remove('hidden');
    const res = await fetch('/api/auth/2fa/setup', { method: 'POST', headers: { Authorization: `Bearer ${getToken()}` } });
    const d = await res.json();
    if (d.qrCode) document.getElementById('twoFAQrCode').src = d.qrCode;
});
document.getElementById('close2FAModal').addEventListener('click', () => document.getElementById('twoFAModal').classList.add('hidden'));
document.getElementById('twoFAVerifyBtn').addEventListener('click', async () => {
    const token = document.getElementById('twoFAVerifyCode').value.trim();
    const errEl = document.getElementById('twoFAError');
    const res = await fetch('/api/auth/2fa/verify', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` }, body: JSON.stringify({ token }) });
    const d = await res.json();
    if (d.success) { document.getElementById('twoFAModal').classList.add('hidden'); alert('✅ 2FA enabled! Your account is now protected.'); }
    else { errEl.textContent = d.error || 'Invalid code.'; errEl.classList.remove('hidden'); }
});

// ─── History Dashboard ────────────────────────────────────────────────────────
document.getElementById('navHistoryBtn').addEventListener('click', openDashboard);
document.getElementById('closeDashboardBtn').addEventListener('click', () => document.getElementById('historyDashboard').classList.add('hidden'));

async function openDashboard() {
    document.getElementById('historyDashboard').classList.remove('hidden');
    await Promise.all([loadHeatmap(), loadHistory(), loadDomainList()]);
}

async function loadHeatmap() {
    const grid = document.getElementById('heatmapGrid');
    const empty = document.getElementById('heatmapEmpty');
    grid.innerHTML = '';
    try {
        const res = await fetch('/api/history/heatmap', { headers: { Authorization: `Bearer ${getToken()}` } });
        const d = await res.json();
        if (!d.data || d.data.length === 0) { empty.style.display = 'block'; return; }
        empty.style.display = 'none';
        d.data.forEach(item => {
            const card = document.createElement('div');
            card.className = `heatmap-card heatmap-grade-${item.grade}`;
            card.title = `Last scan: ${new Date(item.created_at).toLocaleString()}`;
            card.innerHTML = `<div style="font-size:1.6rem;margin-bottom:4px;">${item.grade}</div><div>${item.score}/100</div><div style="font-size:0.75rem;margin-top:4px;opacity:0.8;">${item.domain}</div>`;
            grid.appendChild(card);
        });
    } catch (e) { empty.style.display = 'block'; }
}

async function loadHistory() {
    const tbody = document.getElementById('historyTableBody');
    try {
        const res = await fetch('/api/history', { headers: { Authorization: `Bearer ${getToken()}` } });
        const d = await res.json();
        if (!d.history || d.history.length === 0) { tbody.innerHTML = '<tr><td colspan="4" style="padding:20px;text-align:center;color:var(--text-secondary);">No scans yet. Run a scan while logged in!</td></tr>'; return; }
        const gradeColors = { A:'#10b981', B:'#3b82f6', C:'#f59e0b', D:'#f97316', F:'#ef4444' };
        tbody.innerHTML = d.history.map(s => `<tr>
            <td style="font-weight:600;">${s.domain}</td>
            <td><div style="background:rgba(59,130,246,0.1);border-radius:4px;height:6px;width:100%;max-width:80px;display:inline-block;vertical-align:middle;"><div style="background:${gradeColors[s.grade]||'#64748b'};height:100%;width:${s.score}%;border-radius:4px;"></div></div> <span style="margin-left:6px;">${s.score}</span></td>
            <td><span style="color:${gradeColors[s.grade]||'#64748b'};font-weight:700;">${s.grade}</span></td>
            <td style="color:var(--text-secondary);font-size:0.85rem;">${new Date(s.created_at).toLocaleString()}</td>
        </tr>`).join('');
    } catch (e) { tbody.innerHTML = '<tr><td colspan="4" style="padding:20px;text-align:center;color:#ef4444;">Failed to load history.</td></tr>'; }
}

async function loadDomainList() {
    const select = document.getElementById('trendDomainSelect');
    try {
        const res = await fetch('/api/history/domains', { headers: { Authorization: `Bearer ${getToken()}` } });
        const d = await res.json();
        select.innerHTML = '<option value="">Select a domain...</option>';
        (d.domains || []).forEach(dom => { const o = document.createElement('option'); o.value = dom; o.textContent = dom; select.appendChild(o); });
    } catch (e) {}
}

document.getElementById('trendDomainSelect').addEventListener('change', async (e) => {
    const domain = e.target.value;
    if (!domain) return;
    try {
        const res = await fetch(`/api/history/${encodeURIComponent(domain)}`, { headers: { Authorization: `Bearer ${getToken()}` } });
        const d = await res.json();
        renderTrendChart(d.scans || []);
    } catch (e) {}
});

function renderTrendChart(scans) {
    const canvas = document.getElementById('trendChart');
    if (trendChartInstance) { trendChartInstance.destroy(); trendChartInstance = null; }
    const labels = scans.map(s => new Date(s.created_at).toLocaleDateString()).reverse();
    const scores = scans.map(s => s.score).reverse();
    trendChartInstance = new Chart(canvas, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Security Score',
                data: scores,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59,130,246,0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3,
                pointBackgroundColor: '#3b82f6',
                pointRadius: 4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#94a3b8' } } },
            scales: {
                x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
                y: { min: 0, max: 100, ticks: { color: '#64748b' }, grid: { color: '#1e293b' } }
            }
        }
    });
}

// ─── Settings Panel ───────────────────────────────────────────────────────────
document.getElementById('navSettingsBtn').addEventListener('click', openSettings);
document.getElementById('closeSettingsBtn').addEventListener('click', () => document.getElementById('settingsPanel').classList.add('hidden'));

async function openSettings() {
    document.getElementById('settingsPanel').classList.remove('hidden');
    // Pre-populate white-label from localStorage
    document.getElementById('settingsWlName').value = localStorage.getItem('wl_name') || '';
    document.getElementById('settingsWlLogo').value = localStorage.getItem('wl_logo') || '';
}

document.getElementById('saveSettingsBtn').addEventListener('click', async () => {
    const payload = {
        slack_webhook: document.getElementById('settingsSlackWebhook').value.trim() || null,
        jira_url: document.getElementById('settingsJiraUrl').value.trim() || null,
        jira_email: document.getElementById('settingsJiraEmail').value.trim() || null,
        jira_token: document.getElementById('settingsJiraToken').value.trim() || null,
        jira_project: document.getElementById('settingsJiraProject').value.trim() || null,
        webhook_url: document.getElementById('settingsWebhookUrl').value.trim() || null,
        whitelabel_name: document.getElementById('settingsWlName').value.trim() || null,
        whitelabel_logo: document.getElementById('settingsWlLogo').value.trim() || null,
    };
    // Save white-label locally for instant apply
    if (payload.whitelabel_name) localStorage.setItem('wl_name', payload.whitelabel_name); else localStorage.removeItem('wl_name');
    if (payload.whitelabel_logo) localStorage.setItem('wl_logo', payload.whitelabel_logo); else localStorage.removeItem('wl_logo');
    applyWhiteLabel();

    const statusEl = document.getElementById('settingsSaveStatus');
    try {
        const res = await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` }, body: JSON.stringify(payload) });
        const d = await res.json();
        statusEl.textContent = d.success ? '✅ Settings saved successfully!' : ('❌ ' + (d.error || 'Save failed.'));
        statusEl.style.color = d.success ? '#10b981' : '#ef4444';
    } catch (e) { statusEl.textContent = '❌ Could not save to server (are you logged in?). White-label applied locally.'; statusEl.style.color = '#f59e0b'; }
    statusEl.style.display = 'block';
    setTimeout(() => { statusEl.style.display = 'none'; }, 4000);
});

// ─── Regenerate Recovery Key ────────────────────────────────────────────────
document.getElementById('regenKeyBtn').addEventListener('click', async () => {
    const password = document.getElementById('regenKeyPassword').value;
    const errEl = document.getElementById('regenKeyError');
    errEl.classList.add('hidden');
    document.getElementById('regenKeySuccessPane').classList.add('hidden');
    if (!password) { errEl.textContent = 'Please confirm your password.'; errEl.classList.remove('hidden'); return; }
    
    if (!confirm('Are you sure you want to regenerate your recovery key? Your old key will stop working immediately.')) return;
    
    try {
        const res = await fetch('/api/auth/regenerate-recovery-key', { 
            method: 'POST', 
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` }, 
            body: JSON.stringify({ password }) 
        });
        const d = await res.json();
        if (!d.success) { errEl.textContent = d.error || 'Failed to regenerate key.'; errEl.classList.remove('hidden'); return; }
        
        document.getElementById('regenNewKeyDisplay').textContent = d.newRecoveryKey;
        document.getElementById('regenKeySuccessPane').classList.remove('hidden');
        document.getElementById('regenKeyPassword').value = '';
    } catch (e) {
        errEl.textContent = 'Server error.'; errEl.classList.remove('hidden');
    }
});

document.getElementById('copyRegenKeyBtn').addEventListener('click', () => {
    const key = document.getElementById('regenNewKeyDisplay').textContent;
    navigator.clipboard.writeText(key).then(() => { 
        document.getElementById('copyRegenKeyBtn').textContent = '✓ Copied!'; 
        setTimeout(() => { document.getElementById('copyRegenKeyBtn').textContent = '📋 Copy Key'; }, 2000); 
    });
});

// ─── Render New Scan Modules in Results ───────────────────────────────────────
// Hook into the existing renderResults flow by extending window.renderAdvancedResults
const _originalRenderAdvanced = window.renderAdvancedResults;
window.renderAdvancedResults = function(advanced, domain) {
    if (_originalRenderAdvanced) _originalRenderAdvanced(advanced, domain);
    renderOwaspMap(advanced.owaspMap);
    renderGdprResults(advanced.gdpr);
    renderCmsInfo(advanced.cmsInfo);
    renderRateLimit(advanced.rateLimit);
};

function renderOwaspMap(owaspMap) {
    if (!owaspMap) return;
    // Find or create OWASP section
    let section = document.getElementById('owaspSection');
    if (!section) {
        section = document.createElement('div');
        section.id = 'owaspSection';
        section.className = 'card';
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) resultsSection.appendChild(section);
    }
    const passed = owaspMap.filter(c => c.pass).length;
    section.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem;">
            <h3 style="font-size:1.1rem;">⚠️ OWASP Top 10 Report Card</h3>
            <span style="font-size:0.85rem;color:var(--text-secondary);">${passed}/10 categories passing</span>
        </div>
        <div class="owasp-grid">
            ${owaspMap.map(c => `
                <div class="owasp-item">
                    <span class="owasp-id">${c.id}</span>
                    <span class="owasp-name">${c.name}</span>
                    <span class="owasp-evidence">${c.evidence}</span>
                    <span class="owasp-badge ${c.pass ? 'owasp-pass' : 'owasp-fail'}">${c.pass ? '✓ PASS' : '✗ FAIL'}</span>
                </div>
            `).join('')}
        </div>`;
}

function renderGdprResults(gdpr) {
    if (!gdpr) return;
    let section = document.getElementById('gdprSection');
    if (!section) {
        section = document.createElement('div');
        section.id = 'gdprSection';
        section.className = 'card';
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) resultsSection.appendChild(section);
    }
    const riskColor = { 'Low Risk': '#10b981', 'Medium Risk': '#f59e0b', 'High Risk': '#ef4444' }[gdpr.gdprScore] || '#94a3b8';
    section.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;flex-wrap:wrap;gap:0.5rem;">
            <h3 style="font-size:1.1rem;">🍪 GDPR / Privacy Scan</h3>
            <span style="color:${riskColor};font-weight:700;">${gdpr.gdprScore}</span>
        </div>
        ${gdpr.trackers.length > 0
            ? `<div style="margin-bottom:1rem;">${gdpr.trackers.map(t => `<span class="gdpr-tracker">📡 ${t}</span>`).join('')}</div>`
            : '<p style="color:#10b981;margin-bottom:0.5rem;">✅ No known tracking scripts detected.</p>'
        }
        ${gdpr.issues.length > 0
            ? `<div>${gdpr.issues.map(i => `<div style="color:#f97316;font-size:0.88rem;padding:8px;background:rgba(249,115,22,0.08);border-radius:6px;margin-top:6px;">⚠️ ${i}</div>`).join('')}</div>`
            : ''
        }`;
}

function renderCmsInfo(cmsInfo) {
    if (!cmsInfo) return;
    let section = document.getElementById('cmsSection');
    if (!section) {
        section = document.createElement('div');
        section.id = 'cmsSection';
        section.className = 'card';
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) resultsSection.appendChild(section);
    }
    const riskColors = { 'HIGH': '#ef4444', 'MEDIUM': '#f59e0b', 'LOW': '#10b981' };
    const riskLevel = cmsInfo.risk ? cmsInfo.risk.split(' ')[0] : 'LOW';
    const riskColor = riskColors[riskLevel] || '#94a3b8';
    section.innerHTML = `
        <h3 style="font-size:1.1rem;margin-bottom:1rem;">🔍 CMS Fingerprint</h3>
        <div class="cms-card-inner">
            <div style="font-size:2rem;">🏗️</div>
            <div>
                <div style="font-weight:700;font-size:1rem;margin-bottom:4px;">${cmsInfo.cms}</div>
                ${cmsInfo.version && cmsInfo.version !== 'N/A' ? `<div style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:6px;">Version: ${cmsInfo.version}</div>` : ''}
                <div style="font-size:0.85rem;color:${riskColor};">⚠️ ${cmsInfo.risk}</div>
            </div>
        </div>`;
}

function renderRateLimit(rateLimit) {
    if (!rateLimit) return;
    let section = document.getElementById('rateLimitSection');
    if (!section) {
        section = document.createElement('div');
        section.id = 'rateLimitSection';
        section.className = 'card';
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) resultsSection.appendChild(section);
    }
    const ok = rateLimit.protected;
    section.innerHTML = `
        <h3 style="font-size:1.1rem;margin-bottom:0.75rem;">🚦 Rate Limiting / DDoS Test</h3>
        <div style="display:flex;align-items:center;gap:12px;padding:12px;background:rgba(0,0,0,0.1);border-radius:8px;">
            <span style="font-size:1.8rem;">${ok ? '🛡️' : '⚠️'}</span>
            <div>
                <div style="font-weight:600;color:${ok ? '#10b981' : '#ef4444'};">${ok ? 'Protected' : 'Vulnerable'}</div>
                <div style="font-size:0.85rem;color:var(--text-secondary);margin-top:3px;">${rateLimit.message}</div>
            </div>
        </div>`;
}

// ─── Check auth on page load ───────────────────────────────────────────────
checkAuthOnLoad();
applyWhiteLabel();

