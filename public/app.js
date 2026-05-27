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
            if (resultsSection.classList.contains('hidden')) return;
            const originalText = exportPdfBtn.textContent;
            exportPdfBtn.textContent = 'Generating PDF...';
            exportPdfBtn.disabled = true;

            try {
                const canvas = await window.html2canvas(resultsSection, {
                    scale: 2,
                    backgroundColor: '#0B0F19'
                });
                const imgData = canvas.toDataURL('image/png');
                const pdf = new window.jspdf.jsPDF('p', 'mm', 'a4');
                const pdfWidth = pdf.internal.pageSize.getWidth();
                const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
                
                pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
                pdf.save(`WebGuard_Audit_${resultDomain.textContent}.pdf`);
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
                const sslStatus = `Valid • Exp: ${data.tlsDetails.daysRemaining || 0}d • ${data.tlsDetails.supportsHttp2 ? 'HTTP/2 Supported' : 'HTTP/1.1 Only'}`;
                sslStatusBadge.textContent = `Active & Secure (${sslStatus})`;
                sslStatusBadge.className = 'ssl-badge secure';
            }
            
            document.getElementById('sslSans').textContent = (data.tlsDetails.sans && data.tlsDetails.sans.length > 0) ? data.tlsDetails.sans.join(', ') : 'None Detected';
            document.getElementById('sslOcsp').textContent = (data.tlsDetails.ocsp && data.tlsDetails.ocsp.length > 0) ? data.tlsDetails.ocsp.join(', ') : 'None Detected';
            
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
            if (chatBtn) chatBtn.classList.add('hidden');
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
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Chat Widget Logic
    const openChatBtn = document.getElementById('openChatBtn');
    const closeChatBtn = document.getElementById('closeChatBtn');
    const chatWidget = document.getElementById('chatWidget');
    const sendChatBtn = document.getElementById('sendChatBtn');
    const chatInput = document.getElementById('chatInput');
    const chatMessages = document.getElementById('chatMessages');

    if (openChatBtn && closeChatBtn && chatWidget) {
        openChatBtn.addEventListener('click', () => {
            chatWidget.classList.remove('hidden');
            openChatBtn.classList.add('hidden');
        });
        closeChatBtn.addEventListener('click', () => {
            chatWidget.classList.add('hidden');
            openChatBtn.classList.remove('hidden');
        });

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
