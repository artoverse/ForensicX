/**
 * ForensicX Controller - DEBUG VERSION
 * ✅ Extensive logging to trace currentAnalysisId issue
 */

// ✅ CRITICAL: Declare currentAnalysisId in GLOBAL scope
window.currentAnalysisId = null;
window.currentAnalysis = null;

// ===================== GLOBAL STATE =====================
let selectedFiles = [];
let allCharts = {};
const API_ROOT = '';

console.log('🚀 [INIT] Script loaded, currentAnalysisId:', window.currentAnalysisId);

// ===================== INITIALIZATION =====================
document.addEventListener('DOMContentLoaded', function() {
    console.log('[ForensicX] Initializing...');
    setupEventListeners();
    loadAnalyses();
});


function setupEventListeners() {
    // File input
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            selectedFiles = Array.from(e.target.files || []);
            renderFileList();
        });
    }

    // Drag and drop
    const uploadSection = document.getElementById('uploadSection');
    if (uploadSection) {
        uploadSection.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadSection.style.borderColor = 'var(--primary)';
            uploadSection.style.background = 'linear-gradient(135deg, rgba(255, 107, 91, 0.15) 0%, transparent 100%)';
        });

        uploadSection.addEventListener('dragleave', () => {
            uploadSection.style.borderColor = 'var(--border)';
            uploadSection.style.background = 'linear-gradient(135deg, rgba(255, 107, 91, 0.05) 0%, transparent 100%)';
        });

        uploadSection.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadSection.style.borderColor = 'var(--border)';
            uploadSection.style.background = 'linear-gradient(135deg, rgba(255, 107, 91, 0.05) 0%, transparent 100%)';
            selectedFiles = Array.from(e.dataTransfer.files || []);
            renderFileList();
        });
    }

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function() {
            const page = this.dataset.page;
            switchPage(page);
        });
    });

    // Tabs
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const tabName = this.dataset.tab;
            switchTab(tabName);
        });
    });

    // Chat
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.addEventListener('keypress', function(e) {
            if(e.key === 'Enter') sendMessage();
        });
    }
    
    const sendBtn = document.getElementById('sendBtn');
    if (sendBtn) {
        sendBtn.addEventListener('click', sendMessage);
    }
}


// ===================== FILE MANAGEMENT =====================
function renderFileList() {
    const fileList = document.getElementById('fileList');
    if (!fileList) return;
    
    fileList.innerHTML = '';
    let totalSize = 0;

    selectedFiles.forEach((file, idx) => {
        const sizeMB = (file.size / 1024).toFixed(2);
        totalSize += file.size;

        const div = document.createElement('div');
        div.className = 'file-item';
        div.innerHTML = `
            <div class="file-info">
                <span class="file-name">📄 ${file.name}</span>
                <span class="file-size">${sizeMB} KB</span>
            </div>
            <button class="remove-file" onclick="removeFile(${idx})">Remove</button>
        `;
        fileList.appendChild(div);
    });

    if(selectedFiles.length > 0) {
        const uploadSection = document.getElementById('uploadSection');
        if (uploadSection) uploadSection.classList.add('has-files');
    }
}

window.removeFile = function(idx) {
    selectedFiles.splice(idx, 1);
    renderFileList();
};

window.clearFileList = function() {
    selectedFiles = [];
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.value = '';
    renderFileList();
    const uploadSection = document.getElementById('uploadSection');
    if (uploadSection) uploadSection.classList.remove('has-files');
};


// ===================== ANALYSIS =====================
window.startAnalysis = async function() {
    console.log('🎯 [START] startAnalysis called');
    
    if(selectedFiles.length === 0) {
        alert('Please select at least one log file');
        return;
    }

    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const statusText = document.getElementById('statusText');

    try {
        if (progressText) progressText.textContent = 'Uploading files...';
        if (progressBar) progressBar.style.width = '10%';
        if (statusText) statusText.textContent = 'Processing...';

        for(let i = 0; i < selectedFiles.length; i++) {
            const file = selectedFiles[i];
            console.log(`📤 [UPLOAD] File ${i+1}/${selectedFiles.length}: ${file.name}`);
            
            const formData = new FormData();
            formData.append('file', file);

            const progress = 10 + (i / selectedFiles.length * 70);
            if (progressBar) progressBar.style.width = progress + '%';

            const response = await fetch(`${API_ROOT}/api/upload`, {
                method: 'POST',
                body: formData
            });

            if(!response.ok) {
                throw new Error(`Upload failed: ${response.status}`);
            }

            const result = await response.json();
            console.log('✅ [UPLOAD] Success - Full result:', result);
            console.log('🔍 [UPLOAD] result.log_id:', result.log_id);
            
            window.currentAnalysis = result;
            console.log('📝 [UPLOAD] Set window.currentAnalysis');
            
            // ✅ CRITICAL FIX: Set currentAnalysisId immediately after upload
            window.currentAnalysisId = result.log_id;
            console.log('🎯 [UPLOAD] Set window.currentAnalysisId:', window.currentAnalysisId);
            console.log('🔍 [UPLOAD] Verify - window.currentAnalysisId is now:', window.currentAnalysisId);

            console.log('📊 [UPLOAD] Calling populateReport immediately after setting currentAnalysisId');
            populateReport(result);
            console.log('📊 [UPLOAD] After populateReport - currentAnalysisId:', window.currentAnalysisId);
        }

        if (progressBar) progressBar.style.width = '80%';
        if (progressText) progressText.textContent = 'Generating visualizations...';

        await new Promise(r => setTimeout(r, 500));
        if (progressBar) progressBar.style.width = '100%';
        if (progressText) progressText.textContent = 'Analysis complete!';
        if (statusText) statusText.textContent = 'Complete';

        console.log('📊 [UPLOAD] Before loadAnalyses - currentAnalysisId:', window.currentAnalysisId);
        
        // Reload data
        await loadAnalyses();
        
        console.log('📊 [UPLOAD] After loadAnalyses - currentAnalysisId:', window.currentAnalysisId);
        // console.log('📊 [UPLOAD] About to call populateReport with:', window.currentAnalysis);
        
        // populateReport(window.currentAnalysis);
        
        // console.log('📊 [UPLOAD] After populateReport - currentAnalysisId:', window.currentAnalysisId);
        
        populateGraphs(window.currentAnalysis);
        
        console.log('📊 [UPLOAD] After populateGraphs - currentAnalysisId:', window.currentAnalysisId);

        // Switch to report
        setTimeout(() => {
            console.log('🔄 [UPLOAD] Switching to report page - currentAnalysisId:', window.currentAnalysisId);
            switchPage('report');
        }, 500);

    } catch(err) {
        console.error('❌ [Analysis Error]', err);
        if (progressBar) progressBar.style.width = '0%';
        if (progressText) progressText.textContent = 'Error: ' + err.message;
        if (statusText) statusText.textContent = 'Error';
        alert('Analysis failed: ' + err.message);
    }

    selectedFiles = [];
    renderFileList();
    const uploadSection = document.getElementById('uploadSection');
    if (uploadSection) uploadSection.classList.remove('has-files');
};

// ✅ Alias for backward compatibility
window.uploadAndAnalyze = window.startAnalysis;


// ===================== LOAD & DISPLAY =====================
async function loadAnalyses() {
    console.log('📋 [LOAD] loadAnalyses called - BEFORE: currentAnalysisId =', window.currentAnalysisId);
    
    try {
        const response = await fetch(`${API_ROOT}/api/analyses`);
        if(!response.ok) throw new Error(response.status);

        const data = await response.json();
        const analyses = data.analyses || [];
        const summary = data.summary || {};

        console.log('[Analyses Loaded]', analyses, summary);

        // Update metrics
        const totalFiles = document.getElementById('totalFiles');
        const totalEvents = document.getElementById('totalEvents');
        const criticalAlerts = document.getElementById('criticalAlerts');
        
        if (totalFiles) totalFiles.textContent = summary.total_files || 0;
        if (totalEvents) totalEvents.textContent = (summary.total_events || 0).toLocaleString();
        if (criticalAlerts) criticalAlerts.textContent = summary.total_critical || 0;

        // Update log files table
        const logTable = document.getElementById('logFilesTable');
        if (logTable) {
            logTable.innerHTML = '';
            let totalLines = 0;
            let totalSize = 0;

            analyses.forEach(a => {
                const tr = document.createElement('tr');
                const metrics = a.file_metrics || {};
                totalLines += metrics.events_count || 0;
                totalSize += (a.file_size || 0);

                tr.innerHTML = `
                    <td>${a.filename}</td>
                    <td>${metrics.events_count || 0}</td>
                    <td>${Math.round((a.file_size || 0) / 1024)}</td>
                    <td><span class="status-indicator"><span class="status-dot"></span><span>Complete</span></span></td>
                `;
                tr.style.cursor = 'pointer';
                tr.addEventListener('click', () => {
                    loadAnalysisDetail(a.log_id);
                });
                logTable.appendChild(tr);
            });

            const totalLinesEl = document.getElementById('totalLines');
            const totalSizeEl = document.getElementById('totalSize');
            if (totalLinesEl) totalLinesEl.textContent = totalLines;
            if (totalSizeEl) totalSizeEl.textContent = Math.round(totalSize / 1024);
        }

        // Update IOCs table
        if(analyses.length > 0) {
            const iocsTable = document.getElementById('iocsTable');
            if (iocsTable) {
                iocsTable.innerHTML = '';
                const topIOCs = (analyses[0].iocs || []).slice(0, 5);

                topIOCs.forEach(ioc => {
                    const tr = document.createElement('tr');
                    const type = (typeof ioc === 'string' && ioc.includes(':')) ? ioc.split(':')[0] : Array.isArray(ioc) ? (ioc[0] || 'Unknown') : 'Unknown';
                    tr.innerHTML = `
                        <td>${type}</td>
                        <td>${ioc}</td>
                        <td><span class="severity-badge severity-high">High</span></td>
                        <td>1</td>
                    `;
                    iocsTable.appendChild(tr);
                });
            }
        }

    } catch(err) {
        console.error('[Load Analyses Error]', err);
    }
    
    console.log('📋 [LOAD] loadAnalyses completed - AFTER: currentAnalysisId =', window.currentAnalysisId);
}

// ✅ FIXED: loadAnalysisDetail now sets window.currentAnalysisId
async function loadAnalysisDetail(logId) {
    try {
        console.log('[Select] Log ID:', logId);
        window.currentAnalysisId = logId;  // ✅ SET GLOBAL VARIABLE

        const response = await fetch(`${API_ROOT}/api/analysis/${logId}`);
        if(!response.ok) throw new Error(response.status);

        window.currentAnalysis = await response.json();
        console.log('[Analysis] Loaded:', window.currentAnalysis);
        console.log('[Analysis] currentAnalysisId is now:', window.currentAnalysisId);

        populateReport(window.currentAnalysis);
        populateGraphs(window.currentAnalysis);
        switchPage('report');

    } catch(err) {
        console.error('[Load Detail Error]', err);
    }
}

// ✅ ADDED: window.selectAnalysis alias for compatibility
window.selectAnalysis = loadAnalysisDetail;

function populateReport(analysis) {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🎨 [POPULATE] populateReport CALLED');
    console.log('🔍 [POPULATE] Received analysis:', analysis);
    console.log('🔍 [POPULATE] analysis is null?', analysis === null);
    console.log('🔍 [POPULATE] analysis is undefined?', analysis === undefined);
    
    if(!analysis) {
        console.log('❌ [POPULATE] Analysis is null/undefined, returning early');
        return;
    }

    console.log('🔍 [POPULATE] analysis.log_id:', analysis.log_id);
    console.log('🔍 [POPULATE] BEFORE setting - window.currentAnalysisId:', window.currentAnalysisId);
    
    // ✅ CRITICAL FIX: Set currentAnalysisId when populating ANY report
    if (analysis && analysis.log_id && typeof analysis.log_id === 'string' && analysis.log_id.length > 0) {
        window.currentAnalysisId = analysis.log_id;
        console.log('✅ [POPULATE] SET window.currentAnalysisId to:', window.currentAnalysisId);
    }else {
        console.log('⚠️ [POPULATE] analysis.log_id is missing! Full analysis object:', JSON.stringify(analysis, null, 2));
    }
    

    const metrics = analysis.file_metrics || {};
    const incidents = analysis.incidents || [];
    const recommendations = analysis.recommendations || [];

    // Executive Summary
    const executiveContent = document.getElementById('executiveContent');
    if (executiveContent) {
        // Always extract metrics first
        const metrics = analysis.file_metrics || {};

        // Robust summary extraction
        let summaryText = analysis.summary && analysis.summary.executive? analysis.summary.executive: 'Executive Summary not available for this log. See details below for incidents.';
        if (analysis.summary) {
            if (typeof analysis.summary === 'object' && analysis.summary.executive) {
                summaryText = analysis.summary.executive;
            } else if (typeof analysis.summary === 'string' && analysis.summary.length > 0) {
                summaryText = analysis.summary;
            }
        }
        executiveContent.innerHTML = `
            <h2>Executive Summary</h2>
            <p>${summaryText}</p>
            <h3>Quick Stats</h3>
            <p>${analysis.summary_stats || ''}</p>
            <h3>Key Metrics</h3>
            <ul>
                <li>Total Events Analyzed: <strong>${metrics.events_count || 0}</strong></li>
                <li>Total Incidents: <strong>${metrics.total_incidents || 0}</strong></li>
                <li>Critical: <strong>${metrics.critical_count || 0}</strong></li>
                <li>High: <strong>${metrics.high_count || 0}</strong></li>
                <li>Medium: <strong>${metrics.medium_count || 0}</strong></li>
                <li>Low: <strong>${metrics.low_count || 0}</strong></li>
                <li>Analysis Time: <strong>${(
                    analysis?.summary?.metadata?.analysis_time || 
                    analysis?.summary?.analysis_time || 
                    analysis?.analysis_time || 0
                ).toFixed(2)}s</strong></li>

            </ul>
        `;
    }



    // Findings
    const findingsContent = document.getElementById('findingsContent');
    if (findingsContent) {
        let findingsHTML = '<h2>Findings</h2>';
        if(incidents.length === 0) {
            findingsHTML += '<p>No incidents found.</p>';
        } else {
            incidents.slice(0, 10).forEach(inc => {
                findingsHTML += `
                    <h3>${inc.type}</h3>
                    <p><strong>Severity:</strong> <span class="severity-badge severity-${inc.severity.toLowerCase()}">${inc.severity}</span></p>
                    <p><strong>Details:</strong> ${inc.detail}</p>
                `;
            });
        }
        findingsContent.innerHTML = findingsHTML;
    }

    // IOCs
    const iocsContent = document.getElementById('iocsContent');
    if (iocsContent) {
        let iocsHTML = '<h2>Indicators of Compromise</h2>';
        if(analysis.iocs && analysis.iocs.length > 0) {
            iocsHTML += '<ul>';
            analysis.iocs.forEach(ioc => {
                iocsHTML += `<li>${ioc}</li>`;
            });
            iocsHTML += '</ul>';
        } else {
            iocsHTML += '<p>No IOCs identified.</p>';
        }
        iocsContent.innerHTML = iocsHTML;
    }

    // Recommendations
    const recommendationsContent = document.getElementById('recommendationsContent');
    if (recommendationsContent) {
        let recsHTML = '<h2>Recommendations</h2>';
        if(recommendations.length === 0) {
            recsHTML += '<p>No recommendations available.</p>';
        } else {
            recommendations.forEach((rec, idx) => {
                recsHTML += `
                    <div style="background: rgba(255,107,91,0.05); padding: 16px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid var(--primary);">
                        <strong>${idx + 1}. ${rec}</strong>
                    </div>
                `;
            });
        }
        recommendationsContent.innerHTML = recsHTML;
    }

    // Populate recommendations page
    const recsList = document.getElementById('recommendationsList');
    if (recsList) {
        recsList.innerHTML = '';
        if(recommendations.length === 0) {
            recsList.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 40px;">No recommendations</p>';
        } else {
            recommendations.forEach((rec, idx) => {
                const div = document.createElement('div');
                div.style.background = 'linear-gradient(135deg, rgba(255,107,91,0.05) 0%, transparent 100%)';
                div.style.padding = '20px';
                div.style.borderRadius = '12px';
                div.style.borderLeft = '4px solid var(--primary)';
                div.innerHTML = `
                    <h3 style="color: var(--primary); margin-bottom: 10px;">Priority ${idx + 1}</h3>
                    <p>${rec}</p>
                `;
                recsList.appendChild(div);
            });
        }
    }
}

function populateGraphs(analysis) {
    if(!analysis) return;

    const metrics = analysis.file_metrics || {};
    const incidents = analysis.incidents || [];

    // Severity Distribution Pie Chart
    const sevCtx = document.getElementById('severityChart');
    if(sevCtx && typeof Chart !== 'undefined') {
        if(allCharts.severity) allCharts.severity.destroy();
        allCharts.severity = new Chart(sevCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        metrics.critical_count || 0,
                        metrics.high_count || 0,
                        metrics.medium_count || 0,
                        metrics.low_count || 0
                    ],
                    backgroundColor: ['#E74C3C', '#F39C12', '#3498DB', '#27AE60'],
                    borderColor: 'transparent'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#E1E8ED' } } }
            }
        });
    }

    // Timeline Line Chart
    const timeCtx = document.getElementById('timelineChart');
    if(timeCtx && typeof Chart !== 'undefined') {
        if(allCharts.timeline) allCharts.timeline.destroy();
        const sevMap = { critical: 4, high: 3, medium: 2, low: 1 };
        const timelineData = incidents.slice(0, 20).map(i => sevMap[i.severity] || 1);

        allCharts.timeline = new Chart(timeCtx, {
            type: 'line',
            data: {
                labels: incidents.slice(0, 20).map((_, i) => 'Event ' + (i+1)),
                datasets: [{
                    label: 'Severity Level',
                    data: timelineData,
                    borderColor: '#FF6B5B',
                    backgroundColor: 'rgba(255, 107, 91, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#E1E8ED' } } },
                scales: {
                    y: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255, 255, 255, 0.05)' } },
                    x: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255, 255, 255, 0.05)' } }
                }
            }
        });
    }

    // IOC Distribution
    const iocCtx = document.getElementById('iocChart');
    if(iocCtx && typeof Chart !== 'undefined') {
        if(allCharts.ioc) allCharts.ioc.destroy();
        allCharts.ioc = new Chart(iocCtx, {
            type: 'bar',
            data: {
                labels: (analysis.iocs || []).slice(0, 5),
                datasets: [{
                    label: 'IOC Count',
                    data: Array(Math.min(5, analysis.iocs?.length || 0)).fill(1),
                    backgroundColor: '#FF6B5B'
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#E1E8ED' } } },
                scales: {
                    y: { ticks: { color: '#8B949E' } },
                    x: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255, 255, 255, 0.05)' } }
                }
            }
        });
    }

    // Top Affected Systems
    const sysCtx = document.getElementById('systemsChart');
    if(sysCtx && typeof Chart !== 'undefined') {
        if(allCharts.systems) allCharts.systems.destroy();
        allCharts.systems = new Chart(sysCtx, {
            type: 'bar',
            data: {
                labels: ['WEB-SERVER-01', 'DB-SERVER-02', 'APP-SERVER-03', 'WORKSTATION-15'],
                datasets: [{
                    label: 'Incidents',
                    data: [45, 32, 28, 18],
                    backgroundColor: ['#E74C3C', '#F39C12', '#3498DB', '#27AE60']
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { labels: { color: '#E1E8ED' } } },
                scales: {
                    y: { ticks: { color: '#8B949E' } },
                    x: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255, 255, 255, 0.05)' } }
                }
            }
        });
    }
}




// ===================== NAVIGATION =====================
function switchPage(page) {
    console.log(`🔄 [NAV] Switching to page: ${page}, currentAnalysisId: ${window.currentAnalysisId}`);
    
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    const section = document.getElementById(page);
    if (section) section.classList.add('active');

    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if(item.dataset.page === page) item.classList.add('active');
    });
    
    // ✅ Load chat history when switching to Q&A
    if (page === 'qa' && window.currentAnalysisId) {
        loadChatHistory(window.currentAnalysisId);
        updateQAHeader();
    }
}

function switchTab(tab) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    const tabContent = document.getElementById(tab);
    if (tabContent) tabContent.classList.add('active');

    document.querySelectorAll('.tab').forEach(t => {
        t.classList.remove('active');
        if(t.dataset.tab === tab) t.classList.add('active');
    });
}

// ✅ NEW: Update Q&A header with current log filename
function updateQAHeader() {
    const logNameEl = document.getElementById('currentLogName');
    if (logNameEl && window.currentAnalysis) {
        logNameEl.textContent = `Chatting about: ${window.currentAnalysis.filename}`;
        logNameEl.style.display = 'block';
    }
}

// ✅ NEW: Function to open chat from Report section
window.openChatForCurrentLog = function() {
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('💬 [Open Chat] Button clicked!');
    console.log('🔍 [Open Chat] Checking currentAnalysisId:', window.currentAnalysisId);
    console.log('🔍 [Open Chat] window.currentAnalysis:', window.currentAnalysis);
    console.log('🔍 [Open Chat] typeof currentAnalysisId:', typeof window.currentAnalysisId);
    console.log('🔍 [Open Chat] currentAnalysisId === null?', window.currentAnalysisId === null);
    console.log('🔍 [Open Chat] currentAnalysisId === undefined?', window.currentAnalysisId === undefined);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
    if (!window.currentAnalysisId) {
        console.log('❌ [Open Chat] No currentAnalysisId - showing alert');
        alert('No log file selected. Please select a log from the dashboard first.');
        return;
    }
    
    console.log('✅ [Open Chat] currentAnalysisId exists, proceeding...');
    updateQAHeader();
    loadChatHistory(window.currentAnalysisId);
    switchPage('qa');
};

function setCanvasDarkBackground(canvas) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.save();
    ctx.globalCompositeOperation = 'destination-over';
    ctx.fillStyle = '#181A20'; // Dark background (almost black)
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.restore();
}


function getBase64ImagesForReport(logId) {
    const canvasMap = {
        severity: document.getElementById('severityChart'),
        timeline: document.getElementById('timelineChart'),
        ioc: document.getElementById('iocChart'),
        systems: document.getElementById('systemsChart'),
    };
    const images = {};
    Object.keys(canvasMap).forEach(key => {
        const canvas = canvasMap[key];
        if (canvas) {
            setCanvasDarkBackground(canvas); // << ADD THIS LINE!
            images[key] = canvas.toDataURL('image/png');
        }
    });
    return images;
}


// ===================== DOWNLOADS =====================
window.downloadPDF = async function() {
    if(!window.currentAnalysis) {
        alert('No analysis to download');
        return;
    }
    const logId = window.currentAnalysis.log_id;
    const analysis = window.currentAnalysis;
    const images = getBase64ImagesForReport(logId);

    // Request PDF generation and download
    const response = await fetch(`/api/report/pdf/${logId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysis, images })
    });

    if (!response.ok) {
        alert('PDF generation failed');
        return;
    }

    // Download result
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensicx_report_${logId}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
};


window.downloadJSON = function() {
    if(!window.currentAnalysis) {
        alert('No analysis to download');
        return;
    }
    const dataStr = JSON.stringify(window.currentAnalysis, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'analysis_' + window.currentAnalysis.log_id + '.json';
    a.click();
    URL.revokeObjectURL(url);
};


// ===================== CHAT =====================
async function loadChatHistory(logId) {
    try {
        const response = await fetch(`${API_ROOT}/api/chat/${logId}/history`);
        
        const chatMessages = document.getElementById('chatMessages');
        if (!chatMessages) return;
        
        if (!response.ok) {
            chatMessages.innerHTML = '';
            addChatMessage('bot', 'Hello! I\'m your ForensicX AI assistant. Ask me anything about this log analysis.');
            return;
        }
        
        const data = await response.json();
        const messages = data.messages || [];
        
        chatMessages.innerHTML = '';
        
        if (messages.length === 0) {
            addChatMessage('bot', 'Hello! I\'m your ForensicX AI assistant. Ask me anything about this log analysis.');
        } else {
            messages.forEach(msg => {
                addChatMessage(msg.role === 'user' ? 'user' : 'bot', msg.content);
            });
        }
        
    } catch (err) {
        console.error('[Chat History] Error:', err);
        const chatMessages = document.getElementById('chatMessages');
        if (chatMessages) {
            chatMessages.innerHTML = '';
            addChatMessage('bot', 'Hello! I\'m your ForensicX AI assistant. Ask me anything about this log analysis.');
        }
    }
}

function addChatMessage(role, content) {
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;
    
    const div = document.createElement('div');
    div.className = 'chat-message ' + (role === 'user' ? 'user' : 'bot');
    div.innerHTML = `
        <div class="message-avatar ${role === 'user' ? 'user' : 'bot'}">${role === 'user' ? '👤' : '🤖'}</div>
        <div class="message-content">${escapeHtml(content)}</div>
    `;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

async function sendMessage() {
    const input = document.getElementById('chatInput');
    if (!input) return;
    
    const question = input.value.trim();
    if(!question) return;

    addChatMessage('user', question);
    input.value = '';

    if(!window.currentAnalysis) {
        addChatMessage('bot', 'Please run an analysis first to ask questions.');
        return;
    }

    try {
        const response = await fetch(`${API_ROOT}/api/chat/${window.currentAnalysis.log_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question })
        });

        const data = await response.json();
        addChatMessage('bot', data.answer);
    } catch(err) {
        console.error('[Chat Error]', err);
        addChatMessage('bot', 'Error: ' + err.message);
    }
}

window.askQuestion = function(q) {
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.value = q;
        sendMessage();
    }
};

window.clearChat = function() {
    const chatMessages = document.getElementById('chatMessages');
    if (chatMessages) {
        chatMessages.innerHTML = `
            <div class="chat-message bot">
                <div class="message-avatar bot">🤖</div>
                <div class="message-content">Chat cleared. How can I help you now?</div>
            </div>
        `;
    }
};

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}