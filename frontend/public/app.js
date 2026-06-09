/**
 * ForensicX — Frontend Controller
 * Handles file upload, analysis display, charts, chat, PDF download
 */

// ===================== GLOBAL STATE =====================
window.currentAnalysis = null;
window.currentAnalysisId = null;

let selectedFiles = [];
let allCharts = {};
const API_ROOT = '';

// ===================== INITIALIZATION =====================
document.addEventListener('DOMContentLoaded', function () {
    setupNavigation();
    setupTabs();
    setupFileUpload();
    setupChat();
    loadAnalyses();
    document.getElementById('analyzedDate').textContent = new Date().toLocaleDateString();
});


// ===================== NAVIGATION =====================
function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function () {
            switchPage(this.dataset.page);
        });
    });
}

function switchPage(page) {
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    const section = document.getElementById(page);
    if (section) section.classList.add('active');

    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === page) item.classList.add('active');
    });

    if (page === 'qa' && window.currentAnalysisId) {
        loadChatHistory(window.currentAnalysisId);
        const logName = document.getElementById('currentLogName');
        if (logName && window.currentAnalysis) {
            logName.textContent = 'Chatting about: ' + window.currentAnalysis.filename;
            logName.style.display = 'block';
        }
    }
}

function setupTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', function () {
            const container = this.closest('.card');
            container.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            container.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            this.classList.add('active');
            const target = document.getElementById(this.dataset.tab);
            if (target) target.classList.add('active');
        });
    });
}


// ===================== FILE UPLOAD =====================
function setupFileUpload() {
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', e => {
            selectedFiles = Array.from(e.target.files || []);
            renderFileList();
        });
    }

    const uploadSection = document.getElementById('uploadSection');
    if (uploadSection) {
        uploadSection.addEventListener('dragover', e => {
            e.preventDefault();
            uploadSection.classList.add('drag-over');
        });
        uploadSection.addEventListener('dragleave', () => uploadSection.classList.remove('drag-over'));
        uploadSection.addEventListener('drop', e => {
            e.preventDefault();
            uploadSection.classList.remove('drag-over');
            selectedFiles = Array.from(e.dataTransfer.files || []);
            renderFileList();
        });
    }
}

function renderFileList() {
    const fileList = document.getElementById('fileList');
    if (!fileList) return;

    fileList.innerHTML = '';
    selectedFiles.forEach((file, idx) => {
        const div = document.createElement('div');
        div.className = 'file-item';
        div.innerHTML = `
            <div class="file-info">
                <span class="file-name">📄 ${file.name}</span>
                <span class="file-size">${(file.size / 1024).toFixed(1)} KB</span>
            </div>
            <button class="remove-file" onclick="removeFile(${idx})">Remove</button>
        `;
        fileList.appendChild(div);
    });

    const uploadSection = document.getElementById('uploadSection');
    if (uploadSection) {
        uploadSection.classList.toggle('has-files', selectedFiles.length > 0);
    }
}

window.removeFile = function (idx) {
    selectedFiles.splice(idx, 1);
    renderFileList();
};

window.clearFileList = function () {
    selectedFiles = [];
    const fileInput = document.getElementById('fileInput');
    if (fileInput) fileInput.value = '';
    renderFileList();
    const uploadSection = document.getElementById('uploadSection');
    if (uploadSection) uploadSection.classList.remove('has-files');
};


// ===================== ANALYSIS =====================
window.startAnalysis = async function () {
    if (selectedFiles.length === 0) {
        alert('Please select at least one log file first.');
        return;
    }

    const progressContainer = document.getElementById('progressContainer');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const runBtn = document.getElementById('runAnalysisBtn');

    if (progressContainer) progressContainer.style.display = 'block';
    if (runBtn) runBtn.disabled = true;
    setProgress(5, 'Uploading files…');

    try {
        for (let i = 0; i < selectedFiles.length; i++) {
            const file = selectedFiles[i];
            const formData = new FormData();
            formData.append('file', file);

            setProgress(10 + (i / selectedFiles.length * 65), `Analysing ${file.name}…`);

            const response = await fetch(`${API_ROOT}/api/upload`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const err = await response.json().catch(() => ({ detail: response.statusText }));
                throw new Error(err.detail || `Server error ${response.status}`);
            }

            const result = await response.json();
            window.currentAnalysis = result;
            window.currentAnalysisId = result.log_id;
            populateReport(result);
        }

        setProgress(80, 'Generating visualisations…');
        await loadAnalyses();
        setProgress(100, 'Analysis complete ✓');

        populateGraphs(window.currentAnalysis);

        setTimeout(() => {
            if (progressContainer) progressContainer.style.display = 'none';
            if (progressText) progressText.textContent = '';
            switchPage('report');
        }, 800);

    } catch (err) {
        setProgress(0, '');
        if (progressContainer) progressContainer.style.display = 'none';
        alert('Analysis failed: ' + err.message);
        console.error('[Analysis Error]', err);
    } finally {
        if (runBtn) runBtn.disabled = false;
        selectedFiles = [];
        renderFileList();
    }
};

// alias
window.uploadAndAnalyze = window.startAnalysis;

function setProgress(pct, text) {
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    if (progressBar) progressBar.style.width = pct + '%';
    if (progressText) progressText.textContent = text;
}


// ===================== LOAD ANALYSES =====================
async function loadAnalyses() {
    try {
        const response = await fetch(`${API_ROOT}/api/analyses`);
        if (!response.ok) throw new Error(response.status);

        const data = await response.json();
        const analyses = data.analyses || [];
        const summary = data.summary || {};

        // Update metrics
        setEl('totalFiles', summary.total_files || 0);
        setEl('totalEvents', (summary.total_events || 0).toLocaleString());
        setEl('criticalAlerts', summary.total_critical || 0);

        // Log files table
        const logTable = document.getElementById('logFilesTable');
        if (logTable) {
            if (analyses.length === 0) {
                logTable.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary);padding:32px;">No logs analysed yet</td></tr>';
            } else {
                logTable.innerHTML = analyses.map(a => {
                    const m = a.file_metrics || {};
                    return `
                        <tr onclick="loadAnalysisDetail('${a.log_id}')" title="Click to view">
                            <td>${a.filename}</td>
                            <td>${m.events_count || 0}</td>
                            <td>${Math.round((a.file_size || 0) / 1024)}</td>
                            <td><span class="status-indicator status-complete"><span class="status-dot"></span>Complete</span></td>
                        </tr>
                    `;
                }).join('');
            }
        }

        // IOCs table
        const iocsTable = document.getElementById('iocsTable');
        if (iocsTable && analyses.length > 0) {
            const iocs = (analyses[0].iocs || []).slice(0, 8);
            if (iocs.length === 0) {
                iocsTable.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary);padding:32px;">No IOCs found</td></tr>';
            } else {
                iocsTable.innerHTML = iocs.map(ioc => {
                    const type = typeof ioc === 'string' && ioc.includes(':') ? ioc.split(':')[0] : 'Unknown';
                    return `
                        <tr>
                            <td>${type}</td>
                            <td style="word-break:break-all;">${ioc}</td>
                            <td><span class="severity-badge severity-high">High</span></td>
                            <td>1</td>
                        </tr>
                    `;
                }).join('');
            }
        }

    } catch (err) {
        console.error('[Load Analyses Error]', err);
    }
}

async function loadAnalysisDetail(logId) {
    try {
        window.currentAnalysisId = logId;
        const response = await fetch(`${API_ROOT}/api/analysis/${logId}`);
        if (!response.ok) throw new Error(response.status);
        window.currentAnalysis = await response.json();
        populateReport(window.currentAnalysis);
        populateGraphs(window.currentAnalysis);
        switchPage('report');
    } catch (err) {
        console.error('[Load Detail Error]', err);
    }
}

window.selectAnalysis = loadAnalysisDetail;


// ===================== POPULATE REPORT =====================
function populateReport(analysis) {
    if (!analysis) return;

    window.currentAnalysisId = analysis.log_id;
    window.currentAnalysis = analysis;

    const metrics = analysis.file_metrics || {};
    const incidents = analysis.incidents || [];
    const recommendations = analysis.recommendations || [];

    // Executive Summary
    const executiveContent = document.getElementById('executiveContent');
    if (executiveContent) {
        let summaryText = 'Heuristic analysis complete. See findings below.';
        if (analysis.summary) {
            if (typeof analysis.summary === 'object' && analysis.summary.executive) {
                summaryText = analysis.summary.executive;
            } else if (typeof analysis.summary === 'string') {
                summaryText = analysis.summary;
            }
        }
        const analysisTime = (
            analysis?.summary?.metadata?.analysis_time ||
            analysis?.summary?.analysis_time ||
            analysis?.analysis_time || 0
        ).toFixed(2);

        executiveContent.innerHTML = `
            <h2>Executive Summary</h2>
            <p>${summaryText}</p>
            <h3>Key Metrics</h3>
            <ul>
                <li>Total Events Analysed: <strong>${metrics.events_count || 0}</strong></li>
                <li>Total Incidents: <strong>${metrics.total_incidents || 0}</strong></li>
                <li>Critical: <strong style="color:var(--danger)">${metrics.critical_count || 0}</strong></li>
                <li>High: <strong style="color:var(--warning)">${metrics.high_count || 0}</strong></li>
                <li>Medium: <strong style="color:var(--info)">${metrics.medium_count || 0}</strong></li>
                <li>Low: <strong style="color:var(--success)">${metrics.low_count || 0}</strong></li>
                <li>Analysis Time: <strong>${analysisTime}s</strong></li>
            </ul>
        `;
    }

    // Findings
    const findingsContent = document.getElementById('findingsContent');
    if (findingsContent) {
        if (incidents.length === 0) {
            findingsContent.innerHTML = '<h2>Findings</h2><p>No incidents detected.</p>';
        } else {
            findingsContent.innerHTML = '<h2>Findings</h2>' + incidents.slice(0, 15).map(inc => `
                <h3>${inc.type}</h3>
                <p><strong>Severity:</strong> <span class="severity-badge severity-${(inc.severity || '').toLowerCase()}">${inc.severity}</span></p>
                <p><strong>Detail:</strong> ${inc.detail}</p>
            `).join('');
        }
    }

    // IOCs
    const iocsContent = document.getElementById('iocsContent');
    if (iocsContent) {
        if (!analysis.iocs || analysis.iocs.length === 0) {
            iocsContent.innerHTML = '<h2>Indicators of Compromise</h2><p>No IOCs identified.</p>';
        } else {
            iocsContent.innerHTML = '<h2>Indicators of Compromise</h2><ul>' +
                analysis.iocs.map(ioc => `<li style="word-break:break-all;">${ioc}</li>`).join('') + '</ul>';
        }
    }

    // Recommendations in report tab
    const recsContent = document.getElementById('recommendationsContent');
    if (recsContent) {
        if (recommendations.length === 0) {
            recsContent.innerHTML = '<h2>Recommendations</h2><p>No recommendations available.</p>';
        } else {
            recsContent.innerHTML = '<h2>Recommendations</h2>' + recommendations.map((rec, i) => `
                <div style="background:rgba(255,107,91,0.05);padding:16px;border-radius:8px;margin-bottom:12px;border-left:4px solid var(--primary);">
                    <strong>${i + 1}. ${rec}</strong>
                </div>
            `).join('');
        }
    }

    // Recommendations page
    const recsList = document.getElementById('recommendationsList');
    if (recsList) {
        if (recommendations.length === 0) {
            recsList.innerHTML = '<p style="text-align:center;color:var(--text-secondary);padding:48px 0;">No recommendations</p>';
        } else {
            recsList.innerHTML = recommendations.map((rec, i) => `
                <div style="background:linear-gradient(135deg,rgba(255,107,91,0.06) 0%,transparent 100%);padding:20px;border-radius:12px;border-left:4px solid var(--primary);">
                    <h3 style="color:var(--primary);margin-bottom:10px;">Priority ${i + 1}</h3>
                    <p>${rec}</p>
                </div>
            `).join('');
        }
    }
}


// ===================== CHARTS =====================
function populateGraphs(analysis) {
    if (!analysis || typeof Chart === 'undefined') return;

    const metrics = analysis.file_metrics || {};
    const incidents = analysis.incidents || [];

    // Severity Distribution
    renderChart('severityChart', 'doughnut', {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [metrics.critical_count || 0, metrics.high_count || 0, metrics.medium_count || 0, metrics.low_count || 0],
            backgroundColor: ['#E74C3C', '#F39C12', '#3498DB', '#27AE60'],
            borderColor: 'transparent'
        }]
    }, { plugins: { legend: { labels: { color: '#E1E8ED', padding: 16 } } } });

    // Incident Timeline
    const sevMap = { critical: 4, high: 3, medium: 2, low: 1 };
    renderChart('timelineChart', 'line', {
        labels: incidents.slice(0, 20).map((_, i) => 'Event ' + (i + 1)),
        datasets: [{
            label: 'Severity Level',
            data: incidents.slice(0, 20).map(i => sevMap[i.severity] || 1),
            borderColor: '#FF6B5B',
            backgroundColor: 'rgba(255,107,91,0.1)',
            fill: true,
            tension: 0.4
        }]
    }, {
        plugins: { legend: { labels: { color: '#E1E8ED' } } },
        scales: {
            y: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255,255,255,0.05)' } },
            x: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        }
    });

    // IOC Distribution
    const iocLabels = (analysis.iocs || []).slice(0, 6).map(s => s.length > 30 ? s.substring(0, 30) + '…' : s);
    renderChart('iocChart', 'bar', {
        labels: iocLabels,
        datasets: [{ label: 'IOC', data: Array(iocLabels.length).fill(1), backgroundColor: '#FF6B5B' }]
    }, {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
            y: { ticks: { color: '#8B949E' } },
            x: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        }
    });

    // Top Affected Systems (placeholder data enriched from IOCs)
    renderChart('systemsChart', 'bar', {
        labels: ['Web Server', 'DB Server', 'App Server', 'Workstation'],
        datasets: [{
            label: 'Incidents',
            data: [
                Math.max(metrics.critical_count || 0, 1),
                Math.max(metrics.high_count || 0, 1),
                Math.max(metrics.medium_count || 0, 1),
                Math.max(metrics.low_count || 0, 1)
            ],
            backgroundColor: ['#E74C3C', '#F39C12', '#3498DB', '#27AE60']
        }]
    }, {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
            y: { ticks: { color: '#8B949E' } },
            x: { ticks: { color: '#8B949E' }, grid: { color: 'rgba(255,255,255,0.05)' } }
        }
    });
}

function renderChart(id, type, data, extraOptions) {
    const ctx = document.getElementById(id);
    if (!ctx) return;
    if (allCharts[id]) allCharts[id].destroy();
    allCharts[id] = new Chart(ctx, {
        type,
        data,
        options: Object.assign({ responsive: true, maintainAspectRatio: false }, extraOptions || {})
    });
}


// ===================== DOWNLOADS =====================
window.downloadPDF = async function () {
    if (!window.currentAnalysis) { alert('Run an analysis first.'); return; }

    const images = {};
    ['severityChart', 'timelineChart', 'iocChart', 'systemsChart'].forEach(id => {
        const canvas = document.getElementById(id);
        if (canvas) images[id] = canvas.toDataURL('image/png');
    });

    try {
        const response = await fetch(`/api/report/pdf/${window.currentAnalysis.log_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ analysis: window.currentAnalysis, images })
        });
        if (!response.ok) throw new Error('PDF generation failed');
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `forensicx_report_${window.currentAnalysis.log_id}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (err) {
        alert('PDF download failed: ' + err.message);
    }
};

window.downloadJSON = function () {
    if (!window.currentAnalysis) { alert('Run an analysis first.'); return; }
    const blob = new Blob([JSON.stringify(window.currentAnalysis, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `analysis_${window.currentAnalysis.log_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
};

window.openChatForCurrentLog = function () {
    if (!window.currentAnalysisId) {
        alert('No analysis selected. Run an analysis first.');
        return;
    }
    switchPage('qa');
};


// ===================== CHAT =====================
function setupChat() {
    const chatInput = document.getElementById('chatInput');
    if (chatInput) chatInput.addEventListener('keypress', e => { if (e.key === 'Enter') sendMessage(); });

    const sendBtn = document.getElementById('sendBtn');
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);
}

async function loadChatHistory(logId) {
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;

    try {
        const response = await fetch(`${API_ROOT}/api/chat/${logId}/history`);
        if (!response.ok) return;
        const data = await response.json();
        const messages = data.messages || [];
        if (messages.length > 0) {
            chatMessages.innerHTML = '';
            messages.forEach(msg => addChatMessage(msg.role === 'user' ? 'user' : 'bot', msg.content));
        }
    } catch (err) {
        console.error('[Chat History Error]', err);
    }
}

async function sendMessage() {
    const input = document.getElementById('chatInput');
    if (!input) return;
    const question = input.value.trim();
    if (!question) return;

    addChatMessage('user', question);
    input.value = '';

    if (!window.currentAnalysis) {
        addChatMessage('bot', 'Please run an analysis first, then ask me questions about the findings.');
        return;
    }

    // Show thinking dots
    const thinkingId = 'thinking-' + Date.now();
    const chatMessages = document.getElementById('chatMessages');
    if (chatMessages) {
        const div = document.createElement('div');
        div.className = 'chat-message bot';
        div.id = thinkingId;
        div.innerHTML = `<div class="message-avatar bot">🤖</div><div class="message-content"><div class="thinking"><span></span><span></span><span></span></div></div>`;
        chatMessages.appendChild(div);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    try {
        const response = await fetch(`${API_ROOT}/api/chat/${window.currentAnalysis.log_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question })
        });
        const data = await response.json();
        const thinkingEl = document.getElementById(thinkingId);
        if (thinkingEl) thinkingEl.remove();
        addChatMessage('bot', data.answer || 'No response received.');
    } catch (err) {
        const thinkingEl = document.getElementById(thinkingId);
        if (thinkingEl) thinkingEl.remove();
        addChatMessage('bot', 'Error: ' + err.message);
    }
}

function addChatMessage(role, content) {
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;
    const div = document.createElement('div');
    div.className = 'chat-message ' + (role === 'user' ? 'user' : 'bot');
    div.innerHTML = `
        <div class="message-avatar ${role}">${role === 'user' ? '👤' : '🤖'}</div>
        <div class="message-content">${escapeHtml(content)}</div>
    `;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

window.askQuestion = function (q) {
    const chatInput = document.getElementById('chatInput');
    if (chatInput) { chatInput.value = q; sendMessage(); }
};

window.clearChat = function () {
    const chatMessages = document.getElementById('chatMessages');
    if (chatMessages) {
        chatMessages.innerHTML = `
            <div class="chat-message bot">
                <div class="message-avatar bot">🤖</div>
                <div class="message-content">Chat cleared. Ask me anything about your forensic analysis.</div>
            </div>
        `;
    }
};


// ===================== UTILS =====================
function setEl(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}