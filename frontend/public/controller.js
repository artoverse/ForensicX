/**
 * ForensicX Controller
 * Binds UI to backend API endpoints
 * Handles: upload, analysis, charts, reports, chat
 */

(function() {
    const API_ROOT = '';  // Same origin
    
    // DOM query helpers
    const $ = (sel) => document.querySelector(sel);
    const $all = (sel) => Array.from(document.querySelectorAll(sel));
    const id = (i) => document.getElementById(i);
    const el = (tag, attrs = {}) => {
        const e = document.createElement(tag);
        Object.assign(e, attrs);
        return e;
    };
    
    // Safe event binding
    const safeBind = (elem, event, fn) => {
        if (elem) elem.addEventListener(event, fn);
    };
    
    // State
    let selectedFiles = [];
    let currentAnalysisId = null;
    let currentAnalysis = null;
    
    // ============================
    // INITIALIZATION
    // ============================
    
    function init() {
        console.log('[ForensicX] Initializing...');
        bindFileUpload();
        bindNavigation();
        bindChatControls();
        loadAnalysisHistory();
        setupDragDrop();
    }
    
    // ============================
    // FILE UPLOAD
    // ============================
    
    function bindFileUpload() {
        const fileInput = id('fileInput') || $('input[type="file"]');
        if (fileInput) {
            safeBind(fileInput, 'change', (e) => {
                selectedFiles = Array.from(e.target.files || []);
                renderFileList();
            });
        }
        
        const uploadBtn = id('runAnalysisBtn') || $('.upload-btn');
        safeBind(uploadBtn, 'click', uploadAndAnalyze);
    }
    
    function setupDragDrop() {
        const dropZone = id('uploadSection') || $('.upload-area') || document.body;
        safeBind(dropZone, 'dragover', (e) => {
            e.preventDefault();
            dropZone.style.backgroundColor = '#f0f0f0';
        });
        safeBind(dropZone, 'dragleave', () => {
            dropZone.style.backgroundColor = '';
        });
        safeBind(dropZone, 'drop', (e) => {
            e.preventDefault();
            dropZone.style.backgroundColor = '';
            selectedFiles = Array.from(e.dataTransfer.files || []);
            renderFileList();
        });
    }
    
    function renderFileList() {
        const listEl = id('uploadedFiles') || id('fileList') || $('.file-list');
        if (!listEl) return;
        
        listEl.innerHTML = '';
        let totalSize = 0;
        
        selectedFiles.forEach((f, idx) => {
            const div = el('div', { className: 'file-item' });
            const size = (f.size / 1024).toFixed(2);
            totalSize += f.size;
            
            div.innerHTML = `
                <span>📄 ${f.name} (${size} KB)</span>
                <button onclick="removeFile(${idx})">Remove</button>
            `;
            listEl.appendChild(div);
        });
        
        if (selectedFiles.length > 0) {
            const totalDiv = el('div', { className: 'file-summary' });
            totalDiv.textContent = `Total: ${selectedFiles.length} file(s), ${(totalSize / 1024).toFixed(2)} KB`;
            listEl.appendChild(totalDiv);
        }
    }
    
    window.removeFile = (idx) => {
        selectedFiles.splice(idx, 1);
        renderFileList();
    };
    
    async function uploadAndAnalyze() {
        if (selectedFiles.length === 0) {
            alert('Please select files to analyze');
            return;
        }
        
        for (const file of selectedFiles) {
            await uploadFile(file);
        }
        
        selectedFiles = [];
        renderFileList();
        loadAnalysisHistory();
    }
    
    async function uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch(`${API_ROOT}/api/upload`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) throw new Error(response.statusText);
            
            const result = await response.json();
            console.log('[Upload] Success:', result);
            
            // Show success message
            const msg = `✅ Analyzed: ${file.name} - Found ${result.file_metrics.total_incidents} incidents`;
            showNotification(msg, 'success');
            
        } catch (err) {
            console.error('[Upload] Error:', err);
            showNotification(`❌ Error uploading ${file.name}: ${err.message}`, 'error');
        }
    }
    
    // ============================
    // ANALYSIS HISTORY & DISPLAY
    // ============================
    
    async function loadAnalysisHistory() {
        try {
            const response = await fetch(`${API_ROOT}/api/analyses`);
            if (!response.ok) throw new Error(response.statusText);
            
            const data = await response.json();
            const analyses = data.analyses || [];
            const summary = data.summary || {};
            
            // Update dashboard numbers
            updateDashboard(analyses, summary);
            
            // Populate analysis list
            const listEl = id('analysisList') || $('#analysisList');
            if (listEl) {
                listEl.innerHTML = '';
                analyses.forEach(a => {
                    const div = el('div', { className: 'analysis-item' });
                    div.innerHTML = `
                        <h4>${a.filename}</h4>
                        <p>ID: ${a.log_id}</p>
                        <p>Events: ${a.file_metrics.events_count} | Incidents: ${a.file_metrics.total_incidents}</p>
                        <button onclick="selectAnalysis('${a.log_id}')">View Details</button>
                    `;
                    listEl.appendChild(div);
                });
            }
        } catch (err) {
            console.error('[History] Error:', err);
        }
    }
    
    function updateDashboard(analyses, summary) {
        if (id('totalFiles')) id('totalFiles').textContent = summary.total_files || 0;
        if (id('totalEvents')) id('totalEvents').textContent = summary.total_events || 0;
        if (id('totalCritical')) id('totalCritical').textContent = summary.total_critical || 0;
    }
    
    window.selectAnalysis = async (logId) => {
        currentAnalysisId = logId;
        
        try {
            const response = await fetch(`${API_ROOT}/api/analysis/${logId}`);
            if (!response.ok) throw new Error(response.statusText);
            
            currentAnalysis = await response.json();
            displayAnalysisDetails(currentAnalysis);
            
        } catch (err) {
            console.error('[Analysis] Error:', err);
            alert('Failed to load analysis details');
        }
    };
    
    function displayAnalysisDetails(analysis) {
        // Update report section
        const reportEl = id('reportContent') || $('.report-content');
        if (reportEl) {
            reportEl.innerHTML = `
                <h3>Forensic Analysis Report</h3>
                <p><strong>File:</strong> ${analysis.filename}</p>
                <p><strong>Events:</strong> ${analysis.file_metrics.events_count}</p>
                <p><strong>Incidents Found:</strong> ${analysis.file_metrics.total_incidents}</p>
                <h4>Severity Breakdown</h4>
                <ul>
                    <li>Critical: ${analysis.file_metrics.critical_count}</li>
                    <li>High: ${analysis.file_metrics.high_count}</li>
                    <li>Medium: ${analysis.file_metrics.medium_count}</li>
                    <li>Low: ${analysis.file_metrics.low_count}</li>
                </ul>
                <h4>Recommendations</h4>
                <ul>${analysis.recommendations.map(r => `<li>${r}</li>`).join('')}</ul>
            `;
        }
        
        // Load and display charts
        loadCharts(analysis.log_id);
        
        // Load chat history
        loadChatHistory(analysis.log_id);
        
        // Switch to report tab
        switchTab('report');
    }
    
    // ============================
    // CHARTS
    // ============================
    
    async function loadCharts(logId) {
        const chartsEl = id('chartsContent') || $('.charts-content');
        if (!chartsEl) return;
        
        chartsEl.innerHTML = '<p>Loading charts...</p>';
        
        try {
            const severityImg = `${API_ROOT}/api/chart/severity/${logId}`;
            const timelineImg = `${API_ROOT}/api/chart/timeline/${logId}`;
            
            chartsEl.innerHTML = `
                <div class="chart-container">
                    <h3>Severity Distribution</h3>
                    <img src="${severityImg}" alt="Severity Chart" />
                </div>
                <div class="chart-container">
                    <h3>Incident Timeline</h3>
                    <img src="${timelineImg}" alt="Timeline Chart" />
                </div>
            `;
        } catch (err) {
            console.error('[Charts] Error:', err);
            chartsEl.innerHTML = '<p>Failed to load charts</p>';
        }
    }
    
    // ============================
    // CHAT & Q&A
    // ============================
    
    function bindChatControls() {
        const chatInput = id('chatInput') || $('input[placeholder*="question"]');
        const sendBtn = id('sendBtn') || $('.chat-send-btn');
        
        safeBind(chatInput, 'keypress', (e) => {
            if (e.key === 'Enter') sendChatMessage();
        });
        safeBind(sendBtn, 'click', sendChatMessage);
    }
    
    async function sendChatMessage() {
        if (!currentAnalysisId) {
            alert('Please select an analysis first');
            return;
        }
        
        const chatInput = id('chatInput') || $('input[placeholder*="question"]');
        const question = chatInput.value.trim();
        
        if (!question) return;
        
        // Add user message to chat
        addChatMessage('user', question);
        chatInput.value = '';
        
        try {
            const response = await fetch(`${API_ROOT}/api/chat/${currentAnalysisId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ question })
            });
            
            if (!response.ok) throw new Error(response.statusText);
            
            const data = await response.json();
            addChatMessage('assistant', data.answer);
            
        } catch (err) {
            console.error('[Chat] Error:', err);
            addChatMessage('assistant', '❌ Error processing question');
        }
    }
    
    async function loadChatHistory(logId) {
        try {
            const response = await fetch(`${API_ROOT}/api/chat/${logId}/history`);
            if (!response.ok) throw new Error(response.statusText);
            
            const data = await response.json();
            const chatEl = id('chatMessages') || $('.chat-messages');
            
            if (chatEl) {
                chatEl.innerHTML = '';
                data.messages.forEach(msg => {
                    addChatMessage(msg.role, msg.content);
                });
            }
        } catch (err) {
            console.error('[Chat History] Error:', err);
        }
    }
    
    function addChatMessage(role, content) {
        const chatEl = id('chatMessages') || $('.chat-messages');
        if (!chatEl) return;
        
        const div = el('div', { className: `chat-message ${role}` });
        div.innerHTML = `<strong>${role === 'user' ? 'You' : 'Assistant'}:</strong> ${escapeHtml(content)}`;
        chatEl.appendChild(div);
        chatEl.scrollTop = chatEl.scrollHeight;
    }
    
    // ============================
    // NAVIGATION & TABS
    // ============================
    
    function bindNavigation() {
        $all('[data-tab]').forEach(btn => {
            safeBind(btn, 'click', (e) => {
                switchTab(e.target.dataset.tab);
            });
        });
    }
    
    window.switchTab = (tabName) => {
        // Hide all sections
        $all('[data-section]').forEach(s => s.style.display = 'none');
        
        // Show selected
        const sel = $(`[data-section="${tabName}"]`);
        if (sel) sel.style.display = 'block';
        
        // Update button states
        $all('[data-tab]').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
    };
    
    // ============================
    // REPORTS
    // ============================
    
    window.downloadReport = async () => {
        if (!currentAnalysisId) {
            alert('No analysis selected');
            return;
        }
        
        try {
            const url = `${API_ROOT}/api/report/${currentAnalysisId}`;
            const a = el('a', { href: url, download: `report_${currentAnalysisId}.pdf` });
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        } catch (err) {
            console.error('[Report] Error:', err);
            alert('Failed to download report');
        }
    };
    
    // ============================
    // UTILITIES
    // ============================
    
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    function showNotification(msg, type = 'info') {
        const div = el('div', { 
            className: `notification ${type}`,
            textContent: msg
        });
        document.body.appendChild(div);
        setTimeout(() => document.body.removeChild(div), 3000);
    }
    
    // ============================
    // START
    // ============================
    
    document.addEventListener('DOMContentLoaded', init);
})();