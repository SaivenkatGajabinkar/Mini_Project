/**
 * CyberShield — Frontend Application
 *
 * Handles all dashboard interactions:
 * - File upload (drag & drop or click to browse)
 * - Sending the PCAP file to the backend API for analysis
 * - Displaying results (risk score, suspicious IPs, flow table)
 * - Capture history and detailed result views
 * - Simulated IP blocking (demonstration only)
 * - HTML report download
 *
 * All communication is through /api/* endpoints.
 * All user-supplied values are HTML-escaped before DOM insertion (XSS prevention).
 */

// ============================================================
// Utility: HTML Escaping (prevents XSS)
// ============================================================
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const str = String(text);
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// ============================================================
// Toast Notifications
// ============================================================
function showToast(title, message, type = 'info', duration = 5000) {
    const container = document.getElementById('toastContainer');
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <div class="toast-body">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ============================================================
// Loading Overlay
// ============================================================
function showLoading(show = true) {
    const overlay = document.getElementById('loadingOverlay');
    if (show) {
        overlay.classList.add('active');
    } else {
        overlay.classList.remove('active');
    }
}

// ============================================================
// Navigation
// ============================================================
let currentPage = 'overview';
let currentResult = null;

function navigateTo(page) {
    // Hide all pages
    document.querySelectorAll('.page-section').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

    // Show selected page
    const pageEl = document.getElementById(`page-${page}`);
    const navEl = document.getElementById(`nav-${page}`);

    if (pageEl) pageEl.classList.add('active');
    if (navEl) navEl.classList.add('active');

    currentPage = page;

    // Load page-specific data from API
    switch (page) {
        case 'overview':
            loadOverview();
            break;
        case 'history':
            loadHistory();
            break;
        case 'blocked':
            loadBlocked();
            break;
    }

    // Close mobile sidebar
    document.getElementById('sidebar').classList.remove('open');
}

// Setup navigation click handlers
document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', () => {
        navigateTo(item.dataset.page);
    });
});

// Mobile toggle
document.getElementById('mobileToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
});

// ============================================================
// API Calls — All communication with the FastAPI backend
// ============================================================
const API = {
    async health() {
        const res = await fetch('/api/health');
        return res.json();
    },

    async analyze(file) {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/analyze', { method: 'POST', body: formData });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Analysis failed');
        }
        return res.json();
    },

    async captures() {
        const res = await fetch('/api/captures');
        return res.json();
    },

    async capture(id) {
        const res = await fetch(`/api/captures/${encodeURIComponent(id)}`);
        if (!res.ok) throw new Error('Capture not found');
        return res.json();
    },

    async blockIp(ip, captureId) {
        const res = await fetch('/api/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, capture_id: captureId })
        });
        return res.json();
    },

    async blockedList() {
        const res = await fetch('/api/blocked');
        return res.json();
    },

    async unblock(id) {
        const res = await fetch(`/api/blocked/${id}`, { method: 'DELETE' });
        return res.json();
    }
};

// ============================================================
// Overview Page — Dashboard statistics
// ============================================================
async function loadOverview() {
    try {
        // Load health info for system status and model metrics
        const health = await API.health();
        updateSystemStatus(health.model_loaded);
        updateModelInfo(health);

        // Load captures for dashboard stats
        const data = await API.captures();
        const captures = data.captures || [];

        const totalCaptures = captures.length;
        const attackCaptures = captures.filter(c => c.status === 'ATTACK').length;
        const normalCaptures = captures.filter(c => c.status === 'NORMAL').length;

        animateCounter('stat-total-captures', totalCaptures);
        animateCounter('stat-attack-captures', attackCaptures);
        animateCounter('stat-normal-captures', normalCaptures);

        // Load blocked count
        const blocked = await API.blockedList();
        animateCounter('stat-blocked-ips', (blocked.blocks || []).length);

        // Show latest result card if there are any captures
        if (captures.length > 0) {
            const latest = captures[0];
            showLatestResult(latest);
        } else {
            document.getElementById('latestResultCard').style.display = 'none';
        }

    } catch (err) {
        console.error('Failed to load overview:', err);
        updateSystemStatus(false);
    }
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    const duration = 800;
    const startTime = performance.now();

    function update(time) {
        const elapsed = time - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (target - start) * eased);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function updateSystemStatus(modelLoaded) {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('systemStatusText');
    const hdrText = document.getElementById('headerStatusText');

    if (modelLoaded) {
        dot.className = 'status-dot';
        text.textContent = 'System Operational';
        if (hdrText) hdrText.textContent = 'System Operational';
    } else {
        dot.className = 'status-dot error';
        text.textContent = 'Model Not Loaded';
        if (hdrText) hdrText.textContent = 'Model Missing';
    }
}

function updateModelInfo(health) {
    const container = document.getElementById('modelInfo');
    const metrics = health.metrics || {};

    container.innerHTML = `
        <div class="model-info-grid">
            <div class="model-info-item">
                <div class="model-info-label">Model Type</div>
                <div class="model-info-value text-blue" style="font-size: 14px;">Random Forest</div>
            </div>
            <div class="model-info-item">
                <div class="model-info-label">Version</div>
                <div class="model-info-value text-cyan" style="font-size: 12px;">${escapeHtml(health.model_version || 'N/A')}</div>
            </div>
            <div class="model-info-item">
                <div class="model-info-label">Accuracy</div>
                <div class="model-info-value text-cyan">${metrics.accuracy ? (metrics.accuracy * 100).toFixed(1) + '%' : 'N/A'}</div>
            </div>
            <div class="model-info-item">
                <div class="model-info-label">Attack Recall</div>
                <div class="model-info-value text-green">${metrics.recall_attack ? (metrics.recall_attack * 100).toFixed(1) + '%' : 'N/A'}</div>
            </div>
            <div class="model-info-item">
                <div class="model-info-label">Attack F1</div>
                <div class="model-info-value text-purple">${metrics.f1_attack ? (metrics.f1_attack * 100).toFixed(1) + '%' : 'N/A'}</div>
            </div>
            <div class="model-info-item">
                <div class="model-info-label">ROC-AUC</div>
                <div class="model-info-value text-amber">${metrics.roc_auc ? (metrics.roc_auc * 100).toFixed(1) + '%' : 'N/A'}</div>
            </div>
        </div>`;
}

function showLatestResult(capture) {
    const card = document.getElementById('latestResultCard');
    const content = document.getElementById('latestResultContent');
    card.style.display = 'block';

    const statusClass = capture.status === 'ATTACK' ? 'badge-attack' : 'badge-normal';
    const riskClass = `badge-${(capture.risk_level || 'low').toLowerCase()}`;

    content.innerHTML = `
        <div class="flex items-center gap-md flex-wrap mb-md">
            <span class="badge ${statusClass}">${escapeHtml(capture.status)}</span>
            <span class="badge ${riskClass}">${escapeHtml(capture.risk_level)} RISK</span>
            <span class="text-mono" style="font-size: 13px; color: var(--text-muted);">${escapeHtml(capture.original_name)}</span>
            <span class="text-mono" style="font-size: 12px; color: var(--text-dim);">${escapeHtml(formatDate(capture.uploaded_at))}</span>
        </div>
        <div class="latest-result-summary">
            <div class="latest-stat">
                <div class="latest-stat-value">${capture.risk_score || 0}</div>
                <div class="latest-stat-label">Risk Score</div>
            </div>
            <div class="latest-stat">
                <div class="latest-stat-value">${(capture.total_flows || 0).toLocaleString()}</div>
                <div class="latest-stat-label">Total Flows</div>
            </div>
            <div class="latest-stat">
                <div class="latest-stat-value text-red">${(capture.attack_flows || 0).toLocaleString()}</div>
                <div class="latest-stat-label">Attack Flows</div>
            </div>
            <div class="latest-stat">
                <div class="latest-stat-value text-green">${(capture.normal_flows || 0).toLocaleString()}</div>
                <div class="latest-stat-label">Normal Flows</div>
            </div>
        </div>`;

    document.getElementById('viewLatestBtn').onclick = () => {
        loadCaptureResult(capture.id);
    };
}

// ============================================================
// Upload & Analysis
// ============================================================
let selectedFile = null;

const uploadZone = document.getElementById('uploadZone');
const fileInput = document.getElementById('fileInput');
const selectedFileInfo = document.getElementById('selectedFileInfo');

// Click to browse
uploadZone.addEventListener('click', () => fileInput.click());

// Drag & Drop
uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('drag-over');
});

uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('drag-over');
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length > 0) selectFile(files[0]);
});

// File input change
fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) selectFile(fileInput.files[0]);
});

function selectFile(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['pcapng', 'pcap'].includes(ext)) {
        showToast('Invalid File', 'Please select a .pcapng or .pcap file', 'error');
        return;
    }

    if (file.size > 50 * 1024 * 1024) {
        showToast('File Too Large', 'Maximum file size is 50 MB', 'error');
        return;
    }

    selectedFile = file;
    document.getElementById('selectedFileName').textContent = file.name;
    document.getElementById('selectedFileSize').textContent = formatFileSize(file.size);
    selectedFileInfo.classList.remove('hidden');
}

document.getElementById('clearFileBtn').addEventListener('click', () => {
    selectedFile = null;
    fileInput.value = '';
    selectedFileInfo.classList.add('hidden');
});

document.getElementById('analyzeBtn').addEventListener('click', async () => {
    if (!selectedFile) {
        showToast('No File', 'Please select a file first', 'warning');
        return;
    }

    showLoading(true);

    try {
        const result = await API.analyze(selectedFile);
        currentResult = result;

        showLoading(false);
        showToast('Analysis Complete', `Status: ${result.status} | Risk: ${result.risk_level}`,
            result.status === 'ATTACK' ? 'warning' : 'success');

        // Clear selection
        selectedFile = null;
        fileInput.value = '';
        selectedFileInfo.classList.add('hidden');

        // Show result page
        displayResult(result);
        document.getElementById('nav-result').style.display = '';
        navigateTo('result');

    } catch (err) {
        showLoading(false);
        showToast('Analysis Failed', err.message, 'error');
    }
});

// ============================================================
// Result Display
// ============================================================
function displayResult(result) {
    currentResult = result;
    const cid = result.capture_id || result.id;

    // Header metadata
    document.getElementById('resultFilename').textContent = result.filename || result.original_name || '';
    document.getElementById('resultCaptureId').textContent = cid || '';
    document.getElementById('resultAnalyzedAt').textContent = formatDate(result.analysed_at || result.uploaded_at);

    // Status badge
    const badge = document.getElementById('resultStatusBadge');
    badge.textContent = result.status;
    badge.className = `result-status-badge badge ${result.status === 'ATTACK' ? 'badge-attack' : 'badge-normal'}`;

    // Download report link
    document.getElementById('downloadReportBtn').href = `/api/captures/${encodeURIComponent(cid)}/report`;

    // Risk meter animation
    updateRiskMeter(result.risk_score, result.risk_level);

    // Flow summary
    document.getElementById('resultTotalFlows').textContent = (result.total_flows || 0).toLocaleString();
    document.getElementById('resultAttackFlows').textContent = (result.attack_flows || 0).toLocaleString();
    document.getElementById('resultNormalFlows').textContent = (result.normal_flows || 0).toLocaleString();
    document.getElementById('resultAttackRatio').textContent = ((result.attack_ratio || 0) * 100).toFixed(1) + '%';

    // Render sub-components
    renderProtocolChart(result.protocol_breakdown || {});
    renderSuspiciousIps(result.suspicious_ips || [], cid);
    renderSuspiciousFlows(result.top_suspicious_flows || [], cid);
}

function updateRiskMeter(score, level) {
    const circumference = 2 * Math.PI * 85; // ~534
    const fill = document.getElementById('riskMeterFill');
    const valueEl = document.getElementById('riskScoreValue');
    const labelEl = document.getElementById('riskLevelLabel');

    // Animate the circular fill
    const offset = circumference - (score / 100) * circumference;
    fill.style.strokeDashoffset = offset;

    // Color the meter based on risk level
    const colors = {
        LOW: '#22C55E',
        MEDIUM: '#F59E0B',
        HIGH: '#EF4444'
    };
    const color = colors[level] || colors.LOW;
    fill.style.stroke = color;
    valueEl.style.color = color;

    // Animate counter from current value to target score
    const duration = 1200;
    const startTime = performance.now();
    const startVal = parseInt(valueEl.textContent) || 0;

    function update(time) {
        const elapsed = time - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        valueEl.textContent = Math.round(startVal + (score - startVal) * eased);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);

    labelEl.textContent = level;
    labelEl.style.color = color;
}

function renderProtocolChart(breakdown) {
    const container = document.getElementById('protocolChart');
    const entries = Object.entries(breakdown);

    if (entries.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No protocol data</div></div>';
        return;
    }

    const maxVal = Math.max(...entries.map(e => e[1]));
    const colors = ['cyan', 'green', 'orange', 'red', 'purple'];

    container.innerHTML = entries.map(([proto, count], i) => {
        const pct = maxVal > 0 ? (count / maxVal * 100) : 0;
        const color = colors[i % colors.length];
        return `
            <div class="bar-item">
                <span class="bar-label">${escapeHtml(proto)}</span>
                <div class="bar-track">
                    <div class="bar-fill ${color}" style="width: 0%;" data-width="${pct}%"></div>
                </div>
                <span class="bar-value">${count.toLocaleString()}</span>
            </div>`;
    }).join('');

    // Animate bars after render
    requestAnimationFrame(() => {
        container.querySelectorAll('.bar-fill').forEach(bar => {
            bar.style.width = bar.dataset.width;
        });
    });
}

function renderSuspiciousIps(ips, captureId) {
    const container = document.getElementById('suspiciousIpsContent');

    if (ips.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-state-text text-green">✅ No suspicious IPs detected</div></div>';
        return;
    }

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Attack Flows</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                ${ips.map(ip => `
                    <tr>
                        <td style="font-weight: 600; color: var(--text-primary);">${escapeHtml(ip.ip)}</td>
                        <td class="text-red">${ip.attack_flows}</td>
                        <td>
                            <button class="btn btn-danger btn-sm"
                                    onclick="blockIp('${escapeHtml(ip.ip)}', '${escapeHtml(captureId)}')">
                                🚫 Block (Simulated)
                            </button>
                        </td>
                    </tr>`).join('')}
            </tbody>
        </table>`;
}

function renderSuspiciousFlows(flows, captureId) {
    const tbody = document.getElementById('suspiciousFlowsBody');

    if (flows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No suspicious flows</td></tr>';
        return;
    }

    tbody.innerHTML = flows.map(flow => {
        const probPct = (flow.attack_probability * 100).toFixed(1);
        const probColor = flow.attack_probability > 0.8 ? 'text-red' :
                          flow.attack_probability > 0.5 ? 'text-amber' : 'text-green';
        const labelClass = flow.label === 'Attack' ? 'badge-attack' : 'badge-normal';

        return `
            <tr>
                <td class="text-mono">${escapeHtml(flow.src_ip)}</td>
                <td class="text-mono">${escapeHtml(flow.dst_ip)}</td>
                <td class="text-mono">${flow.src_port}</td>
                <td class="text-mono">${flow.dst_port}</td>
                <td>${escapeHtml(flow.protocol)}</td>
                <td class="${probColor}" style="font-weight: 600;">${probPct}%</td>
                <td><span class="badge ${labelClass}">${escapeHtml(flow.label)}</span></td>
                <td>
                    ${flow.label === 'Attack' ? `
                        <button class="btn btn-danger btn-sm"
                                onclick="blockIp('${escapeHtml(flow.src_ip)}', '${escapeHtml(captureId)}')">
                            🚫 Block
                        </button>` : ''}
                </td>
            </tr>`;
    }).join('');
}

// ============================================================
// History Page
// ============================================================
async function loadHistory() {
    try {
        const data = await API.captures();
        const captures = data.captures || [];

        const tbody = document.getElementById('historyBody');
        const empty = document.getElementById('historyEmpty');

        if (captures.length === 0) {
            tbody.innerHTML = '';
            empty.style.display = '';
            return;
        }

        empty.style.display = 'none';
        tbody.innerHTML = captures.map(c => {
            const statusClass = c.status === 'ATTACK' ? 'badge-attack' : 'badge-normal';
            const riskClass = `badge-${(c.risk_level || 'low').toLowerCase()}`;
            return `
                <tr class="clickable" onclick="loadCaptureResult('${escapeHtml(c.id)}')">
                    <td class="text-mono" style="white-space: nowrap;">${escapeHtml(formatDate(c.uploaded_at))}</td>
                    <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(c.original_name)}</td>
                    <td><span class="badge ${statusClass}">${escapeHtml(c.status)}</span></td>
                    <td><span class="badge ${riskClass}">${escapeHtml(c.risk_level)}</span></td>
                    <td class="text-mono">${c.risk_score || 0}</td>
                    <td class="text-mono">${(c.total_flows || 0).toLocaleString()}</td>
                    <td class="text-mono text-red">${(c.attack_flows || 0).toLocaleString()}</td>
                    <td><button class="btn btn-ghost btn-sm">View →</button></td>
                </tr>`;
        }).join('');

    } catch (err) {
        showToast('Error', 'Failed to load history', 'error');
    }
}

async function loadCaptureResult(captureId) {
    try {
        const result = await API.capture(captureId);
        displayResult(result);
        document.getElementById('nav-result').style.display = '';
        navigateTo('result');
    } catch (err) {
        showToast('Error', 'Failed to load capture details', 'error');
    }
}

// ============================================================
// Blocked IPs Page
// ============================================================
async function loadBlocked() {
    try {
        const data = await API.blockedList();
        const blocks = data.blocks || [];

        const listEl = document.getElementById('blockedList');
        const emptyEl = document.getElementById('blockedEmpty');

        if (blocks.length === 0) {
            listEl.innerHTML = '';
            emptyEl.style.display = '';
            return;
        }

        emptyEl.style.display = 'none';
        listEl.innerHTML = blocks.map(b => `
            <div class="blocked-ip-card">
                <div class="blocked-ip-info">
                    <span style="font-size: 24px;">🚫</span>
                    <div>
                        <div class="blocked-ip-address">${escapeHtml(b.ip)}</div>
                        <div class="blocked-ip-meta">Blocked at ${escapeHtml(formatDate(b.blocked_at))}</div>
                    </div>
                    <span class="simulated-tag">SIMULATED</span>
                </div>
                <button class="btn btn-ghost btn-sm" onclick="unblockIp(${b.id})">Remove</button>
            </div>
        `).join('');

    } catch (err) {
        showToast('Error', 'Failed to load blocked IPs', 'error');
    }
}

async function blockIp(ip, captureId) {
    try {
        await API.blockIp(ip, captureId);
        showToast('IP Blocked (Simulated)',
            `${ip} has been blocked. This is a simulation — no network changes were made.`,
            'warning');
        if (currentPage === 'blocked') loadBlocked();
        loadOverview();
    } catch (err) {
        showToast('Error', 'Failed to block IP', 'error');
    }
}

async function unblockIp(blockId) {
    try {
        await API.unblock(blockId);
        showToast('Block Removed', 'Simulated block has been removed', 'success');
        loadBlocked();
    } catch (err) {
        showToast('Error', 'Failed to remove block', 'error');
    }
}

// ============================================================
// Helpers
// ============================================================
function formatDate(isoString) {
    if (!isoString) return 'N/A';
    try {
        const d = new Date(isoString);
        return d.toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch {
        return isoString;
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ============================================================
// Initialization
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    navigateTo('overview');
});
