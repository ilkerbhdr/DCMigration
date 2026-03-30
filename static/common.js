/* ============================================================
   PORT MAPPING — Shared JavaScript Utilities
   ============================================================ */

// --- HTML Escape ---
function esc(text) {
    const d = document.createElement('div');
    d.textContent = text || '';
    return d.innerHTML;
}

// --- Profile Loading ---
let _profiles = [];

async function loadProfiles() {
    try {
        const res = await fetch('/migration/api/profiles');
        _profiles = await res.json();
    } catch { _profiles = []; }
    return _profiles;
}

function getProfileOptions(emptyLabel) {
    let opts = `<option value="">${emptyLabel || '-- Profil Sec --'}</option>`;
    _profiles.forEach(p => {
        opts += `<option value="${esc(p.name)}">${esc(p.name)} (${esc(p.username)})</option>`;
    });
    return opts;
}

function updateAllSelects(selector) {
    const opts = getProfileOptions();
    document.querySelectorAll(selector).forEach(sel => {
        const cur = sel.value;
        sel.innerHTML = opts;
        sel.value = cur;
    });
}

// --- Switch Groups ---
let _switchGroups = [];

async function loadSwitchGroups() {
    try {
        const res = await fetch('/migration/api/switch-groups');
        _switchGroups = await res.json();
    } catch { _switchGroups = []; }
    return _switchGroups;
}

function getSwitchGroupOptions() {
    let opts = '<option value="">-- Grup Sec --</option>';
    _switchGroups.forEach(g => {
        const count = g.switches ? g.switches.length : 0;
        const ips = g.switches ? g.switches.map(s => s.host).join(', ') : '';
        opts += `<option value="${esc(g.name)}" title="${esc(ips)}">${esc(g.name)} (${count} giri\u015f)</option>`;
    });
    return opts;
}

function getSwitchGroupByName(name) {
    return _switchGroups.find(g => g.name === name) || null;
}

// --- Switch Color Palette ---
const SW_COLORS = ['#3b82f6','#8b5cf6','#06b6d4','#10b981','#f59e0b','#ef4444','#6366f1','#14b8a6','#eab308','#ec4899'];
const _swColorMap = {};
let _swColorIdx = 0;

function getSwColor(host) {
    if (!_swColorMap[host]) {
        _swColorMap[host] = SW_COLORS[_swColorIdx % SW_COLORS.length];
        _swColorIdx++;
    }
    return _swColorMap[host];
}

// --- Audio Beep ---
let _audioCtx;
function playBeep() {
    if (!_audioCtx) _audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = _audioCtx.createOscillator();
    const gain = _audioCtx.createGain();
    osc.connect(gain);
    gain.connect(_audioCtx.destination);
    osc.frequency.value = 700;
    gain.gain.value = 0.2;
    osc.start();
    osc.stop(_audioCtx.currentTime + 0.12);
}

// --- Topbar HTML ---
function renderTopbar(activePage) {
    const pages = [
        { id: 'dashboard', label: 'Dashboard', href: '/migration/dashboard' },
        { id: 'collect', label: 'Port Mapping', href: '/migration/port-mapping' },
        { id: 'live', label: 'Live Table', href: '/migration/live' },
        { id: 'monitor', label: 'Monitor', href: '/migration/monitor' },
        { id: 'topology', label: 'Topology', href: '/migration/topology' },
        { id: 'sfp', label: 'SFP Check', href: '/migration/sfp' },
    ];

    const nav = pages.map(p =>
        `<a href="${p.href}" class="${p.id === activePage ? 'active' : ''}">${p.label}</a>`
    ).join('');

    return `
    <nav class="topbar">
        <a class="topbar-brand" href="/migration/dashboard">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>
                <circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/>
            </svg>
            Port Mapping <span>|</span> DC Migration
        </a>
        <div class="topbar-nav">${nav}</div>
        <div class="topbar-right" id="topbarRight"></div>
    </nav>`;
}
