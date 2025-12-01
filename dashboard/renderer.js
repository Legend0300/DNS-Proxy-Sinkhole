const API_BASE = 'http://localhost:8080';

// State
let currentTab = 'dashboard';

// DOM Elements
const statusDot = document.getElementById('connection-status');
const statusText = document.getElementById('status-text');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    refreshAll();
    setInterval(checkStatus, 5000); // Check connection every 5s
});

function showTab(tabName) {
    // Update Sidebar
    document.querySelectorAll('.sidebar li').forEach(el => el.classList.remove('active'));
    document.getElementById(`nav-${tabName}`).classList.add('active');

    // Update Content
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.getElementById(`tab-${tabName}`).classList.add('active');

    currentTab = tabName;
    refreshAll();
}

async function checkStatus() {
    try {
        await fetch(`${API_BASE}/stats`);
        statusDot.className = 'status-dot connected';
        statusText.textContent = 'Connected';
        return true;
    } catch (e) {
        statusDot.className = 'status-dot disconnected';
        statusText.textContent = 'Disconnected';
        return false;
    }
}

async function refreshAll() {
    const isConnected = await checkStatus();
    if (!isConnected) return;

    if (currentTab === 'dashboard') {
        updateStats();
        updateMode();
    } else if (currentTab === 'blacklist') {
        updateList('blacklist');
    } else if (currentTab === 'whitelist') {
        updateList('whitelist');
    } else if (currentTab === 'adapters') {
        loadAdapters();
    }
}

async function updateMode() {
    try {
        const res = await fetch(`${API_BASE}/mode`);
        const data = await res.json();
        const isWhitelist = data.mode === 'whitelist';
        
        document.getElementById('mode-toggle').checked = isWhitelist;
        
        document.getElementById('mode-label-blacklist').classList.toggle('active', !isWhitelist);
        document.getElementById('mode-label-whitelist').classList.toggle('active', isWhitelist);
        
        document.getElementById('mode-desc-text').textContent = isWhitelist 
            ? "Allowing ONLY domains in the whitelist. All others blocked." 
            : "Blocking domains in the blacklist. All others allowed.";
            
    } catch (e) {
        console.error('Failed to fetch mode', e);
    }
}

async function toggleMode() {
    const isChecked = document.getElementById('mode-toggle').checked;
    const newMode = isChecked ? 'whitelist' : 'blacklist';
    
    try {
        const res = await fetch(`${API_BASE}/mode`, {
            method: 'POST',
            body: newMode
        });
        
        if (res.ok) {
            updateMode();
            showToast(`Switched to ${newMode} mode`);
        } else {
            showToast('Failed to switch mode', true);
            // Revert toggle
            document.getElementById('mode-toggle').checked = !isChecked;
        }
    } catch (e) {
        console.error('Error switching mode', e);
        showToast('Error switching mode', true);
        document.getElementById('mode-toggle').checked = !isChecked;
    }
}

async function flushDns() {
    try {
        const res = await fetch(`${API_BASE}/flushdns`, { method: 'POST' });
        if (res.ok) {
            showToast('System DNS Cache Flushed');
        } else {
            showToast('Failed to flush DNS', true);
        }
    } catch (e) {
        showToast('Error flushing DNS', true);
    }
}

async function updateStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const data = await res.json();
        document.getElementById('stat-blacklist').textContent = data.blacklist_count;
        document.getElementById('stat-whitelist').textContent = data.whitelist_count;
    } catch (e) {
        console.error('Failed to fetch stats', e);
    }
}

async function updateList(type) {
    try {
        const res = await fetch(`${API_BASE}/${type}`);
        const list = await res.json();
        const ul = document.getElementById(`${type}-list`);
        ul.innerHTML = '';

        list.forEach(domain => {
            const li = document.createElement('li');
            li.innerHTML = `
                <span>${domain}</span>
                <button class="delete-btn" onclick="deleteDomain('${type}', '${domain}')">Delete</button>
            `;
            ul.appendChild(li);
        });
    } catch (e) {
        console.error(`Failed to fetch ${type}`, e);
    }
}

async function addDomain(type) {
    const input = document.getElementById(`${type}-input`);
    const domain = input.value.trim();
    
    if (!domain) return;

    try {
        const res = await fetch(`${API_BASE}/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });

        if (res.ok) {
            input.value = '';
            updateList(type);
            showToast('Domain added successfully');
        } else {
            showToast('Failed to add domain', true);
        }
    } catch (e) {
        console.error('Error adding domain', e);
        showToast('Error adding domain', true);
    }
}

async function deleteDomain(type, domain) {
    if (!confirm(`Are you sure you want to remove ${domain}?`)) return;

    try {
        const res = await fetch(`${API_BASE}/${type}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });

        if (res.ok) {
            updateList(type);
            showToast('Domain removed successfully');
        } else {
            showToast('Failed to delete domain', true);
        }
    } catch (e) {
        console.error('Error deleting domain', e);
        showToast('Error deleting domain', true);
    }
}

// Bulk Operations
let currentBulkType = '';

function openBulkModal(type) {
    currentBulkType = type;
    document.getElementById('bulk-modal').style.display = 'block';
    document.getElementById('bulk-textarea').value = '';
    document.getElementById('bulk-textarea').focus();
}

function closeBulkModal() {
    document.getElementById('bulk-modal').style.display = 'none';
}

async function submitBulk() {
    const text = document.getElementById('bulk-textarea').value;
    if (!text.trim()) return;

    // Split by newlines or commas
    const domains = text.split(/[\n,]+/).map(d => d.trim()).filter(d => d);
    
    if (domains.length === 0) return;

    try {
        const res = await fetch(`${API_BASE}/${currentBulkType}/bulk`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(domains) // Send as array directly
        });

        if (res.ok) {
            const data = await res.json();
            closeBulkModal();
            updateList(currentBulkType);
            showToast(`Added ${data.count} domains`);
        } else {
            showToast('Failed to add domains', true);
        }
    } catch (e) {
        console.error('Error bulk adding', e);
        showToast('Error bulk adding', true);
    }
}

async function clearAll(type) {
    if (!confirm(`Are you sure you want to clear the entire ${type}? This cannot be undone.`)) return;

    try {
        const res = await fetch(`${API_BASE}/${type}/all`, {
            method: 'DELETE'
        });

        if (res.ok) {
            updateList(type);
            showToast(`${type} cleared successfully`);
        } else {
            showToast('Failed to clear list', true);
        }
    } catch (e) {
        console.error('Error clearing list', e);
        showToast('Error clearing list', true);
    }
}

async function reloadRules() {
    try {
        const res = await fetch(`${API_BASE}/reload`, { method: 'POST' });
        if (res.ok) {
            refreshAll();
            showToast('Rules reloaded from disk');
        } else {
            showToast('Failed to reload rules', true);
        }
    } catch (e) {
        showToast('Error reloading rules', true);
    }
}

function showToast(message, isError = false) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.style.backgroundColor = isError ? '#e74c3c' : '#333';
    toast.className = 'toast show';
    setTimeout(() => { toast.className = toast.className.replace('show', ''); }, 3000);
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('bulk-modal');
    if (event.target == modal) {
        closeBulkModal();
    }
}

async function loadAdapters() {
    try {
        const res = await fetch(`${API_BASE}/adapters`);
        if (!res.ok) throw new Error('Failed to fetch adapters');
        const adapters = await res.json();
        
        const tbody = document.getElementById('adapters-list');
        tbody.innerHTML = '';
        
        adapters.forEach(adapter => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid #333';
            
            const statusColor = adapter.isUp ? '#4caf50' : '#f44336';
            
            tr.innerHTML = `
                <td style="padding: 10px;">${adapter.alias}</td>
                <td style="padding: 10px;">${adapter.description}</td>
                <td style="padding: 10px;"><span style="color: ${statusColor};">●</span> ${adapter.isUp ? 'Up' : 'Down'}</td>
                <td style="padding: 10px; font-family: monospace;">${adapter.dnsServers || '-'}</td>
                <td style="padding: 10px;">
                    <button class="btn-small" onclick="setAdapterDns('${adapter.alias}')" style="margin-right: 5px; background-color: #2196F3; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px;">Set DNS</button>
                    <button class="btn-small" onclick="resetAdapterDns('${adapter.alias}')" style="background-color: #FF9800; color: white; border: none; padding: 5px 10px; cursor: pointer; border-radius: 3px;">Reset DHCP</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Error loading adapters', e);
        showToast('Failed to load adapters', true);
    }
}

async function setAdapterDns(alias) {
    if (!confirm(`Set DNS to 127.0.0.1 for "${alias}"?`)) return;
    
    try {
        const res = await fetch(`${API_BASE}/adapters/dns`, {
            method: 'POST',
            body: JSON.stringify({ adapter: alias, action: 'set_localhost' })
        });
        
        if (res.ok) {
            showToast(`DNS set for ${alias}`);
        } else {
            showToast('Failed to set DNS', true);
        }
    } catch (e) {
        console.error('Error setting DNS', e);
        showToast('Error setting DNS', true);
    }
}

async function resetAdapterDns(alias) {
    if (!confirm(`Reset DNS to DHCP for "${alias}"?`)) return;
    
    try {
        const res = await fetch(`${API_BASE}/adapters/dns`, {
            method: 'POST',
            body: JSON.stringify({ adapter: alias, action: 'reset_dhcp' })
        });
        
        if (res.ok) {
            showToast(`DNS reset for ${alias}`);
        } else {
            showToast('Failed to reset DNS', true);
        }
    } catch (e) {
        console.error('Error resetting DNS', e);
        showToast('Error resetting DNS', true);
    }
}

async function autoDetectAdapters() {
    try {
        const res = await fetch(`${API_BASE}/adapters`);
        if (!res.ok) throw new Error('Failed to fetch adapters');
        const adapters = await res.json();
        
        const candidates = adapters.filter(a => 
            /ethernet|wi-?fi/i.test(a.alias) || /ethernet|wi-?fi/i.test(a.description)
        );
        
        if (candidates.length === 0) {
            alert('No Ethernet or Wi-Fi adapters detected.');
            return;
        }
        
        const names = candidates.map(c => c.alias).join(', ');
        if (confirm(`Detected adapters: ${names}.\n\nApply DNS settings to these adapters?`)) {
            for (const c of candidates) {
                await setAdapterDns(c.alias);
            }
        }
    } catch (e) {
        console.error('Error auto-detecting', e);
        showToast('Error auto-detecting adapters', true);
    }
}
