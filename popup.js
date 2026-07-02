/**
 * Popup Script for PayTrace Extension
 * Handles dashboard UI and user interactions
 */

// DOM Elements
const elements = {
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  domainValue: document.getElementById('domainValue'),
  httpsValue: document.getElementById('httpsValue'),
  paymentPageValue: document.getElementById('paymentPageValue'),
  riskScore: document.getElementById('riskScore'),
  levelBadge: document.getElementById('levelBadge'),
  riskFactors: document.getElementById('riskFactors'),
  requestCount: document.getElementById('requestCount'),
  thirdPartyCount: document.getElementById('thirdPartyCount'),
  domainsList: document.getElementById('domainsList'),
  hiddenIframes: document.getElementById('hiddenIframes'),
  dynamicScripts: document.getElementById('dynamicScripts'),
  domChanges: document.getElementById('domChanges'),
  focusChanges: document.getElementById('focusChanges'),
  tabSwitches: document.getElementById('tabSwitches'),
  liveEvents: document.getElementById('liveEvents'),
  refreshBtn: document.getElementById('refreshBtn'),
  exportBtn: document.getElementById('exportBtn'),
  resetBtn: document.getElementById('resetBtn'),
  loadingOverlay: document.getElementById('loadingOverlay')
};

// Current monitoring data
let currentData = null;
let refreshInterval = null;

/**
 * Initialize popup
 */
function initializePopup() {
  showLoading(true);
  
  // Load initial data
  loadMonitoringData();
  
  // Set up event listeners
  setupEventListeners();
  
  // Start auto-refresh
  startAutoRefresh();
}

/**
 * Show/hide loading overlay
 */
function showLoading(show) {
  if (show) {
    elements.loadingOverlay.classList.add('active');
  } else {
    elements.loadingOverlay.classList.remove('active');
  }
}

/**
 * Load monitoring data from content script
 */
async function loadMonitoringData() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      showError('No active tab found');
      showLoading(false);
      return;
    }
    
    const response = await chrome.tabs.sendMessage(tab.id, { 
      action: 'getMonitoringData' 
    });
    
    if (response && chrome.runtime.lastError) {
      showError('Extension not active on this page');
      showLoading(false);
      return;
    }
    
    if (response) {
      currentData = response;
      updateUI(response);
    } else {
      showError('No monitoring data available');
    }
  } catch (error) {
    console.error('[PayTrace] Error loading data:', error);
    showError('Failed to load monitoring data');
  }
  
  showLoading(false);
}

/**
 * Update UI with monitoring data
 */
function updateUI(data) {
  // Update status
  updateStatus(data.isActive, data.isPaymentPage);
  
  // Update site info
  elements.domainValue.textContent = data.domain || '--';
  elements.httpsValue.textContent = data.https ? 'Secure' : 'Insecure';
  elements.httpsValue.className = 'info-value ' + (data.https ? 'secure' : 'insecure');
  elements.paymentPageValue.textContent = data.isPaymentPage ? 'Yes' : 'No';
  
  // Update risk assessment
  updateRiskAssessment(data.risk);
  
  // Update network stats
  elements.requestCount.textContent = data.network?.requestCount || 0;
  elements.thirdPartyCount.textContent = data.network?.thirdPartyDomains?.length || 0;
  updateDomainsList(data.network?.thirdPartyDomains || []);
  
  // Update DOM stats
  elements.hiddenIframes.textContent = data.dom?.hiddenIframes || 0;
  elements.dynamicScripts.textContent = data.dom?.dynamicScripts || 0;
  elements.domChanges.textContent = data.dom?.domChanges || 0;
  
  // Update behavior stats
  elements.focusChanges.textContent = data.behavior?.focusChanges || 0;
  elements.tabSwitches.textContent = data.behavior?.tabSwitches || 0;
  
  // Update live events counter
  updateLiveEvents(data);
}

/**
 * Update status indicator
 */
function updateStatus(isActive, isPaymentPage) {
  if (isActive && isPaymentPage) {
    elements.statusDot.className = 'status-dot active';
    elements.statusText.textContent = 'Monitoring';
  } else if (isPaymentPage) {
    elements.statusDot.className = 'status-dot';
    elements.statusText.textContent = 'Ready';
  } else {
    elements.statusDot.className = 'status-dot inactive';
    elements.statusText.textContent = 'Inactive';
  }
}

/**
 * Update risk assessment display
 */
function updateRiskAssessment(risk) {
  if (!risk) return;
  
  // Update score
  elements.riskScore.textContent = risk.score || 0;
  
  // Update level badge
  const level = risk.level || 'Low';
  elements.levelBadge.textContent = level;
  elements.levelBadge.className = 'level-badge ' + level.toLowerCase();
  
  // Update risk factors
  if (risk.factors && risk.factors.length > 0) {
    elements.riskFactors.innerHTML = risk.factors
      .map(factor => `<div class="risk-factor">${factor.factor} (+${factor.weight})</div>`)
      .join('');
  } else {
    elements.riskFactors.innerHTML = '<p class="no-factors">No risk factors detected</p>';
  }
}

/**
 * Update domains list
 */
function updateDomainsList(domains) {
  if (domains && domains.length > 0) {
    elements.domainsList.innerHTML = domains
      .map(domain => `<div class="domain-item">${domain}</div>`)
      .join('');
  } else {
    elements.domainsList.innerHTML = '<p class="no-domains">No third-party domains detected</p>';
  }
}

/**
 * Update live events counter
 */
function updateLiveEvents(data) {
  const totalEvents = 
    (data.network?.requestCount || 0) +
    (data.dom?.domChanges || 0) +
    (data.behavior?.focusChanges || 0) +
    (data.behavior?.tabSwitches || 0);
  
  elements.liveEvents.textContent = totalEvents;
}

/**
 * Show error message
 */
function showError(message) {
  elements.domainValue.textContent = 'Error';
  elements.statusText.textContent = 'Error';
  console.error('[PayTrace]', message);
}

/**
 * Set up event listeners
 */
function setupEventListeners() {
  // Refresh button
  elements.refreshBtn.addEventListener('click', () => {
    showLoading(true);
    loadMonitoringData();
  });
  
  // Export button
  elements.exportBtn.addEventListener('click', exportReport);
  
  // Reset button
  elements.resetBtn.addEventListener('click', resetMonitoring);
}

/**
 * Start auto-refresh (every 2 seconds)
 */
function startAutoRefresh() {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
  
  refreshInterval = setInterval(() => {
    if (!document.hidden) {
      loadMonitoringData();
    }
  }, 2000);
}

/**
 * Stop auto-refresh
 */
function stopAutoRefresh() {
  if (refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
  }
}

/**
 * Export report as JSON
 */
async function exportReport() {
  try {
    if (!currentData) {
      alert('No data to export');
      return;
    }
    
    // Generate report
    const report = {
      timestamp: new Date().toISOString(),
      website: currentData.website,
      domain: currentData.domain,
      https: currentData.https,
      network: {
        requestCount: currentData.network?.requestCount || 0,
        requests: currentData.network?.requests || [],
        thirdPartyDomains: currentData.network?.thirdPartyDomains || []
      },
      dom: {
        hiddenIframes: currentData.dom?.hiddenIframes || 0,
        dynamicScripts: currentData.dom?.dynamicScripts || 0,
        domChanges: currentData.dom?.domChanges || 0
      },
      behavior: {
        focusChanges: currentData.behavior?.focusChanges || 0,
        tabSwitches: currentData.behavior?.tabSwitches || 0,
        clickIntervals: currentData.behavior?.clickIntervals || []
      },
      risk: {
        score: currentData.risk?.score || 0,
        level: currentData.risk?.level || 'Low',
        factors: currentData.risk?.factors || []
      }
    };
    
    // Download as JSON
    const json = JSON.stringify(report, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const domain = report.domain.replace(/[^a-zA-Z0-9]/g, '_');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `paytrace_report_${domain}_${timestamp}.json`;
    
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    URL.revokeObjectURL(url);
    
    // Show feedback
    const originalText = elements.exportBtn.innerHTML;
    elements.exportBtn.innerHTML = '✓ Exported';
    setTimeout(() => {
      elements.exportBtn.innerHTML = originalText;
    }, 2000);
    
  } catch (error) {
    console.error('[PayTrace] Export error:', error);
    alert('Failed to export report');
  }
}

/**
 * Reset monitoring data
 */
async function resetMonitoring() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      alert('No active tab found');
      return;
    }
    
    const confirmed = confirm('Are you sure you want to reset all monitoring data?');
    if (!confirmed) return;
    
    await chrome.tabs.sendMessage(tab.id, { action: 'resetMonitoring' });
    
    // Reload data after reset
    showLoading(true);
    setTimeout(() => {
      loadMonitoringData();
    }, 500);
    
    // Show feedback
    const originalText = elements.resetBtn.innerHTML;
    elements.resetBtn.innerHTML = '✓ Reset';
    setTimeout(() => {
      elements.resetBtn.innerHTML = originalText;
    }, 2000);
    
  } catch (error) {
    console.error('[PayTrace] Reset error:', error);
    alert('Failed to reset monitoring data');
  }
}

/**
 * Clean up when popup closes
 */
window.addEventListener('beforeunload', () => {
  stopAutoRefresh();
});

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializePopup);
} else {
  initializePopup();
}
