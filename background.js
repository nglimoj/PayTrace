/**
 * Background Service Worker for PayTrace Extension
 * Manages extension lifecycle and badge updates
 */

// Storage for tab-specific data
const tabData = new Map();

/**
 * Install event handler
 */
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[PayTrace] Extension installed');
    
    // Set default badge
    chrome.action.setBadgeText({ text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#9E9E9E' });
  } else if (details.reason === 'update') {
    console.log('[PayTrace] Extension updated');
  }
});

/**
 * Handle tab creation
 */
chrome.tabs.onCreated.addListener((tab) => {
  tabData.set(tab.id, {
    monitoringActive: false,
    riskLevel: 'Low',
    riskColor: '#4CAF50'
  });
});

/**
 * Handle tab removal
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  tabData.delete(tabId);
});

/**
 * Handle tab updates (navigation)
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Reset badge for new page
    chrome.action.setBadgeText({ tabId, text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#9E9E9E' });
    
    // Update tab data
    if (tabData.has(tabId)) {
      const data = tabData.get(tabId);
      data.monitoringActive = false;
      data.riskLevel = 'Low';
      data.riskColor = '#4CAF50';
      tabData.set(tabId, data);
    }
  }
});

/**
 * Handle messages from content script and popup
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'updateBadge') {
    updateBadge(sender.tab.id, request.data);
    sendResponse({ success: true });
  } else if (request.action === 'getTabData') {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    sendResponse(tabData.get(tabId) || {});
  } else if (request.action === 'setTabData') {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    tabData.set(tabId, request.data);
    sendResponse({ success: true });
  }
  return true;
});

/**
 * Update badge based on risk level
 */
function updateBadge(tabId, data) {
  if (!tabId) return;
  
  const { level, color } = data;
  
  // Set badge text based on risk level
  let badgeText = 'OFF';
  if (level === 'Low') {
    badgeText = 'LOW';
  } else if (level === 'Medium') {
    badgeText = 'MED';
  } else if (level === 'High') {
    badgeText = 'HIGH';
  }
  
  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: color });
  
  // Update tab data
  if (tabData.has(tabId)) {
    const data = tabData.get(tabId);
    data.monitoringActive = true;
    data.riskLevel = level;
    data.riskColor = color;
    tabData.set(tabId, data);
  }
}

/**
 * Handle extension icon click (optional - can be used for quick actions)
 */
chrome.action.onClicked.addListener((tab) => {
  // Open popup is default behavior, this is for additional actions if needed
  console.log('[PayTrace] Extension icon clicked');
});

/**
 * Keep service worker alive (optional, for long-running operations)
 */
chrome.alarms.create('keepAlive', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    // Perform any periodic maintenance tasks
  }
});
