/**
 * Content Script for PayTrace Extension
 * Monitors payment pages for suspicious behavior without collecting sensitive data
 */

// Monitoring state
const monitoringState = {
  isActive: false,
  isPaymentPage: false,
  networkRequests: [],
  domChanges: 0,
  hiddenIframes: 0,
  dynamicScripts: 0,
  suspiciousOverlays: 0,
  invisibleInputs: 0,
  domReplacements: 0,
  unexpectedPopups: 0,
  focusChanges: 0,
  tabSwitches: 0,
  clickIntervals: [],
  formReplacements: 0,
  hiddenFields: 0,
  suspiciousDomains: 0,
  thirdPartyScripts: 0,
  externalRedirects: 0,
  startTime: null,
  lastClickTime: null,
  domChangeTimestamps: [],
  initialScripts: new Set()
};

// Mutation observer for DOM monitoring
let domObserver = null;

// Original methods for network monitoring
const originalFetch = window.fetch;
const originalXHROpen = XMLHttpRequest.prototype.open;
const originalXHRSend = XMLHttpRequest.prototype.send;
const originalSendBeacon = navigator.sendBeacon;
const originalWebSocket = window.WebSocket;

/**
 * Initialize monitoring on page load
 */
function initializeMonitoring() {
  // Check if this is a payment page
  monitoringState.isPaymentPage = isPaymentPage();
  
  if (monitoringState.isPaymentPage) {
    startMonitoring();
  } else {
    // Set up a listener to detect if page becomes a payment page
    setupPaymentPageDetection();
  }
  
  // Store initial scripts to detect dynamic injections
  document.querySelectorAll('script[src]').forEach(script => {
    monitoringState.initialScripts.add(script.src);
  });
}

/**
 * Start all monitoring activities
 */
function startMonitoring() {
  if (monitoringState.isActive) return;
  
  monitoringState.isActive = true;
  monitoringState.startTime = Date.now();
  
  console.log('[PayTrace] Monitoring started on payment page');
  
  // Start network monitoring
  setupNetworkMonitoring();
  
  // Start DOM monitoring
  setupDOMMonitoring();
  
  // Start user interaction monitoring
  setupInteractionMonitoring();
  
  // Start security checks
  performSecurityChecks();
  
  // Update badge
  updateBadge();
}

/**
 * Stop all monitoring activities
 */
function stopMonitoring() {
  if (!monitoringState.isActive) return;
  
  monitoringState.isActive = false;
  
  // Stop DOM observer
  if (domObserver) {
    domObserver.disconnect();
    domObserver = null;
  }
  
  console.log('[PayTrace] Monitoring stopped');
}

/**
 * Set up detection for payment page changes
 */
function setupPaymentPageDetection() {
  const checkInterval = setInterval(() => {
    if (isPaymentPage() && !monitoringState.isActive) {
      clearInterval(checkInterval);
      startMonitoring();
    }
  }, 1000);
  
  // Check for 10 seconds, then stop
  setTimeout(() => clearInterval(checkInterval), 10000);
}

/**
 * Set up network monitoring
 */
function setupNetworkMonitoring() {
  // Monitor fetch API
  window.fetch = function(...args) {
    const url = args[0];
    const startTime = Date.now();
    
    return originalFetch.apply(this, args).then(response => {
      const duration = Date.now() - startTime;
      logNetworkRequest(url, 'FETCH', response.status, duration);
      return response;
    }).catch(error => {
      const duration = Date.now() - startTime;
      logNetworkRequest(url, 'FETCH', 0, duration);
      throw error;
    });
  };
  
  // Monitor XMLHttpRequest
  XMLHttpRequest.prototype.open = function(method, url) {
    this._payTraceUrl = url;
    this._payTraceMethod = method;
    this._payTraceStartTime = Date.now();
    return originalXHROpen.apply(this, arguments);
  };
  
  XMLHttpRequest.prototype.send = function() {
    this.addEventListener('loadend', () => {
      const duration = Date.now() - this._payTraceStartTime;
      logNetworkRequest(
        this._payTraceUrl,
        this._payTraceMethod,
        this.status,
        duration
      );
    });
    return originalXHRSend.apply(this, arguments);
  };
  
  // Monitor sendBeacon
  if (navigator.sendBeacon) {
    navigator.sendBeacon = function(url, data) {
      logNetworkRequest(url, 'BEACON', 200, 0);
      return originalSendBeacon.apply(this, arguments);
    };
  }
  
  // Monitor WebSocket
  window.WebSocket = function(url, protocols) {
    logNetworkRequest(url, 'WEBSOCKET', 101, 0);
    return new originalWebSocket(url, protocols);
  };
}

/**
 * Log a network request (metadata only, no bodies)
 */
function logNetworkRequest(url, method, status, duration) {
  const domain = extractDomain(url);
  
  const request = {
    url: sanitizeData(url),
    domain: domain,
    method: method,
    timestamp: getTimestamp(),
    duration: duration,
    status: status,
    type: method
  };
  
  monitoringState.networkRequests.push(request);
  
  // Check for suspicious domains
  if (isSuspiciousDomain(domain)) {
    monitoringState.suspiciousDomains++;
  }
  
  // Check for external redirects
  if (status >= 300 && status < 400 && isThirdPartyDomain(domain)) {
    monitoringState.externalRedirects++;
  }
  
  // Update badge periodically
  if (monitoringState.networkRequests.length % 10 === 0) {
    updateBadge();
  }
}

/**
 * Set up DOM monitoring with MutationObserver
 */
function setupDOMMonitoring() {
  domObserver = new MutationObserver((mutations) => {
    monitoringState.domChanges++;
    monitoringState.domChangeTimestamps.push(Date.now());
    
    // Check for rapid DOM changes
    if (monitoringState.domChangeTimestamps.length > 20) {
      const recentChanges = monitoringState.domChangeTimestamps.slice(-20);
      const timeSpan = recentChanges[19] - recentChanges[0];
      if (timeSpan < 2000) { // 20 changes in less than 2 seconds
        // Flag as rapid changes (handled in risk assessment)
      }
    }
    
    mutations.forEach(mutation => {
      // Check for added nodes
      mutation.addedNodes.forEach(node => {
        if (node.nodeName === 'IFRAME') {
          checkHiddenIframe(node);
        }
        
        if (node.nodeName === 'SCRIPT') {
          checkDynamicScript(node);
        }
        
        if (node.nodeName === 'INPUT') {
          checkInvisibleInput(node);
        }
        
        if (node.nodeName === 'DIV' || node.nodeName === 'SPAN') {
          checkSuspiciousOverlay(node);
        }
      });
      
      // Check for removed nodes (potential replacement)
      mutation.removedNodes.forEach(node => {
        if (node.nodeName === 'FORM') {
          monitoringState.formReplacements++;
        }
      });
    });
  });
  
  domObserver.observe(document, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['style', 'class', 'hidden']
  });
  
  // Initial DOM checks
  setTimeout(() => {
    performInitialDOMChecks();
  }, 1000);
}

/**
 * Perform initial DOM checks when page loads
 */
function performInitialDOMChecks() {
  // Check for hidden iframes
  document.querySelectorAll('iframe').forEach(checkHiddenIframe);
  
  // Check for invisible inputs
  document.querySelectorAll('input').forEach(checkInvisibleInput);
  
  // Check for hidden form fields
  document.querySelectorAll('input[type="hidden"]').forEach(() => {
    monitoringState.hiddenFields++;
  });
  
  // Count third-party scripts
  monitoringState.thirdPartyScripts = countThirdPartyScripts();
}

/**
 * Check if iframe is hidden
 */
function checkHiddenIframe(iframe) {
  const style = window.getComputedStyle(iframe);
  if (style.display === 'none' || 
      style.visibility === 'hidden' ||
      style.opacity === '0' ||
      iframe.width === '0' ||
      iframe.height === '0') {
    monitoringState.hiddenIframes++;
  }
}

/**
 * Check if script was dynamically injected
 */
function checkDynamicScript(script) {
  if (script.src && !monitoringState.initialScripts.has(script.src)) {
    monitoringState.dynamicScripts++;
    monitoringState.initialScripts.add(script.src);
  }
}

/**
 * Check if input is invisible
 */
function checkInvisibleInput(input) {
  const style = window.getComputedStyle(input);
  if (style.display === 'none' || 
      style.visibility === 'hidden' ||
      style.opacity === '0' ||
      input.offsetWidth === 0 ||
      input.offsetHeight === 0) {
    if (input.type !== 'hidden') {
      monitoringState.invisibleInputs++;
    }
  }
}

/**
 * Check for suspicious overlay
 */
function checkSuspiciousOverlay(element) {
  const style = window.getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  
  // Check if element covers large portion of screen
  if (rect.width > window.innerWidth * 0.8 && 
      rect.height > window.innerHeight * 0.8) {
    monitoringState.suspiciousOverlays++;
  }
}

/**
 * Set up user interaction monitoring
 */
function setupInteractionMonitoring() {
  // Monitor focus changes
  document.addEventListener('focus', () => {
    monitoringState.focusChanges++;
  }, true);
  
  document.addEventListener('blur', () => {
    monitoringState.focusChanges++;
  }, true);
  
  // Monitor clicks (timing only, not content)
  document.addEventListener('click', () => {
    const now = Date.now();
    if (monitoringState.lastClickTime) {
      const interval = now - monitoringState.lastClickTime;
      monitoringState.clickIntervals.push(interval);
      
      // Keep only last 100 intervals
      if (monitoringState.clickIntervals.length > 100) {
        monitoringState.clickIntervals.shift();
      }
    }
    monitoringState.lastClickTime = now;
  }, true);
  
  // Monitor tab visibility changes
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      monitoringState.tabSwitches++;
    }
  });
  
  // Monitor page redirects
  window.addEventListener('beforeunload', () => {
    // Log redirect before page unloads
  });
}

/**
 * Perform security checks
 */
function performSecurityChecks() {
  // HTTPS check
  const httpsStatus = isHTTPS();
  
  // Mixed content check
  const mixedContent = hasMixedContent();
  
  // Store security data
  monitoringState.security = {
    https: httpsStatus,
    mixedContent: mixedContent
  };
}

/**
 * Calculate current risk score
 */
function calculateRiskScore() {
  const monitoringData = {
    security: monitoringState.security,
    dom: {
      hiddenIframes: monitoringState.hiddenIframes,
      dynamicScripts: monitoringState.dynamicScripts,
      suspiciousOverlays: monitoringState.suspiciousOverlays,
      invisibleInputs: monitoringState.invisibleInputs,
      domReplacements: monitoringState.domReplacements,
      unexpectedPopups: monitoringState.unexpectedPopups,
      rapidChanges: monitoringState.domChangeTimestamps.length > 50
    },
    network: {
      suspiciousDomains: monitoringState.suspiciousDomains,
      thirdPartyScripts: monitoringState.thirdPartyScripts,
      externalRedirects: monitoringState.externalRedirects
    },
    behavior: {
      focusChanges: monitoringState.focusChanges,
      tabSwitches: monitoringState.tabSwitches,
      suspiciousTiming: monitoringState.clickIntervals.some(interval => interval < 50)
    },
    form: {
      formReplacements: monitoringState.formReplacements,
      hiddenFields: monitoringState.hiddenFields
    }
  };
  
  return riskEngine.assess(monitoringData);
}

/**
 * Update extension badge based on risk level
 */
function updateBadge() {
  const assessment = calculateRiskScore();
  
  chrome.runtime.sendMessage({
    action: 'updateBadge',
    data: {
      level: assessment.level,
      color: assessment.color
    }
  });
}

/**
 * Get monitoring data for popup
 */
function getMonitoringData() {
  return {
    timestamp: getTimestamp(),
    website: window.location.href,
    domain: window.location.hostname,
    https: isHTTPS(),
    isActive: monitoringState.isActive,
    isPaymentPage: monitoringState.isPaymentPage,
    network: {
      requestCount: monitoringState.networkRequests.length,
      requests: monitoringState.networkRequests.slice(-50), // Last 50 requests
      thirdPartyDomains: getThirdPartyDomains()
    },
    dom: {
      hiddenIframes: monitoringState.hiddenIframes,
      dynamicScripts: monitoringState.dynamicScripts,
      domChanges: monitoringState.domChanges
    },
    behavior: {
      focusChanges: monitoringState.focusChanges,
      tabSwitches: monitoringState.tabSwitches,
      clickIntervals: monitoringState.clickIntervals.slice(-20)
    },
    risk: calculateRiskScore()
  };
}

/**
 * Reset monitoring data
 */
function resetMonitoring() {
  monitoringState.networkRequests = [];
  monitoringState.domChanges = 0;
  monitoringState.hiddenIframes = 0;
  monitoringState.dynamicScripts = 0;
  monitoringState.suspiciousOverlays = 0;
  monitoringState.invisibleInputs = 0;
  monitoringState.domReplacements = 0;
  monitoringState.unexpectedPopups = 0;
  monitoringState.focusChanges = 0;
  monitoringState.tabSwitches = 0;
  monitoringState.clickIntervals = [];
  monitoringState.formReplacements = 0;
  monitoringState.hiddenFields = 0;
  monitoringState.suspiciousDomains = 0;
  monitoringState.externalRedirects = 0;
  monitoringState.domChangeTimestamps = [];
  
  riskEngine.reset();
  updateBadge();
}

/**
 * Listen for messages from popup
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getMonitoringData') {
    sendResponse(getMonitoringData());
  } else if (request.action === 'resetMonitoring') {
    resetMonitoring();
    sendResponse({ success: true });
  } else if (request.action === 'startMonitoring') {
    startMonitoring();
    sendResponse({ success: true });
  } else if (request.action === 'stopMonitoring') {
    stopMonitoring();
    sendResponse({ success: true });
  }
  return true;
});

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeMonitoring);
} else {
  initializeMonitoring();
}
