/**
 * Utility Functions for PayTrace Extension
 * Provides helper functions for data collection, validation, and formatting
 */

// Payment-related keywords to detect payment pages
const PAYMENT_KEYWORDS = [
  'card', 'credit', 'debit', 'cvv', 'cvc', 'expiry', 'expire',
  'payment', 'checkout', 'billing', 'upi', 'netbanking', 'wallet',
  'visa', 'mastercard', 'amex', 'discover', 'paypal', 'stripe'
];

// Input field types that indicate payment fields
const PAYMENT_INPUT_TYPES = [
  'cc-number', 'cc-exp', 'cc-csc', 'cc-exp-month', 'cc-exp-year',
  'card-number', 'card-exp', 'card-cvc', 'credit-card', 'debit-card'
];

// Suspicious domains known for skimming/malware
const SUSPICIOUS_DOMAINS = [
  'jquery-cloudflare', 'cloudflare-cdn', 'cdn-jsdelivr',
  'bootstrap-cdn', 'analytics', 'tracking', 'pixel'
];

/**
 * Check if current page is a payment page
 * @returns {boolean} True if payment page detected
 */
function isPaymentPage() {
  // Check URL for payment-related keywords
  const url = window.location.href.toLowerCase();
  const urlHasPaymentKeyword = PAYMENT_KEYWORDS.some(keyword => 
    url.includes(keyword)
  );

  // Check for payment-related forms
  const forms = document.querySelectorAll('form');
  let formHasPaymentField = false;

  for (const form of forms) {
    const inputs = form.querySelectorAll('input');
    for (const input of inputs) {
      const type = input.type?.toLowerCase() || '';
      const name = input.name?.toLowerCase() || '';
      const id = input.id?.toLowerCase() || '';
      const placeholder = input.placeholder?.toLowerCase() || '';

      const combined = `${type} ${name} ${id} ${placeholder}`;
      
      if (PAYMENT_INPUT_TYPES.some(pt => combined.includes(pt)) ||
          PAYMENT_KEYWORDS.some(pk => combined.includes(pk))) {
        formHasPaymentField = true;
        break;
      }
    }
    if (formHasPaymentField) break;
  }

  // Check page title
  const title = document.title?.toLowerCase() || '';
  const titleHasPaymentKeyword = PAYMENT_KEYWORDS.some(keyword => 
    title.includes(keyword)
  );

  return urlHasPaymentKeyword || formHasPaymentField || titleHasPaymentKeyword;
}

/**
 * Extract domain from URL
 * @param {string} url - Full URL
 * @returns {string} Domain name
 */
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (e) {
    return '';
  }
}

/**
 * Check if domain is third-party (different from current page)
 * @param {string} domain - Domain to check
 * @returns {boolean} True if third-party
 */
function isThirdPartyDomain(domain) {
  const currentDomain = window.location.hostname;
  return domain !== currentDomain && !domain.endsWith('.' + currentDomain);
}

/**
 * Check if domain is suspicious
 * @param {string} domain - Domain to check
 * @returns {boolean} True if suspicious
 */
function isSuspiciousDomain(domain) {
  const lowerDomain = domain.toLowerCase();
  return SUSPICIOUS_DOMAINS.some(suspicious => 
    lowerDomain.includes(suspicious)
  );
}

/**
 * Get current timestamp in ISO format
 * @returns {string} ISO timestamp
 */
function getTimestamp() {
  return new Date().toISOString();
}

/**
 * Calculate duration between two timestamps
 * @param {number} startTime - Start time in milliseconds
 * @param {number} endTime - End time in milliseconds
 * @returns {number} Duration in milliseconds
 */
function calculateDuration(startTime, endTime) {
  return endTime - startTime;
}

/**
 * Sanitize data to remove any sensitive information
 * @param {string} data - Data to sanitize
 * @returns {string} Sanitized data
 */
function sanitizeData(data) {
  if (!data || typeof data !== 'string') return data;
  
  // Remove potential credit card patterns (basic protection)
  let sanitized = data.replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[REDACTED]');
  sanitized = sanitized.replace(/\b\d{16}\b/g, '[REDACTED]');
  
  return sanitized;
}

/**
 * Deep clone an object
 * @param {Object} obj - Object to clone
 * @returns {Object} Cloned object
 */
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Debounce function to limit execution rate
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Throttle function to limit execution rate
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, limit) {
  let inThrottle;
  return function executedFunction(...args) {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

/**
 * Check if page is using HTTPS
 * @returns {boolean} True if HTTPS
 */
function isHTTPS() {
  return window.location.protocol === 'https:';
}

/**
 * Count iframes on page
 * @returns {number} Number of iframes
 */
function countIframes() {
  return document.querySelectorAll('iframe').length;
}

/**
 * Count hidden iframes on page
 * @returns {number} Number of hidden iframes
 */
function countHiddenIframes() {
  const iframes = document.querySelectorAll('iframe');
  let hiddenCount = 0;
  
  iframes.forEach(iframe => {
    const style = window.getComputedStyle(iframe);
    if (style.display === 'none' || 
        style.visibility === 'hidden' ||
        style.opacity === '0' ||
        iframe.width === '0' ||
        iframe.height === '0') {
      hiddenCount++;
    }
  });
  
  return hiddenCount;
}

/**
 * Count scripts on page
 * @returns {number} Number of scripts
 */
function countScripts() {
  return document.querySelectorAll('script').length;
}

/**
 * Count third-party scripts
 * @returns {number} Number of third-party scripts
 */
function countThirdPartyScripts() {
  const scripts = document.querySelectorAll('script[src]');
  let thirdPartyCount = 0;
  
  scripts.forEach(script => {
    const domain = extractDomain(script.src);
    if (domain && isThirdPartyDomain(domain)) {
      thirdPartyCount++;
    }
  });
  
  return thirdPartyCount;
}

/**
 * Get all third-party domains from scripts
 * @returns {Array<string>} Array of third-party domains
 */
function getThirdPartyDomains() {
  const scripts = document.querySelectorAll('script[src]');
  const domains = new Set();
  
  scripts.forEach(script => {
    const domain = extractDomain(script.src);
    if (domain && isThirdPartyDomain(domain)) {
      domains.add(domain);
    }
  });
  
  return Array.from(domains);
}

/**
 * Check for mixed content (HTTP resources on HTTPS page)
 * @returns {boolean} True if mixed content detected
 */
function hasMixedContent() {
  if (!isHTTPS()) return false;
  
  const resources = document.querySelectorAll('[src], [href]');
  for (const resource of resources) {
    const url = resource.src || resource.href;
    if (url && url.startsWith('http:')) {
      return true;
    }
  }
  return false;
}

/**
 * Generate unique ID
 * @returns {string} Unique ID
 */
function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

/**
 * Format bytes to human-readable format
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted string
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Validate URL format
 * @param {string} url - URL to validate
 * @returns {boolean} True if valid URL
 */
function isValidUrl(url) {
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    isPaymentPage,
    extractDomain,
    isThirdPartyDomain,
    isSuspiciousDomain,
    getTimestamp,
    calculateDuration,
    sanitizeData,
    deepClone,
    debounce,
    throttle,
    isHTTPS,
    countIframes,
    countHiddenIframes,
    countScripts,
    countThirdPartyScripts,
    getThirdPartyDomains,
    hasMixedContent,
    generateId,
    formatBytes,
    isValidUrl,
    PAYMENT_KEYWORDS,
    PAYMENT_INPUT_TYPES,
    SUSPICIOUS_DOMAINS
  };
}
