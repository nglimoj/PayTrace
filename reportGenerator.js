/**
 * Report Generator for PayTrace Extension
 * Generates JSON reports of monitoring data
 */

/**
 * Generate a comprehensive JSON report
 * @param {Object} monitoringData - Monitoring data from content script
 * @returns {Object} Formatted report object
 */
function generateReport(monitoringData) {
  const report = {
    timestamp: monitoringData.timestamp || new Date().toISOString(),
    website: monitoringData.website || window.location.href,
    domain: monitoringData.domain || window.location.hostname,
    https: monitoringData.https,
    monitoringActive: monitoringData.isActive,
    isPaymentPage: monitoringData.isPaymentPage,
    network: {
      requestCount: monitoringData.network?.requestCount || 0,
      requests: sanitizeRequests(monitoringData.network?.requests || []),
      thirdPartyDomains: monitoringData.network?.thirdPartyDomains || []
    },
    dom: {
      hiddenIframes: monitoringData.dom?.hiddenIframes || 0,
      dynamicScripts: monitoringData.dom?.dynamicScripts || 0,
      domChanges: monitoringData.dom?.domChanges || 0
    },
    behavior: {
      focusChanges: monitoringData.behavior?.focusChanges || 0,
      tabSwitches: monitoringData.behavior?.tabSwitches || 0,
      clickIntervals: monitoringData.behavior?.clickIntervals || []
    },
    security: {
      https: monitoringData.https,
      mixedContent: false // Would be populated from monitoring data
    },
    risk: {
      score: monitoringData.risk?.score || 0,
      level: monitoringData.risk?.level || 'Low',
      color: monitoringData.risk?.color || '#4CAF50',
      factors: monitoringData.risk?.factors || []
    }
  };
  
  return report;
}

/**
 * Sanitize request data to ensure no sensitive information
 * @param {Array} requests - Array of request objects
 * @returns {Array} Sanitized requests
 */
function sanitizeRequests(requests) {
  return requests.map(request => ({
    url: request.url,
    domain: request.domain,
    method: request.method,
    timestamp: request.timestamp,
    duration: request.duration,
    status: request.status,
    type: request.type
  }));
}

/**
 * Convert report to JSON string
 * @param {Object} report - Report object
 * @returns {string} JSON string
 */
function reportToJSON(report) {
  return JSON.stringify(report, null, 2);
}

/**
 * Download report as JSON file
 * @param {Object} report - Report object
 * @param {string} filename - Optional filename
 */
function downloadReport(report, filename = null) {
  const json = reportToJSON(report);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  // Generate filename if not provided
  if (!filename) {
    const domain = report.domain.replace(/[^a-zA-Z0-9]/g, '_');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    filename = `paytrace_report_${domain}_${timestamp}.json`;
  }
  
  // Create download link
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  // Clean up
  URL.revokeObjectURL(url);
}

/**
 * Generate summary text from report
 * @param {Object} report - Report object
 * @returns {string} Summary text
 */
function generateSummary(report) {
  const lines = [
    `PayTrace Security Report`,
    `=========================`,
    `Website: ${report.website}`,
    `Timestamp: ${report.timestamp}`,
    `HTTPS: ${report.https ? 'Yes' : 'No'}`,
    ``,
    `Network Activity:`,
    `- Total Requests: ${report.network.requestCount}`,
    `- Third-Party Domains: ${report.network.thirdPartyDomains.length}`,
    ``,
    `DOM Activity:`,
    `- Hidden IFrames: ${report.dom.hiddenIframes}`,
    `- Dynamic Scripts: ${report.dom.dynamicScripts}`,
    `- DOM Changes: ${report.dom.domChanges}`,
    ``,
    `User Behavior:`,
    `- Focus Changes: ${report.behavior.focusChanges}`,
    `- Tab Switches: ${report.behavior.tabSwitches}`,
    ``,
    `Risk Assessment:`,
    `- Score: ${report.risk.score}`,
    `- Level: ${report.risk.level}`
  ];
  
  return lines.join('\n');
}

/**
 * Export report to clipboard
 * @param {Object} report - Report object
 * @returns {Promise<boolean>} Success status
 */
async function copyReportToClipboard(report) {
  try {
    const json = reportToJSON(report);
    await navigator.clipboard.writeText(json);
    return true;
  } catch (error) {
    console.error('[PayTrace] Failed to copy to clipboard:', error);
    return false;
  }
}

/**
 * Validate report structure
 * @param {Object} report - Report object to validate
 * @returns {Object} Validation result
 */
function validateReport(report) {
  const errors = [];
  const warnings = [];
  
  // Required fields
  if (!report.timestamp) errors.push('Missing timestamp');
  if (!report.website) errors.push('Missing website');
  if (typeof report.https !== 'boolean') errors.push('Missing or invalid HTTPS status');
  
  // Network section
  if (!report.network) errors.push('Missing network section');
  else {
    if (typeof report.network.requestCount !== 'number') 
      errors.push('Invalid request count');
  }
  
  // DOM section
  if (!report.dom) errors.push('Missing DOM section');
  
  // Behavior section
  if (!report.behavior) errors.push('Missing behavior section');
  
  // Risk section
  if (!report.risk) errors.push('Missing risk section');
  else {
    if (typeof report.risk.score !== 'number') 
      errors.push('Invalid risk score');
    if (!['Low', 'Medium', 'High'].includes(report.risk.level))
      errors.push('Invalid risk level');
  }
  
  // Warnings
  if (report.network?.thirdPartyDomains?.length > 10) {
    warnings.push('High number of third-party domains');
  }
  
  if (report.dom?.hiddenIframes > 0) {
    warnings.push('Hidden iframes detected');
  }
  
  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    generateReport,
    reportToJSON,
    downloadReport,
    generateSummary,
    copyReportToClipboard,
    validateReport
  };
}
