/**
 * Risk Scoring Engine for PayTrace Extension
 * Calculates risk scores based on detected anomalies and suspicious behaviors
 */

/**
 * Risk score thresholds
 */
const RISK_THRESHOLDS = {
  LOW: 30,
  MEDIUM: 60,
  HIGH: 100
};

/**
 * Risk score weights for different anomalies
 */
const RISK_WEIGHTS = {
  // Security issues
  HTTP_PAGE: 50,
  MIXED_CONTENT: 30,
  MISSING_HTTPS: 50,
  
  // DOM anomalies
  HIDDEN_IFRAME: 30,
  MULTIPLE_HIDDEN_IFRAMES: 20, // Additional per iframe
  DYNAMIC_SCRIPT: 25,
  MULTIPLE_DYNAMIC_SCRIPTS: 10, // Additional per script
  SUSPICIOUS_OVERLAY: 35,
  INVISIBLE_INPUT: 25,
  DOM_REPLACEMENT: 40,
  UNEXPECTED_POPUP: 30,
  
  // Network anomalies
  SUSPICIOUS_DOMAIN: 20,
  MANY_THIRD_PARTY_SCRIPTS: 15,
  EXTERNAL_REDIRECT: 25,
  MULTIPLE_REDIRECTS: 10, // Additional per redirect
  
  // Behavioral anomalies
  RAPID_DOM_CHANGES: 10,
  EXCESSIVE_FOCUS_CHANGES: 15,
  RAPID_TAB_SWITCHES: 20,
  SUSPICIOUS_TIMING: 25,
  
  // Form anomalies
  FORM_REPLACEMENT: 35,
  HIDDEN_FORM_FIELDS: 20
};

/**
 * Risk level labels
 */
const RISK_LEVELS = {
  LOW: 'Low',
  MEDIUM: 'Medium',
  HIGH: 'High'
};

/**
 * Risk level colors for badge
 */
const RISK_COLORS = {
  LOW: '#4CAF50',    // Green
  MEDIUM: '#FF9800', // Orange
  HIGH: '#F44336'    // Red
};

/**
 * Risk assessment data structure
 */
class RiskAssessment {
  constructor() {
    this.score = 0;
    this.factors = [];
    this.level = RISK_LEVELS.LOW;
  }
  
  /**
   * Add a risk factor
   * @param {string} factor - Factor description
   * @param {number} weight - Risk weight
   */
  addFactor(factor, weight) {
    this.score += weight;
    this.factors.push({
      factor,
      weight,
      timestamp: new Date().toISOString()
    });
    this.updateLevel();
  }
  
  /**
   * Update risk level based on score
   */
  updateLevel() {
    if (this.score >= RISK_THRESHOLDS.HIGH) {
      this.level = RISK_LEVELS.HIGH;
    } else if (this.score >= RISK_THRESHOLDS.MEDIUM) {
      this.level = RISK_LEVELS.MEDIUM;
    } else {
      this.level = RISK_LEVELS.LOW;
    }
  }
  
  /**
   * Get risk level color
   * @returns {string} Color hex code
   */
  getColor() {
    return RISK_COLORS[this.level.toUpperCase()];
  }
  
  /**
   * Reset assessment
   */
  reset() {
    this.score = 0;
    this.factors = [];
    this.level = RISK_LEVELS.LOW;
  }
  
  /**
   * Get assessment summary
   * @returns {Object} Summary object
   */
  getSummary() {
    return {
      score: this.score,
      level: this.level,
      color: this.getColor(),
      factors: this.factors
    };
  }
}

/**
 * Risk Engine class
 */
class RiskEngine {
  constructor() {
    this.assessment = new RiskAssessment();
  }
  
  /**
   * Assess page security
   * @param {Object} securityData - Security-related data
   */
  assessSecurity(securityData) {
    // Check for HTTP
    if (!securityData.https) {
      this.assessment.addFactor('Page not using HTTPS', RISK_WEIGHTS.HTTP_PAGE);
    }
    
    // Check for mixed content
    if (securityData.mixedContent) {
      this.assessment.addFactor('Mixed content detected (HTTP on HTTPS page)', RISK_WEIGHTS.MIXED_CONTENT);
    }
  }
  
  /**
   * Assess DOM anomalies
   * @param {Object} domData - DOM-related data
   */
  assessDOM(domData) {
    // Hidden iframes
    if (domData.hiddenIframes > 0) {
      this.assessment.addFactor(
        `Hidden iframe detected (${domData.hiddenIframes} total)`,
        RISK_WEIGHTS.HIDDEN_IFRAME + (domData.hiddenIframes - 1) * RISK_WEIGHTS.MULTIPLE_HIDDEN_IFRAMES
      );
    }
    
    // Dynamic scripts
    if (domData.dynamicScripts > 0) {
      this.assessment.addFactor(
        `Dynamically injected script detected (${domData.dynamicScripts} total)`,
        RISK_WEIGHTS.DYNAMIC_SCRIPT + (domData.dynamicScripts - 1) * RISK_WEIGHTS.MULTIPLE_DYNAMIC_SCRIPTS
      );
    }
    
    // Suspicious overlays
    if (domData.suspiciousOverlays > 0) {
      this.assessment.addFactor(
        `Suspicious overlay detected (${domData.suspiciousOverlays} total)`,
        RISK_WEIGHTS.SUSPICIOUS_OVERLAY * domData.suspiciousOverlays
      );
    }
    
    // Invisible inputs
    if (domData.invisibleInputs > 0) {
      this.assessment.addFactor(
        `Invisible input field detected (${domData.invisibleInputs} total)`,
        RISK_WEIGHTS.INVISIBLE_INPUT * domData.invisibleInputs
      );
    }
    
    // DOM replacements
    if (domData.domReplacements > 0) {
      this.assessment.addFactor(
        `DOM replacement detected (${domData.domReplacements} total)`,
        RISK_WEIGHTS.DOM_REPLACEMENT * domData.domReplacements
      );
    }
    
    // Unexpected popups
    if (domData.unexpectedPopups > 0) {
      this.assessment.addFactor(
        `Unexpected popup during checkout (${domData.unexpectedPopups} total)`,
        RISK_WEIGHTS.UNEXPECTED_POPUP * domData.unexpectedPopups
      );
    }
    
    // Rapid DOM changes
    if (domData.rapidChanges) {
      this.assessment.addFactor(
        'Rapid DOM modifications detected',
        RISK_WEIGHTS.RAPID_DOM_CHANGES
      );
    }
  }
  
  /**
   * Assess network anomalies
   * @param {Object} networkData - Network-related data
   */
  assessNetwork(networkData) {
    // Suspicious domains
    if (networkData.suspiciousDomains > 0) {
      this.assessment.addFactor(
        `Suspicious external script domain detected (${networkData.suspiciousDomains} total)`,
        RISK_WEIGHTS.SUSPICIOUS_DOMAIN * networkData.suspiciousDomains
      );
    }
    
    // Many third-party scripts
    if (networkData.thirdPartyScripts > 5) {
      this.assessment.addFactor(
        `Large number of third-party scripts (${networkData.thirdPartyScripts})`,
        RISK_WEIGHTS.MANY_THIRD_PARTY_SCRIPTS
      );
    }
    
    // External redirects
    if (networkData.externalRedirects > 0) {
      this.assessment.addFactor(
        `External redirect detected (${networkData.externalRedirects} total)`,
        RISK_WEIGHTS.EXTERNAL_REDIRECT + (networkData.externalRedirects - 1) * RISK_WEIGHTS.MULTIPLE_REDIRECTS
      );
    }
  }
  
  /**
   * Assess behavioral anomalies
   * @param {Object} behaviorData - Behavior-related data
   */
  assessBehavior(behaviorData) {
    // Excessive focus changes
    if (behaviorData.focusChanges > 10) {
      this.assessment.addFactor(
        `Excessive focus changes detected (${behaviorData.focusChanges})`,
        RISK_WEIGHTS.EXCESSIVE_FOCUS_CHANGES
      );
    }
    
    // Rapid tab switches
    if (behaviorData.tabSwitches > 5) {
      this.assessment.addFactor(
        `Rapid tab switching detected (${behaviorData.tabSwitches})`,
        RISK_WEIGHTS.RAPID_TAB_SWITCHES
      );
    }
    
    // Suspicious timing patterns
    if (behaviorData.suspiciousTiming) {
      this.assessment.addFactor(
        'Suspicious timing pattern detected',
        RISK_WEIGHTS.SUSPICIOUS_TIMING
      );
    }
  }
  
  /**
   * Assess form anomalies
   * @param {Object} formData - Form-related data
   */
  assessForm(formData) {
    // Form replacement
    if (formData.formReplacements > 0) {
      this.assessment.addFactor(
        `Form replacement detected (${formData.formReplacements} total)`,
        RISK_WEIGHTS.FORM_REPLACEMENT * formData.formReplacements
      );
    }
    
    // Hidden form fields
    if (formData.hiddenFields > 0) {
      this.assessment.addFactor(
        `Hidden form field detected (${formData.hiddenFields} total)`,
        RISK_WEIGHTS.HIDDEN_FORM_FIELDS * formData.hiddenFields
      );
    }
  }
  
  /**
   * Perform comprehensive risk assessment
   * @param {Object} monitoringData - Complete monitoring data
   * @returns {Object} Risk assessment result
   */
  assess(monitoringData) {
    // Reset previous assessment
    this.assessment.reset();
    
    // Assess all categories
    if (monitoringData.security) {
      this.assessSecurity(monitoringData.security);
    }
    
    if (monitoringData.dom) {
      this.assessDOM(monitoringData.dom);
    }
    
    if (monitoringData.network) {
      this.assessNetwork(monitoringData.network);
    }
    
    if (monitoringData.behavior) {
      this.assessBehavior(monitoringData.behavior);
    }
    
    if (monitoringData.form) {
      this.assessForm(monitoringData.form);
    }
    
    return this.assessment.getSummary();
  }
  
  /**
   * Get current assessment
   * @returns {Object} Current assessment
   */
  getAssessment() {
    return this.assessment.getSummary();
  }
  
  /**
   * Reset the engine
   */
  reset() {
    this.assessment.reset();
  }
}

// Create global risk engine instance
const riskEngine = new RiskEngine();

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    RiskEngine,
    RiskAssessment,
    riskEngine,
    RISK_THRESHOLDS,
    RISK_WEIGHTS,
    RISK_LEVELS,
    RISK_COLORS
  };
}
