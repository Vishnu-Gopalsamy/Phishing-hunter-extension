/**
 * Content Script for Phishing Guard Pro
 * Analyzes page source code for phishing indicators and sends results to popup
 */

// Define suspicious patterns to look for in source code
const SUSPICIOUS_PATTERNS = {
  obfuscatedJS: /eval\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}|\bunescape\s*\(/i,
  hiddenElements: /style\s*=\s*["'](?:[^"']*(?:visibility\s*:\s*hidden|display\s*:\s*none|opacity\s*:\s*0)[^"']*)/i,
  passwordFields: /<input[^>]*type\s*=\s*["']password["'][^>]*>/i,
  externalForms: /<form[^>]*action\s*=\s*["']https?:\/\/(?!(?:.*?\.)?window\.location\.hostname)/i,
  cookieStealers: /document\.cookie/i,
  redirectScripts: /window\.location|location\.replace|location\.href\s*=/i
};

// Analyze page source code for threats
function analyzeSourceCode() {
  const pageSource = document.documentElement.outerHTML;
  const url = window.location.href;
  const domain = window.location.hostname;
  
  // Results object
  const sourceAnalysis = {
    url: url,
    domain: domain,
    threatIndicators: [],
    riskScore: 0,
    sensitiveFormPresent: false,
    externalSubmission: false,
    threatDetails: {}
  };
  
  // Check for suspicious patterns
  for (const [key, pattern] of Object.entries(SUSPICIOUS_PATTERNS)) {
    if (pattern.test(pageSource)) {
      sourceAnalysis.threatIndicators.push(key);
      sourceAnalysis.riskScore += 15; // 15 points per suspicious pattern
    }
  }
  
  // Analyze forms (more detailed than regex)
  const forms = document.forms;
  sourceAnalysis.threatDetails.forms = {
    count: forms.length,
    externalActions: 0,
    passwordFields: 0,
    loginForms: 0
  };
  
  for (const form of forms) {
    // Check form action
    const action = form.action;
    if (action && action.startsWith('http')) {
      try {
        const actionDomain = new URL(action).hostname;
        if (actionDomain !== domain) {
          sourceAnalysis.threatDetails.forms.externalActions++;
          sourceAnalysis.externalSubmission = true;
          sourceAnalysis.riskScore += 20;
          sourceAnalysis.threatIndicators.push('externalFormSubmission');
        }
      } catch (e) {
        // Invalid URL in action
      }
    }
    
    // Check for password fields
    const passwordFields = form.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
      sourceAnalysis.threatDetails.forms.passwordFields += passwordFields.length;
      sourceAnalysis.sensitiveFormPresent = true;
      
      // If we have password field and external action = high risk
      if (sourceAnalysis.externalSubmission) {
        sourceAnalysis.riskScore += 30;
        sourceAnalysis.threatIndicators.push('credentialStealing');
      }
    }
  }
  
  // Check for hidden elements (better than regex)
  const hiddenElements = document.querySelectorAll(
    '[style*="display: none"], [style*="visibility: hidden"], [style*="opacity: 0"]'
  );
  sourceAnalysis.threatDetails.hiddenElements = hiddenElements.length;
  
  if (hiddenElements.length > 3) { // Allow a few for legitimate sites
    sourceAnalysis.threatIndicators.push('excessiveHiddenElements');
    sourceAnalysis.riskScore += 15;
  }
  
  // Check scripts
  const scripts = document.querySelectorAll('script');
  sourceAnalysis.threatDetails.scripts = {
    count: scripts.length,
    inline: 0,
    external: 0,
    suspicious: 0
  };
  
  scripts.forEach(script => {
    if (script.src) {
      sourceAnalysis.threatDetails.scripts.external++;
      // Check if script is from external domain
      try {
        const scriptDomain = new URL(script.src).hostname;
        if (scriptDomain !== domain) {
          sourceAnalysis.threatDetails.scripts.suspicious++;
        }
      } catch (e) {
        // Invalid URL in src
      }
    } else if (script.innerText) {
      sourceAnalysis.threatDetails.scripts.inline++;
      // Check for suspicious inline script content
      const scriptContent = script.innerText;
      let suspiciousPatternCount = 0;
      
      if (/eval\s*\(/.test(scriptContent)) suspiciousPatternCount++;
      if (/document\.cookie/.test(scriptContent)) suspiciousPatternCount++;
      if (/window\.location/.test(scriptContent)) suspiciousPatternCount++;
      if (/\\x[0-9a-f]{2}/.test(scriptContent)) suspiciousPatternCount++;
      if (/String\.fromCharCode/.test(scriptContent)) suspiciousPatternCount++;
      
      if (suspiciousPatternCount >= 2) {
        sourceAnalysis.threatIndicators.push('suspiciousInlineScript');
        sourceAnalysis.riskScore += 15;
        sourceAnalysis.threatDetails.scripts.suspicious++;
      }
    }
  });
  
  // Cap risk score at 100
  sourceAnalysis.riskScore = Math.min(100, sourceAnalysis.riskScore);
  
  // Store results for popup to access
  chrome.runtime.sendMessage({
    action: 'sourceCodeAnalysisResult',
    data: sourceAnalysis
  });
  
  return sourceAnalysis;
}

// Run analysis when page loads
const analysisResult = analyzeSourceCode();

// Listen for requests from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeSourceCode') {
    const result = analyzeSourceCode();
    sendResponse(result);
    return true;
  }
});

// Periodically check for DOM changes that might indicate phishing
const observer = new MutationObserver((mutations) => {
  // Re-analyze if significant changes (new forms, scripts, etc.)
  for (const mutation of mutations) {
    if (mutation.addedNodes.length > 0) {
      for (const node of mutation.addedNodes) {
        if (node.nodeName === 'FORM' || node.nodeName === 'SCRIPT' || 
            (node.nodeType === 1 && (node.querySelector('form') || node.querySelector('script')))) {
          const updatedAnalysis = analyzeSourceCode();
          // Only notify if risk increased
          if (updatedAnalysis.riskScore > analysisResult.riskScore + 10) {
            chrome.runtime.sendMessage({
              action: 'sourceCodeThreatUpdated',
              data: updatedAnalysis
            });
          }
          break;
        }
      }
    }
  }
});

// Watch for DOM changes
observer.observe(document.body, { childList: true, subtree: true });
