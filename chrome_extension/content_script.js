/**
 * Content Script for Phishing Guard Pro
 * Analyzes page source code for phishing indicators with reduced false positives
 */

// Define suspicious patterns to look for in source code
const SUSPICIOUS_PATTERNS = {
  obfuscatedJS: /eval\s*\(\s*(\w+|['"][^'"]+['"])\s*\)|String\.fromCharCode\(.*\d+.*\d+.*\)|\\x[0-9a-f]{2}[^'"]*\\x[0-9a-f]{2}|\bunescape\s*\(\s*['"][%][0-9a-f]{2}/i,
  hiddenElements: /style\s*=\s*["'](?:[^"']*(?:visibility\s*:\s*hidden|display\s*:\s*none|opacity\s*:\s*0)[^"']*)/i,
  passwordFieldsInHiddenElements: /<input[^>]*type\s*=\s*["']password["'][^>]*>[^<]*<[^>]*style\s*=\s*["'][^"']*(?:visibility\s*:\s*hidden|display\s*:\s*none|opacity\s*:\s*0)/i,
  externalForms: /<form[^>]*action\s*=\s*["'](https?:\/\/(?!(?:.*?\.)?window\.location\.hostname)[^"']+)["'][^>]*>/i,
  documentWriteLongString: /document\.write\([^)]{100,}\)/i
};

// List of known legitimate brand domains and their subdomains
const LEGITIMATE_BRANDS = {
  "instagram.com": ["www", "about", "help", "business", "developers"],
  "facebook.com": ["www", "business", "developers", "m"],
  "google.com": ["www", "mail", "docs", "drive", "calendar", "photos", "accounts"],
  "microsoft.com": ["www", "account", "office", "products", "login"],
  "apple.com": ["www", "support", "developer", "id"],
  "amazon.com": ["www", "smile", "aws", "pay", "music"],
  "paypal.com": ["www", "developer", "checkout"],
  "twitter.com": ["www", "mobile", "api", "business"],
  "linkedin.com": ["www", "business", "developer", "learning"],
  "youtube.com": ["www", "studio", "music", "tv"]
};

// Function to check if the current site is a legitimate brand site
function isLegitimateWebsite(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    // Check against our list of legitimate domains
    for (const [domain, subdomains] of Object.entries(LEGITIMATE_BRANDS)) {
      // Direct match with main domain
      if (hostname === domain) {
        return {legitimate: true, brand: domain.split('.')[0]};
      }
      
      // Check for subdomain matches
      if (hostname.endsWith(`.${domain}`)) {
        const subdomain = hostname.split(`.${domain}`)[0];
        
        // Check if it's a known subdomain or follows the pattern
        if (subdomains.includes(subdomain) || 
            // Common legitimate subdomain patterns
            /^(www\d*|m|mobile|login|account|secure|mail)$/.test(subdomain)) {
          return {legitimate: true, brand: domain.split('.')[0]};
        }
      }
    }
    
    // Check for very common legitimate TLDs
    if (/\.(gov|edu|ac\.uk|edu\.[a-z]{2})$/.test(hostname)) {
      return {legitimate: true, brand: hostname.split('.')[0]};
    }
    
    // NEW: Check for likely legitimate sites based on domain properties
    const domainParts = hostname.split('.');
    const mainDomain = domainParts.length >= 2 ? 
      `${domainParts[domainParts.length-2]}.${domainParts[domainParts.length-1]}` : hostname;
    
    // Less than 20 chars, no numbers, no hyphens = likely legitimate main domain
    if (mainDomain.length < 20 && 
        !/\d/.test(mainDomain) && 
        !/-{2,}/.test(mainDomain) && 
        !/^xn--/.test(mainDomain) && // Not punycode 
        !/^[0-9.]+$/.test(mainDomain) && // Not an IP address
        document.title && document.title.length > 0) {  // Has a title
      // Check if page has consistent content (not just login form)
      const contentAmount = document.body.innerText.length;
      const headingsCount = document.querySelectorAll('h1, h2, h3').length;
      const linksCount = document.querySelectorAll('a').length;
      
      if (contentAmount > 500 && headingsCount > 0 && linksCount > 2) {
        return {legitimate: true, brand: null, likelyLegitimate: true};
      }
    }
    
    // Not a known legitimate brand
    return {legitimate: false, brand: null};
  } catch (error) {
    console.error("Error checking legitimacy:", error);
    return {legitimate: false, brand: null, error: true};
  }
}

// Check for suspicious form behaviors
function checkForSuspiciousForms() {
  const forms = document.forms;
  let suspiciousFormCount = 0;
  let credentialStealingForms = 0;
  let passwordFieldsCount = 0;
  
  for (const form of forms) {
    const formAction = form.action || '';
    const passwordFields = form.querySelectorAll('input[type="password"]');
    passwordFieldsCount += passwordFields.length;
    
    if (passwordFields.length > 0) {
      // Check if form submits to external domain
      if (formAction && formAction.startsWith('http')) {
        try {
          const currentDomain = window.location.hostname;
          const actionDomain = new URL(formAction).hostname;
          
          if (actionDomain !== currentDomain) {
            // Different domain submission with password fields is suspicious
            suspiciousFormCount++;
            
            // If domains are completely unrelated (not subdomains)
            if (!actionDomain.endsWith(currentDomain) && !currentDomain.endsWith(actionDomain)) {
              credentialStealingForms++;
            }
          }
        } catch (e) {
          // URL parsing failed
        }
      }
      
      // Check for suspicious field attributes
      for (const field of form.elements) {
        // Autocomplete disabled is suspicious for login forms
        if (field.getAttribute('autocomplete') === 'off' && 
            (field.type === 'password' || field.name?.toLowerCase().includes('user') || 
             field.id?.toLowerCase().includes('user'))) {
          suspiciousFormCount++;
        }
        
        // Hidden username fields (often used in phishing)
        if (field.type !== 'password' && 
            (field.name?.toLowerCase().includes('user') || field.name?.toLowerCase().includes('email')) && 
            field.type === 'hidden') {
          suspiciousFormCount++;
        }
      }
    }
  }
  
  return {
    passwordFieldsCount,
    suspiciousFormCount,
    credentialStealingForms
  };
}

// Analyze page source code for threats
function analyzeSourceCode() {
  const pageSource = document.documentElement.outerHTML;
  const url = window.location.href;
  const domain = window.location.hostname;
  
  // Check if this is a known legitimate site first
  const brandCheck = isLegitimateWebsite(url);
  
  // Results object
  const sourceAnalysis = {
    url: url,
    domain: domain,
    threatIndicators: [],
    riskScore: 0,
    sensitiveFormPresent: false,
    externalSubmission: false,
    threatDetails: {},
    isLegitimate: brandCheck.legitimate || brandCheck.likelyLegitimate,
    brandName: brandCheck.brand
  };
  
  // If site is recognized as legitimate brand, lower the initial risk
  let legitimacyDiscount = 0;
  if (sourceAnalysis.isLegitimate) {
    // Still check for specific threats but with higher threshold
    legitimacyDiscount = brandCheck.legitimate ? 30 : 20;  // Discount for legitimate brands
  }
  
  // Check for suspicious patterns - only count them if they appear multiple times
  // or in specific combinations to reduce false positives
  for (const [key, pattern] of Object.entries(SUSPICIOUS_PATTERNS)) {
    const matches = (pageSource.match(pattern) || []).length;
    
    if (matches >= 2 || (key === 'externalForms' && matches > 0)) {  // Higher threshold
      sourceAnalysis.threatIndicators.push(key);
      sourceAnalysis.riskScore += 15; // 15 points per suspicious pattern
    }
  }
  
  // Check for form issues
  const formAnalysis = checkForSuspiciousForms();
  sourceAnalysis.threatDetails.forms = formAnalysis;
  
  // Only consider as a threat if there are multiple suspicious forms
  // or credential stealing forms
  if (formAnalysis.suspiciousFormCount >= 2) {
    sourceAnalysis.threatIndicators.push('multipleSuspiciousForms');
    sourceAnalysis.riskScore += 15;
  }
  
  if (formAnalysis.credentialStealingForms > 0) {
    sourceAnalysis.threatIndicators.push('credentialStealingForms');
    sourceAnalysis.riskScore += 25;
    sourceAnalysis.externalSubmission = true;
  }
  
  if (formAnalysis.passwordFieldsCount > 0) {
    sourceAnalysis.sensitiveFormPresent = true;
  }
  
  // Check for hidden elements - only count if excessive
  const hiddenElements = document.querySelectorAll(
    '[style*="display: none"], [style*="visibility: hidden"], [style*="opacity: 0"]'
  );
  sourceAnalysis.threatDetails.hiddenElements = hiddenElements.length;
  
  // Check for hidden fields inside forms specifically
  const hiddenFieldsInForms = Array.from(document.forms).reduce((count, form) => {
    return count + form.querySelectorAll('[style*="display: none"], [style*="visibility: hidden"], [style*="opacity: 0"]').length;
  }, 0);
  
  if (hiddenFieldsInForms >= 3) {  // Only flag if multiple hidden elements in forms
    sourceAnalysis.threatIndicators.push('hiddenFormElements');
    sourceAnalysis.riskScore += 15;
  }
  
  // Check scripts - only consider as threat if there are multiple suspicious patterns
  const scripts = document.querySelectorAll('script');
  sourceAnalysis.threatDetails.scripts = {
    count: scripts.length,
    inline: 0,
    external: 0,
    suspicious: 0
  };
  
  let totalSuspiciousPatterns = 0;
  
  scripts.forEach(script => {
    if (script.src) {
      sourceAnalysis.threatDetails.scripts.external++;
      // Check if script is from external domain
      try {
        const scriptDomain = new URL(script.src).hostname;
        if (scriptDomain !== domain && 
            !scriptDomain.includes('google') && 
            !scriptDomain.includes('facebook') && 
            !scriptDomain.includes('cloudflare')) {
          // Count external scripts from unknown sources, but don't necessarily mark them as threats
          // as many legitimate sites use CDNs and third-party scripts
          sourceAnalysis.threatDetails.scripts.external++;
        }
      } catch (e) {
        // Invalid URL in src
      }
    } else if (script.innerText) {
      sourceAnalysis.threatDetails.scripts.inline++;
      // Check for suspicious inline script content
      const scriptContent = script.innerText;
      let suspiciousPatternCount = 0;
      
      if (/eval\s*\(\s*(\w+|['"][^'"]{20,}['"])\s*\)/.test(scriptContent)) suspiciousPatternCount++;
      if (/document\.cookie.*?[=;]/.test(scriptContent)) suspiciousPatternCount++;
      if (/location\.replace\s*\(/.test(scriptContent)) suspiciousPatternCount++;
      if (/\\x[0-9a-f]{2}.*?\\x[0-9a-f]{2}/.test(scriptContent)) suspiciousPatternCount++;
      if (/String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+/.test(scriptContent)) suspiciousPatternCount++;
      
      totalSuspiciousPatterns += suspiciousPatternCount;
      
      if (suspiciousPatternCount >= 2) {
        sourceAnalysis.threatDetails.scripts.suspicious++;
      }
    }
  });
  
  // Only flag as suspicious if multiple suspicious patterns detected
  if (totalSuspiciousPatterns >= 3 || sourceAnalysis.threatDetails.scripts.suspicious >= 2) {
    sourceAnalysis.threatIndicators.push('suspiciousScripts');
    sourceAnalysis.riskScore += 15;
  }
  
  // Check for iframes from external domains
  const iframes = document.querySelectorAll('iframe');
  const externalIframes = Array.from(iframes).filter(iframe => {
    try {
      const iframeSrc = iframe.src;
      if (!iframeSrc) return false;
      
      const iframeDomain = new URL(iframeSrc).hostname;
      return iframeDomain && iframeDomain !== domain;
    } catch {
      return false;
    }
  });
  
  sourceAnalysis.threatDetails.externalIframes = externalIframes.length;
  
  // Only consider as a threat if multiple external iframes present
  if (externalIframes.length >= 2) {
    sourceAnalysis.threatIndicators.push('multipleExternalIframes');
    sourceAnalysis.riskScore += 10;
  }
  
  // Apply legitimacy adjustment
  if (sourceAnalysis.isLegitimate) {
    sourceAnalysis.riskScore = Math.max(0, sourceAnalysis.riskScore - legitimacyDiscount);
    
    // If legitimate brand with low risk score, clear threat indicators
    if (sourceAnalysis.riskScore < 25) {
      // Keep only the most severe threat indicators
      sourceAnalysis.threatIndicators = sourceAnalysis.threatIndicators.filter(
        indicator => ['credentialStealingForms', 'suspiciousScripts'].includes(indicator)
      );
    }
  }
  
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

// Watch for DOM changes that might indicate phishing
// Using a throttled observer to avoid performance issues
let pendingAnalysis = false;
const observer = new MutationObserver((mutations) => {
  // Only trigger reanalysis for significant DOM changes
  if (pendingAnalysis) return;
  
  // Look for significant changes that would warrant reanalysis
  const significantChanges = mutations.some(mutation => {
    if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
      for (const node of mutation.addedNodes) {
        if (node.nodeName === 'FORM' || node.nodeName === 'SCRIPT' || 
            (node.nodeType === 1 && (node.querySelector('form') || node.querySelector('script') || 
             node.querySelector('input[type="password"]')))) {
          return true;
        }
      }
    }
    return false;
  });
  
  if (significantChanges) {
    pendingAnalysis = true;
    
    // Throttle reanalysis to avoid performance issues
    setTimeout(() => {
      const updatedAnalysis = analyzeSourceCode();
      // Only notify if risk increased significantly
      if (updatedAnalysis.riskScore > analysisResult.riskScore + 20) {
        chrome.runtime.sendMessage({
          action: 'sourceCodeThreatUpdated',
          data: updatedAnalysis
        });
      }
      pendingAnalysis = false;
    }, 1000);
  }
});

// Watch for DOM changes with a throttled approach
observer.observe(document.body, { childList: true, subtree: true });
