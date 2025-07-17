// Background script for the Layered Phishing Detector extension

chrome.runtime.onInstalled.addListener(() => {
  console.log('Layered Phishing Detector extension installed');
  console.log('Using multi-layer detection: Basic Validation + Feature Analysis + ML + Ensemble Decision');
});

// Context menu for quick layered analysis
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "analyzeUrl",
    title: "Analyze with layered phishing detection",
    contexts: ["link"]
  });
  
  chrome.contextMenus.create({
    id: "analyzeDetailedUrl", 
    title: "Detailed layered analysis",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "analyzeUrl" || info.menuItemId === "analyzeDetailedUrl") {
    const url = info.linkUrl;
    console.log("Background: Analyzing URL with layered detection:", url);
    
    try {
      // Call the layered detection API
      const endpoint = info.menuItemId === "analyzeDetailedUrl" ? 
        'http://localhost:5000/analyze_detailed' : 
        'http://localhost:5000/check_url';
      
      let response;
      if (info.menuItemId === "analyzeDetailedUrl") {
        response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url })
        });
      } else {
        response = await fetch(`${endpoint}?url=${encodeURIComponent(url)}`);
      }
      
      const result = await response.json();
      console.log("Layered detection result:", result);
      
      // Show notification with result
      const verdict = result.verdict || result.final_result?.verdict || 'Unknown';
      const riskPct = result.risk_percentage || result.final_result?.risk_percentage || 0;
      
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png',
        title: 'Layered Phishing Detection',
        message: `${url}\nVerdict: ${verdict}\nRisk: ${riskPct.toFixed(1)}%`
      });
      
    } catch (error) {
      console.error("Background: Layered detection failed:", error);
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon48.png', 
        title: 'Layered Phishing Detection',
        message: `Analysis failed: ${error.message}`
      });
    }
  }
});

// Listen for messages from popup (layered detection specific)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeUrlLayered") {
    console.log("Background: Received layered analysis request for:", request.url);
    sendResponse({
      status: "received", 
      system: "layered_detection",
      layers: ["Basic Validation", "Feature Analysis", "ML Classification", "Ensemble Decision", "Final Verdict"]
    });
  }
  
  if (request.action === "getDetectionInfo") {
    sendResponse({
      system: "Layered Phishing Detection System",
      version: "3.0",
      layers: 5,
      ml_model: "RandomForest/XGBoost",
      accuracy: "81.47%",
      features: ["URL Analysis", "Domain Features", "ML Prediction", "Ensemble Voting"]
    });
  }
});

// Store the latest source code analysis result
let latestSourceCodeAnalysis = null;

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Store source code analysis from content script
  if (message.action === 'sourceCodeAnalysisResult' || message.action === 'sourceCodeThreatUpdated') {
    latestSourceCodeAnalysis = message.data;
  }
  
  // Return stored analysis to popup when requested
  if (message.action === 'getSourceCodeAnalysis') {
    sendResponse({data: latestSourceCodeAnalysis});
    return true;
  }
});

// Reset the analysis when navigating to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    latestSourceCodeAnalysis = null;
  }
});

// Add badge text to show detection system status
chrome.action.setBadgeText({text: "AI"});
chrome.action.setBadgeBackgroundColor({color: "#667eea"});

// Complete the background.js with enhanced download protection
chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
  console.log('Download intercepted:', downloadItem);
  
  if (!DOWNLOAD_PROTECTION_CONFIG.enabled) {
    suggest();
    return;
  }
  
  // Store download for analysis
  const downloadId = downloadItem.id;
  pendingDownloads.set(downloadId, {
    item: downloadItem,
    suggest: suggest,
    timestamp: Date.now()
  });
  
  // Analyze the download
  analyzeDownload(downloadItem, suggest);
});

// Add real-time URL monitoring
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    // Quick analysis of new URLs
    performQuickThreatCheck(changeInfo.url, tabId);
  }
});

// Real-time phishing detection for form submissions
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.method === 'POST' && details.requestBody) {
      // Check if sensitive data is being submitted to suspicious domains
      checkFormSubmission(details);
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Enhanced notification system
function showAdvancedNotification(type, data) {
  const notifications = {
    'phishing_detected': {
      title: '🚨 Phishing Site Detected',
      message: `Blocked access to suspicious site: ${data.domain}`,
      iconUrl: 'icons/warning.png'
    },
    'download_blocked': {
      title: '🛡️ Dangerous Download Blocked',
      message: `Prevented download of ${data.filename}`,
      iconUrl: 'icons/shield.png'
    },
    'credential_theft': {
      title: '⚠️ Credential Theft Attempt',
      message: 'Login form detected on suspicious site',
      iconUrl: 'icons/alert.png'
    }
  };
  
  chrome.notifications.create(notifications[type]);
}
