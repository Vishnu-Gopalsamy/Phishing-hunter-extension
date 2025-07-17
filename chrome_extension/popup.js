document.addEventListener('DOMContentLoaded', async () => {
  const loading = document.getElementById('loading');
  const result = document.getElementById('result');
  const errorDiv = document.getElementById('error');
  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');
  const reason = document.getElementById('reason');
  const details = document.getElementById('details');
  const riskBar = document.getElementById('riskFill');
  const riskText = document.getElementById('riskText');
  const sourceCodeAnalysisDiv = document.getElementById('sourceCodeAnalysis');
  
  // Log elements for debugging
  console.log("Element references:", {
    loading,
    result,
    errorDiv,
    statusIcon,
    statusText,
    reason,
    details,
    riskBar,
    riskText,
    sourceCodeAnalysisDiv
  });
  
  // Replace problematic character at position 1457 with standard quotes
  function showError(msg) {
    if (loading) loading.style.display = 'none';
    if (result) result.style.display = 'none';
    if (errorDiv) {
      errorDiv.style.display = 'block';
      errorDiv.textContent = msg;
    } else {
      console.error('Error:', msg);
    }
  }

  function showLoading() {
    if (loading) loading.style.display = 'block';
    if (result) result.style.display = 'none';
    if (errorDiv) errorDiv.style.display = 'none';
  }

  function showResult(data) {
    if (!data) {
      showError('Invalid or empty response data');
      return;
    }
    
    if (loading) loading.style.display = 'none';
    if (result) result.style.display = 'block';
    if (errorDiv) errorDiv.style.display = 'none';
    
    const isSafe = data.safe;
    const isLegitimateWebsite = data.is_legitimate_brand;
    
    if (isSafe) {
      if (statusIcon) statusIcon.textContent = '✅';
      if (statusText) {
        statusText.textContent = isLegitimateWebsite ? 'Legitimate Brand' : 'Safe';
        statusText.className = 'status-safe';
      }
    } else {
      if (statusIcon) statusIcon.textContent = '⚠️';
      if (statusText) {
        statusText.textContent = 'Warning';
        statusText.className = 'status-warning';
      }
    }
    
    if (reason) reason.textContent = data.reason || 'No details available';
    
    // Set risk level bar
    const riskPercentage = data.risk_percentage || 0;
    if (riskBar) riskBar.style.width = `${riskPercentage}%`;
    if (riskText) riskText.textContent = `${Math.round(riskPercentage)}%`;
    
    // Set color based on risk and legitimacy
    if (riskBar) {
      if (isLegitimateWebsite && riskPercentage < 60) {
        // Lower risk threshold for legitimate brands
        riskBar.className = 'risk-fill low-risk';
      } else if (riskPercentage > 75) {
        riskBar.className = 'risk-fill high-risk';
      } else if (riskPercentage > 40) {
        riskBar.className = 'risk-fill medium-risk';
      } else {
        riskBar.className = 'risk-fill low-risk';
      }
    }
    
    // Add brand verification badge if it's a legitimate site
    if (result && isLegitimateWebsite) {
      const verifiedBadge = document.createElement('div');
      verifiedBadge.className = 'verified-badge';
      verifiedBadge.innerHTML = '✓ Verified Brand Site';
      
      // Insert badge after the header
      const header = result.querySelector('.header');
      if (header && header.nextSibling) {
        result.insertBefore(verifiedBadge, header.nextSibling);
      }
    }
    
    // If site is likely legitimate but not specifically whitelisted, show that
    if (result && data.is_likely_legitimate && !data.is_legitimate_brand) {
      const likelyLegitBadge = document.createElement('div');
      likelyLegitBadge.className = 'likely-legitimate-badge';
      likelyLegitBadge.innerHTML = 'Likely Safe Site';
      
      // Insert badge after the header
      const header = result.querySelector('.header');
      if (header && header.nextSibling) {
        result.insertBefore(likelyLegitBadge, header.nextSibling);
      }
    }
    
    // Additional warnings for high-risk cases - but only if not a legitimate brand site
    // or if it's an exceptionally high risk score
    if (result && ((riskPercentage >= 60 && !data.is_legitimate_brand && !data.is_likely_legitimate) || 
        (riskPercentage >= 80) || // Very high risk even for legit sites
        (data.ml_prediction === 'phishing' && data.ml_confidence > 0.8))) {
      // Add visual warning
      const warningDiv = document.createElement('div');
      warningDiv.className = 'high-risk-warning';
      warningDiv.innerHTML = 'HIGH RISK DETECTED - Exercise extreme caution!';
      result.insertBefore(warningDiv, result.firstChild);
    }
    
    // Request source code analysis
    requestSourceCodeAnalysis();
  }
  
  // New function to handle source code analysis results with special handling for brands
  function showSourceCodeAnalysis(analysisData) {
    if (!sourceCodeAnalysisDiv) return;
    
    // Create or update source code analysis section
    sourceCodeAnalysisDiv.innerHTML = '';
    sourceCodeAnalysisDiv.style.display = 'block';
    
    // Create header
    const header = document.createElement('h3');
    header.textContent = 'Page Analysis';
    sourceCodeAnalysisDiv.appendChild(header);
    
    // If site is recognized as a legitimate brand, show that first
    if (analysisData.isLegitimate) {
      const brandInfo = document.createElement('div');
      brandInfo.className = 'brand-info';
      
      if (analysisData.brandName) {
        brandInfo.innerHTML = `<strong>✓ Recognized ${analysisData.brandName} site</strong>`;
      } else {
        brandInfo.innerHTML = `<strong>✓ Likely legitimate site</strong>`;
      }
      
      sourceCodeAnalysisDiv.appendChild(brandInfo);
      
      // If no significant threats were found on the legitimate site, show that
      if (analysisData.threatIndicators.length === 0 || 
          (analysisData.threatIndicators.length === 1 && analysisData.riskScore < 20)) {
        const safeInfo = document.createElement('p');
        safeInfo.textContent = 'No suspicious code patterns detected';
        safeInfo.className = 'safe-info';
        sourceCodeAnalysisDiv.appendChild(safeInfo);
        return;
      }
    }
    
    // Add threat indicators if any
    if (analysisData.threatIndicators && analysisData.threatIndicators.length > 0) {
      const threatList = document.createElement('ul');
      threatList.className = 'threat-list';
      
      // Map threat codes to user-friendly descriptions
      const threatMapping = {
        'obfuscatedJS': 'Obfuscated JavaScript detected',
        'hiddenElements': 'Hidden elements present',
        'externalFormSubmission': 'Form submits to external domain',
        'credentialStealingForms': 'Potential credential stealing',
        'hiddenFormElements': 'Hidden elements in forms',
        'suspiciousScripts': 'Suspicious scripts detected',
        'passwordFieldsInHiddenElements': 'Password fields in hidden elements',
        'documentWriteLongString': 'Dynamically written content',
        'multipleSuspiciousForms': 'Multiple suspicious forms',
        'multipleExternalIframes': 'Multiple external frames'
      };
      
      // Only show the most important threats (up to 3)
      const priorityOrder = [
        'credentialStealingForms', 
        'passwordFieldsInHiddenElements',
        'suspiciousScripts',
        'obfuscatedJS',
        'externalFormSubmission',
        'hiddenFormElements'
      ];
      
      // Sort threats by priority
      const sortedThreats = [...analysisData.threatIndicators].sort((a, b) => {
        const indexA = priorityOrder.indexOf(a);
        const indexB = priorityOrder.indexOf(b);
        return (indexA === -1 ? 999 : indexA) - (indexB === -1 ? 999 : indexB);
      });
      
      // Show at most 3 threats
      const threatsToShow = sortedThreats.slice(0, 3);
      
      threatsToShow.forEach(threat => {
        const item = document.createElement('li');
        item.className = 'threat-item';
        item.textContent = threatMapping[threat] || threat;
        threatList.appendChild(item);
      });
      
      if (threatsToShow.length > 0) {
        sourceCodeAnalysisDiv.appendChild(threatList);
      }
      
      // Add warning if high risk
      // Adjust threshold based on whether it's a legitimate site
      const riskThreshold = analysisData.isLegitimate ? 60 : 40;
      if (analysisData.riskScore > riskThreshold) {
        const warning = document.createElement('div');
        warning.className = 'source-code-warning';
        warning.textContent = `Suspicious code detected (Risk: ${analysisData.riskScore}/100)`;
        sourceCodeAnalysisDiv.appendChild(warning);
      }
    } else {
      // No threats found
      const noThreats = document.createElement('p');
      noThreats.textContent = 'No suspicious code patterns detected';
      noThreats.className = 'safe-info';
      sourceCodeAnalysisDiv.appendChild(noThreats);
    }
    
    // Add details if available
    if (analysisData.threatDetails && (
        (analysisData.threatDetails.forms && analysisData.threatDetails.forms.passwordFieldsCount > 0) || 
        (analysisData.threatDetails.scripts && analysisData.threatDetails.scripts.suspicious > 0))
    ) {
      const details = document.createElement('div');
      details.className = 'code-details';
      
      if (analysisData.threatDetails.forms) {
        const formInfo = document.createElement('p');
        formInfo.textContent = `Forms: ${analysisData.threatDetails.forms.passwordFieldsCount > 0 ? 
          `Contains ${analysisData.threatDetails.forms.passwordFieldsCount} password fields` : 'No password fields'}`;
        
        if (analysisData.threatDetails.forms.credentialStealingForms > 0) {
          formInfo.textContent += ` - Submits to external domain`;
          formInfo.className = 'warning-detail';
        }
        details.appendChild(formInfo);
      }
      
      if (analysisData.threatDetails.scripts && analysisData.threatDetails.scripts.suspicious > 0) {
        const scriptInfo = document.createElement('p');
        scriptInfo.className = 'warning-detail';
        scriptInfo.textContent = `${analysisData.threatDetails.scripts.suspicious} suspicious scripts detected`;
        details.appendChild(scriptInfo);
      }
      
      if (details.childNodes.length > 0) {
        sourceCodeAnalysisDiv.appendChild(details);
      }
    }
  }
  
  // Function to request source code analysis from content script
  function requestSourceCodeAnalysis() {
    if (!sourceCodeAnalysisDiv) return;
    
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      if (!tabs || !tabs.length) return;
      
      const activeTab = tabs[0];
      
      // First try to see if we already have analysis results
      chrome.runtime.sendMessage({action: 'getSourceCodeAnalysis'}, (response) => {
        if (response && response.data) {
          showSourceCodeAnalysis(response.data);
        } else {
          // Request new analysis from content script
          chrome.tabs.sendMessage(activeTab.id, {action: 'analyzeSourceCode'}, (response) => {
            if (response) {
              showSourceCodeAnalysis(response);
            } else if (sourceCodeAnalysisDiv) {
              // Content script may not be loaded or accessible
              sourceCodeAnalysisDiv.innerHTML = '<p>Source code analysis not available for this page</p>';
            }
          });
        }
      });
    });
  }

  // First check if server is running
  async function checkServerHealth() {
    try {
        console.log("Checking server health...");
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout
        
        const healthResponse = await fetch('http://localhost:5000/health', {
            signal: controller.signal,
            mode: 'cors',  // Explicitly set CORS mode
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });
        
        clearTimeout(timeoutId);
        
        if (!healthResponse.ok) {
            throw new Error(`Server health check failed: ${healthResponse.status}`);
        }
        
        const healthData = await healthResponse.json();
        console.log("Server health check response:", healthData);
        
        if (!healthData.detector_loaded) {
            throw new Error("Phishing detector not properly initialized");
        }
        
        return true;
    } catch (healthError) {
        console.error("Server health check failed:", healthError);
        showError(`Server connection failed. Please ensure the API server is running at http://localhost:5000\n\nError: ${healthError.message}`);
        return false;
    }
  }

  // Update the URL analysis function
  async function analyzeUrl(url) {
    try {
        console.log("Sending analysis request for URL:", url);
        const response = await fetch(`http://localhost:5000/check_url?url=${encodeURIComponent(url)}`, {
            method: 'GET',
            mode: 'cors',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }

        const data = await response.json();
        console.log("Analysis response:", data);
        return data;
    } catch (error) {
        console.error("Analysis request failed:", error);
        throw error;
    }
  }

  // Update the main analysis flow
  async function initializeAnalysis() {
    showLoading();
    
    try {
        console.log("Extension popup loaded, checking server...");
        const serverReady = await checkServerHealth();
        if (!serverReady) {
            console.error("Server not ready");
            return;
        }

        let tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tabs || !tabs.length) {
            showError('No active tab found');
            return;
        }
        
        let tab = tabs[0];
        if (!tab || !tab.url) {
            showError('Cannot access tab URL');
            return;
        }
        
        let url = tab.url;
        
        console.log("Analyzing current tab URL:", url);
        
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            showError('Can only analyze HTTP/HTTPS URLs');
            return;
        }

        const analysisResult = await analyzeUrl(url);
        showResult(analysisResult);
        
    } catch (error) {
        console.error("Analysis failed:", error);
        showError(`Analysis failed: ${error.message}`);
    }
  }
  
  // Call the initialization function when DOM is loaded
  initializeAnalysis();

  // Listen for source code analysis results from content script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'sourceCodeAnalysisResult' || message.action === 'sourceCodeThreatUpdated') {
      showSourceCodeAnalysis(message.data);
    }
    return true;
  });
});

// Enhanced detailed analysis with dramatic effects
document.addEventListener('click', async (e) => {
  if (e.target.id === 'detailedAnalysis') {
    try {
      // Dramatic button transformation
      e.target.textContent = 'INITIATING DEEP SCAN...';
      e.target.style.background = 'linear-gradient(45deg, #ff4444, #ff0066)';
      e.target.style.animation = 'criticalWarning 0.5s ease-in-out infinite alternate';
      
      let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      let url = tab.url;
      
      console.log('🔍 DEEP SCAN PROTOCOL ACTIVATED:', url);
      
      const response = await fetch('http://localhost:5000/analyze_detailed', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
      });
      
      const data = await response.json();
      console.log('📊 DEEP SCAN RESULTS:', data);
      
      // Update UI with dramatic layer results
      if (data.layer_results) {
        displayLayerResults(data.layer_results);
        
        // Dramatic completion
        e.target.textContent = 'SCAN COMPLETE';
        e.target.style.background = 'linear-gradient(45deg, #00ff88, #00aa44)';
        e.target.style.animation = 'safeGlow 2s ease-in-out infinite alternate';
        e.target.disabled = true;
        
        // Show additional detailed info matching final verdict logic
        const additionalInfo = document.getElementById('additionalInfo');
        if (additionalInfo && data.final_result) {
          const finalResult = data.final_result;
          additionalInfo.innerHTML = `
            <div class="additional-details">
              <h4>Enhanced Detection Results:</h4>
              <p><strong>Processing Time:</strong> ${(data.processing_time * 1000).toFixed(1)}ms</p>
              <p><strong>Total Layers:</strong> ${data.layer_results.length}</p>
              <p><strong>ML Weight:</strong> 1.5x (Enhanced for phishing detection)</p>
              <p><strong>Consensus:</strong> ${data.ensemble_result?.consensus || 'N/A'}</p>
              ${finalResult.recommendations ? 
                `<div class="recommendations">
                  <strong>Security Recommendations:</strong>
                  ${finalResult.recommendations.slice(0, 3).map(rec => `<div>• ${rec}</div>`).join('')}
                </div>` : ''
              }
              ${data.ensemble_result?.conflicts?.length > 0 ?
                `<div class="conflicts">
                  <strong>Layer Conflicts:</strong>
                  ${data.ensemble_result.conflicts.map(conflict => `<div>⚠️ ${conflict}</div>`).join('')}
                </div>` : ''
              }
            </div>
          `;
          additionalInfo.style.display = 'block';
        }
      }
      
    } catch (error) {
      console.error('🚨 DEEP SCAN FAILURE:', error);
      e.target.textContent = 'SCAN FAILED';
      e.target.style.background = 'linear-gradient(45deg, #666, #333)';
      e.target.style.animation = 'errorShake 0.5s ease-in-out';
    }
  }
});

// Enhanced layer results display with content analysis
function displayLayerResults(layers) {
  const layerResults = document.getElementById('layerResults');
  if (!layerResults) return;
  
  layerResults.innerHTML = '<h4 style="color: #ffffff; font-family: Orbitron, monospace; text-align: center; margin-bottom: 16px; text-shadow: 0 0 10px #667eea;">🔍 ADVANCED THREAT ANALYSIS 🔍</h4>';
  
  layers.forEach((layer, index) => {
    const layerDiv = document.createElement('div');
    layerDiv.className = 'layer-result';
    
    const riskLevel = layer.risk_score || 0;
    const layerWeight = layer.weight || 1.0;
    
    // Dramatic risk level colors and effects
    let riskColor = '#00ff88'; // Safe
    let riskLabel = 'SECURE';
    let riskIcon = '✅';
    
    if (riskLevel >= 75) {
      riskColor = '#ff0066';
      riskLabel = 'CRITICAL';
      riskIcon = '☠️';
    } else if (riskLevel >= 60) {
      riskColor = '#ff4444';
      riskLabel = 'DANGER';
      riskIcon = '🚨';
    } else if (riskLevel >= 35) {
      riskColor = '#ffaa00';
      riskLabel = 'SUSPICIOUS';
      riskIcon = '⚠️';
    } else if (riskLevel >= 15) {
      riskColor = '#88ff00';
      riskLabel = 'LOW RISK';
      riskIcon = '🟡';
    }
    
    let contentAnalysisHTML = '';
    
    // Add content analysis details for Layer 6
    if (layer.layer === 'Website Content Analysis' && layer.content_analysis) {
      const content = layer.content_analysis;
      const ssl = layer.ssl_info;
      const forms = layer.form_analysis;
      const js = layer.js_analysis;
      
      contentAnalysisHTML = `
        <div style="margin-top: 8px; padding: 8px; background: rgba(0,170,255,0.1); border-radius: 4px; border-left: 3px solid #00aaff;">
          <strong style="color: #00aaff;">🌐 WEBSITE SCAN RESULTS:</strong>
          ${ssl.has_ssl ? '🔒 SSL Certificate Valid' : '⚠️ No SSL/Invalid Certificate'}
          ${content.phishing_keywords_found?.length > 0 ? `<br>🚨 Phishing Keywords: ${content.phishing_keywords_found.length}` : ''}
          ${forms.form_count > 0 ? `<br>📝 Forms Detected: ${forms.form_count}` : ''}
          ${forms.sensitive_forms?.length > 0 ? `<br>🔐 Sensitive Data Collection: ${forms.sensitive_forms.length} forms` : ''}
          ${forms.external_submission ? '<br>⚠️ Data Forwarded to External Domain' : ''}
          ${forms.insecure_submission ? '<br>🚨 Insecure Form Submission (HTTP)' : ''}
          ${js.suspicious_patterns?.length > 0 ? `<br>⚙️ Suspicious JavaScript: ${js.suspicious_patterns.length} patterns` : ''}
          ${js.obfuscation_detected ? '<br>🕵️ Code Obfuscation Detected' : ''}
          ${js.data_collection ? '<br>📊 Data Collection Code Found' : ''}
        </div>
      `;
    }
    
    layerDiv.innerHTML = `
      <div class="layer-header">
        <span class="layer-name">${riskIcon} LAYER ${index + 1}: ${layer.layer.toUpperCase()}</span>
        <span class="layer-risk" style="color: ${riskColor}">
          ${riskLevel.toFixed(1)}% (${riskLabel})
        </span>
      </div>
      <div style="font-size: 0.75em; color: rgba(255,255,255,0.7); margin-bottom: 6px;">
        ANALYSIS WEIGHT: ${layerWeight}x ${layerWeight > 1.0 ? '(ENHANCED)' : ''}
      </div>
      ${layer.flags && layer.flags.length > 0 ? 
        `<div style="margin-top: 6px;">
          ${layer.flags.map(flag => `<div style="font-size: 0.8em; color: #ff4444; margin-bottom: 2px;">🔍 ${flag.toUpperCase()}</div>`).join('')}
        </div>` : ''
      }
      ${layer.ml_prediction ? 
        `<div style="font-size: 0.8em; color: #00aaff; margin-top: 6px; padding: 6px; background: rgba(0,170,255,0.1); border-radius: 4px; border-left: 3px solid #00aaff;">
          <strong>🤖 AI NEURAL NET:</strong> ${layer.ml_prediction.toUpperCase()}
          <br><strong>PROBABILITY:</strong> LEGIT: ${(layer.confidence_scores?.legitimate * 100 || 0).toFixed(1)}%, 
          THREAT: ${(layer.confidence_scores?.phishing * 100 || 0).toFixed(1)}%
          ${layer.inference_time ? `<br><strong>INFERENCE:</strong> ${(layer.inference_time * 1000).toFixed(1)}ms` : ''}
          ${layer.model_info ? `<br><strong>MODEL:</strong> ${layer.model_info.type} (ACC: ${(layer.model_info.accuracy * 100).toFixed(1)}%)` : ''}
        </div>` : ''
      }
      ${contentAnalysisHTML}
    `;
    
    // Add dramatic entrance animation
    layerDiv.style.animation = `fadeInUp 0.5s ease-out ${index * 0.1}s both`;
    
    layerResults.appendChild(layerDiv);
  });
  
  layerResults.style.display = 'block';
}