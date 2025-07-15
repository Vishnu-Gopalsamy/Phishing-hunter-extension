document.addEventListener('DOMContentLoaded', async () => {
  const loading = document.getElementById('loading');
  const result = document.getElementById('result');
  const errorDiv = document.getElementById('error');
  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');
  const reason = document.getElementById('reason');
  const details = document.getElementById('details');
  const riskBar = document.getElementById('riskBar');
  const riskFill = document.getElementById('riskFill');
  const riskText = document.getElementById('riskText');
  const layerResults = document.getElementById('layerResults');

  function showLoading() {
    loading.style.display = 'block';
    result.style.display = 'none';
    errorDiv.style.display = 'none';
  }

  function showResult(data) {
    loading.style.display = 'none';
    result.style.display = 'block';
    errorDiv.style.display = 'none';
    
    const safe = data.safe;
    const riskPercentage = data.risk_percentage || 0;
    const confidence = data.confidence || 0;
    const verdict = data.verdict || 'unknown';
    const mlPrediction = data.ml_prediction;
    const mlConfidence = data.ml_confidence || 0;
    
    // Dramatic status display with enhanced animations
    if (verdict === 'SAFE') {
      if (mlPrediction === 'phishing' && mlConfidence > 0.3) {
        statusIcon.textContent = '⚠️';
        statusIcon.className = 'status-icon status-warning';
        statusText.textContent = 'CAUTION';
        statusText.style.color = '#ffaa00';
        // Add dramatic shake effect
        statusIcon.style.animation = 'warningFlicker 1s ease-in-out infinite';
      } else {
        statusIcon.textContent = '✅';
        statusIcon.className = 'status-icon status-safe';
        statusText.textContent = 'SECURE';
        statusText.style.color = '#00ff88';
        // Add success pulse
        statusIcon.style.animation = 'safeGlow 2s ease-in-out infinite alternate';
      }
    } else if (verdict === 'LOW') {
      if (mlPrediction === 'phishing' && mlConfidence > 0.4) {
        statusIcon.textContent = '⚠️';
        statusIcon.className = 'status-icon status-warning';
        statusText.textContent = 'ML ALERT';
        statusText.style.color = '#ffaa00';
      } else {
        statusIcon.textContent = '🟡';
        statusIcon.className = 'status-icon status-warning';
        statusText.textContent = 'LOW RISK';
        statusText.style.color = '#00ff88';
      }
    } else if (verdict === 'MEDIUM') {
      statusIcon.textContent = '⚠️';
      statusIcon.className = 'status-icon status-warning';
      statusText.textContent = 'SUSPICIOUS';
      statusText.style.color = '#ffaa00';
      // Add warning flicker
      statusIcon.style.animation = 'warningFlicker 1s ease-in-out infinite';
    } else if (verdict === 'HIGH') {
      statusIcon.textContent = '🚨';
      statusIcon.className = 'status-icon status-danger';
      statusText.textContent = 'DANGER';
      statusText.style.color = '#ff4444';
      // Add danger shake
      statusIcon.style.animation = 'dangerShake 0.5s ease-in-out infinite';
    } else if (verdict === 'CRITICAL') {
      statusIcon.textContent = '☠️';
      statusIcon.className = 'status-icon status-critical';
      statusText.textContent = 'CRITICAL THREAT';
      statusText.style.color = '#ff0066';
      // Add critical alert animation
      statusIcon.style.animation = 'criticalAlert 0.3s ease-in-out infinite, criticalGlow 1s ease-in-out infinite';
    } else if (verdict === 'ERROR') {
      statusIcon.textContent = '⚠️';
      statusIcon.className = 'status-icon status-warning';
      statusText.textContent = 'THREAT DETECTED';
      statusText.style.color = '#ff4444';
    } else {
      statusIcon.textContent = '❔';
      statusIcon.className = 'status-icon status-unknown';
      statusText.textContent = 'UNKNOWN';
      statusText.style.color = '#888';
    }
    
    // Dramatic reason text with cyber styling
    let reasonText = data.reason || 'Neural network analysis completed';
    if (mlPrediction && mlConfidence > 0.3) {
      reasonText += ` | AI CONFIDENCE: ${(mlConfidence * 100).toFixed(1)}%`;
    }
    reason.textContent = reasonText.toUpperCase();
    
    // Dramatic risk bar with enhanced effects
    if (riskBar && riskFill && riskText) {
      // Animate the risk bar fill
      setTimeout(() => {
        riskFill.style.width = `${riskPercentage}%`;
      }, 500);
      
      riskText.textContent = `${Math.round(riskPercentage)}% THREAT LEVEL`;
      
      // Enhanced color coding with glow effects
      let fillColor = '#00ff88'; // Safe
      if (riskPercentage >= 75) {
        fillColor = '#ff0066'; // Critical
        riskFill.style.animation = 'criticalGlow 1s ease-in-out infinite';
      } else if (riskPercentage >= 60) {
        fillColor = '#ff4444'; // High
        riskFill.style.animation = 'fillGlow 1.5s ease-in-out infinite';
      } else if (riskPercentage >= 35) {
        fillColor = '#ffaa00'; // Medium
        riskFill.style.animation = 'fillGlow 1.5s ease-in-out infinite';
      } else if (riskPercentage >= 15) {
        fillColor = '#88ff00'; // Low
      }
      
      riskFill.style.background = `linear-gradient(90deg, ${fillColor}, ${fillColor}aa)`;
      riskFill.style.boxShadow = `0 0 20px ${fillColor}66`;
    }
    
    // Enhanced details with cyber styling
    if (details) {
      details.innerHTML = `
        <div class="detail-item">
          <span class="detail-label">SYSTEM:</span>
          <span class="detail-value">LAYERED AI DEFENSE</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">STATUS:</span>
          <span class="detail-value">${verdict}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">THREAT LEVEL:</span>
          <span class="detail-value">${Math.round(riskPercentage)}%</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">CONFIDENCE:</span>
          <span class="detail-value">${(confidence * 100).toFixed(1)}%</span>
        </div>
        ${mlPrediction ? `
        <div class="detail-item">
          <span class="detail-label">AI PREDICTION:</span>
          <span class="detail-value">${mlPrediction.toUpperCase()} (${(mlConfidence * 100).toFixed(1)}%)</span>
        </div>
        ` : ''}
      `;
    }

    // Add dramatic warning for high-risk cases
    if (riskPercentage >= 60 || (mlPrediction === 'phishing' && mlConfidence > 0.6)) {
      const warningDiv = document.createElement('div');
      warningDiv.className = 'high-risk-warning';
      warningDiv.innerHTML = '🚨 THREAT DETECTED - EVACUATE IMMEDIATELY! 🚨';
      result.insertBefore(warningDiv, result.firstChild);
    }

    // Add dramatic sound effect (if permissions allow)
    try {
      if (riskPercentage >= 60) {
        // Could add audio alert here if manifest allows
        console.log('🚨 HIGH THREAT DETECTED - ALERT TRIGGERED');
      }
    } catch (e) {
      // Silent fail for audio
    }
  }

  function displayLayerResults(layers) {
    if (!layerResults) return;
    
    layerResults.innerHTML = '<h4 style="color: #ffffff; font-family: Orbitron, monospace; text-align: center; margin-bottom: 16px; text-shadow: 0 0 10px #667eea;">🔍 DEEP SCAN ANALYSIS 🔍</h4>';
    
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
      
      layerDiv.innerHTML = `
        <div class="layer-header">
          <span class="layer-name">${riskIcon} LAYER ${index + 1}: ${layer.layer.toUpperCase()}</span>
          <span class="layer-risk" style="color: ${riskColor}">
            ${riskLevel.toFixed(1)}% (${riskLabel})
          </span>
        </div>
        <div style="font-size: 0.75em; color: rgba(255,255,255,0.7); margin-bottom: 6px;">
          NEURAL WEIGHT: ${layerWeight}x ${layerWeight > 1.0 ? '(ENHANCED)' : ''}
        </div>
        ${layer.flags && layer.flags.length > 0 ? 
          `<div style="margin-top: 6px;">
            ${layer.flags.map(flag => `<div style="font-size: 0.8em; color: #ff4444; margin-bottom: 2px;">🔍 ${flag.toUpperCase()}</div>`).join('')}
          </div>` : ''
        }
        ${layer.ml_prediction ? 
          `<div style="font-size: 0.8em; color: #00aaff; margin-top: 6px; padding: 6px; background: rgba(0,170,255,0.1); border-radius: 4px; border-left: 3px solid #00aaff;">
            <strong>AI NEURAL NET:</strong> ${layer.ml_prediction.toUpperCase()}
            <br><strong>PROBABILITY:</strong> LEGIT: ${(layer.confidence_scores?.legitimate * 100 || 0).toFixed(1)}%, 
            THREAT: ${(layer.confidence_scores?.phishing * 100 || 0).toFixed(1)}%
            ${layer.inference_time ? `<br><strong>INFERENCE:</strong> ${(layer.inference_time * 1000).toFixed(1)}ms` : ''}
            ${layer.model_info ? `<br><strong>MODEL:</strong> ${layer.model_info.type} (ACC: ${(layer.model_info.accuracy * 100).toFixed(1)}%)` : ''}
          </div>` : ''
        }
      `;
      
      // Add dramatic entrance animation
      layerDiv.style.animation = `fadeInUp 0.5s ease-out ${index * 0.1}s both`;
      
      layerResults.appendChild(layerDiv);
    });
    
    layerResults.style.display = 'block';
  }

  function showError(msg) {
    loading.style.display = 'none';
    result.style.display = 'none';
    errorDiv.style.display = 'block';
    errorDiv.textContent = msg;
  }

  showLoading();

  try {
    // Get current tab URL
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let url = tab.url;
    
    // Skip chrome:// and extension URLs - same as phishing detector
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
        url.startsWith('moz-extension://') || url.startsWith('edge://') ||
        url.startsWith('about:') || url.startsWith('file://')) {
      showError('Cannot analyze browser internal pages or local files');
      return;
    }
    
    // Check if URL is valid - same validation as phishing detector
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      showError('Can only analyze HTTP/HTTPS URLs');
      return;
    }
    
    console.log('🛡️ INITIATING DEEP SCAN PROTOCOL...', url);
    
    // Add dramatic loading message
    const loadingElement = document.querySelector('.spinner');
    if (loadingElement) {
      loadingElement.style.animation = 'spin 0.5s linear infinite, spinnerGlow 1s ease-in-out infinite alternate';
    }
    
    // Call the enhanced API with improved logic
    const response = await fetch(`http://localhost:5000/check_url?url=${encodeURIComponent(url)}`);
    
    if (!response.ok) {
      throw new Error(`Enhanced detection server responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('Enhanced Layered Detection API Response:', data);
    
    if (data.error) {
      showError(`Enhanced Detection Error: ${data.error}`);
    } else {
      showResult(data);
      
      // Additional warning for high-risk cases matching detector logic
      if (data.risk_percentage >= 60 || 
          (data.ml_prediction === 'phishing' && data.ml_confidence > 0.6)) {
        // Add visual warning
        const warningDiv = document.createElement('div');
        warningDiv.className = 'high-risk-warning';
        warningDiv.innerHTML = '🚨 THREAT DETECTED - EVACUATE IMMEDIATELY! 🚨';
        result.insertBefore(warningDiv, result.firstChild);
      }
    }
    
  } catch (error) {
    console.error('🚨 CRITICAL SYSTEM ERROR:', error);
    showError('NEURAL NETWORK CONNECTION FAILED. THREAT ANALYSIS COMPROMISED. MANUAL VERIFICATION REQUIRED.');
  }
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

// Enhanced layer results display with dramatic styling
function displayLayerResults(layers) {
  const layerResults = document.getElementById('layerResults');
  if (!layerResults) return;
  
  layerResults.innerHTML = '<h4 style="color: #ffffff; font-family: Orbitron, monospace; text-align: center; margin-bottom: 16px; text-shadow: 0 0 10px #667eea;">🔍 DEEP SCAN ANALYSIS 🔍</h4>';
  
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
    
    layerDiv.innerHTML = `
      <div class="layer-header">
        <span class="layer-name">${riskIcon} LAYER ${index + 1}: ${layer.layer.toUpperCase()}</span>
        <span class="layer-risk" style="color: ${riskColor}">
          ${riskLevel.toFixed(1)}% (${riskLabel})
        </span>
      </div>
      <div style="font-size: 0.75em; color: rgba(255,255,255,0.7); margin-bottom: 6px;">
        NEURAL WEIGHT: ${layerWeight}x ${layerWeight > 1.0 ? '(ENHANCED)' : ''}
      </div>
      ${layer.flags && layer.flags.length > 0 ? 
        `<div style="margin-top: 6px;">
          ${layer.flags.map(flag => `<div style="font-size: 0.8em; color: #ff4444; margin-bottom: 2px;">🔍 ${flag.toUpperCase()}</div>`).join('')}
        </div>` : ''
      }
      ${layer.ml_prediction ? 
        `<div style="font-size: 0.8em; color: #00aaff; margin-top: 6px; padding: 6px; background: rgba(0,170,255,0.1); border-radius: 4px; border-left: 3px solid #00aaff;">
          <strong>AI NEURAL NET:</strong> ${layer.ml_prediction.toUpperCase()}
          <br><strong>PROBABILITY:</strong> LEGIT: ${(layer.confidence_scores?.legitimate * 100 || 0).toFixed(1)}%, 
          THREAT: ${(layer.confidence_scores?.phishing * 100 || 0).toFixed(1)}%
          ${layer.inference_time ? `<br><strong>INFERENCE:</strong> ${(layer.inference_time * 1000).toFixed(1)}ms` : ''}
          ${layer.model_info ? `<br><strong>MODEL:</strong> ${layer.model_info.type} (ACC: ${(layer.model_info.accuracy * 100).toFixed(1)}%)` : ''}
        </div>` : ''
      }
    `;
    
    // Add dramatic entrance animation
    layerDiv.style.animation = `fadeInUp 0.5s ease-out ${index * 0.1}s both`;
    
    layerResults.appendChild(layerDiv);
  });
  
  layerResults.style.display = 'block';
}