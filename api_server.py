from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import time
import os
import sys
import importlib.util
import re
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure scikit-learn is installed before importing phishing_detector
try:
    import sklearn
    logger.info(f"scikit-learn version: {sklearn.__version__}")
except ImportError:
    logger.error("scikit-learn is not installed. Please install it with: pip install scikit-learn>=1.0.0")
    if input("Attempt to install scikit-learn now? (y/n): ").lower() == 'y':
        import subprocess
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "scikit-learn>=1.0.0"])
            logger.info("scikit-learn installed successfully. Continuing...")
        except Exception as e:
            logger.error(f"Failed to install scikit-learn: {e}")
            sys.exit(1)
    else:
        sys.exit(1)

# Now try to import from phishing_detector
try:
    from phishing_detector import LayeredPhishingDetector, RiskLevel
except ImportError as e:
    logger.error(f"Error importing phishing detector: {e}")
    logger.error("This might be due to missing dependencies or incorrect paths")
    logger.error("Please ensure all dependencies are installed and try again")
    sys.exit(1)

app = Flask(__name__)
CORS(app)

# Initialize the detector globally with retry mechanism
detector = None
MAX_INIT_ATTEMPTS = 3

def initialize_detector():
    """Initialize the layered phishing detector with retries."""
    global detector
    
    for attempt in range(1, MAX_INIT_ATTEMPTS + 1):
        try:
            logger.info(f"Initializing detector (attempt {attempt}/{MAX_INIT_ATTEMPTS})...")
            detector = LayeredPhishingDetector()
            logger.info("✅ Layered phishing detector initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize detector (attempt {attempt}): {e}")
            if attempt < MAX_INIT_ATTEMPTS:
                wait_time = 2 * attempt  # Exponential backoff
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
    
    logger.error(f"Failed to initialize detector after {MAX_INIT_ATTEMPTS} attempts")
    return False

# Initialize detector on startup
if not initialize_detector():
    logger.error("Failed to initialize detector - API will return errors")
    logger.warning("API server will start but detector-dependent endpoints will return errors")

@app.route('/check_url')
def check_url_api():
    """
    Simple API endpoint for Chrome extension compatibility.
    Returns basic safe/unsafe status with reason.
    """
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        if detector is None:
            return jsonify({
                'safe': False, 
                'reason': 'Detection system unavailable'
            }), 500
        
        # Get quick verdict using layered approach
        analysis = detector.analyze_url(url)
        final_result = analysis.get('final_result', {})
        
        # Extract verdict and risk info
        verdict = final_result.get('final_verdict', RiskLevel.ERROR)
        risk_percentage = final_result.get('risk_percentage', 50)
        confidence = final_result.get('confidence', 0)
        
        # Get ML prediction for additional context
        ml_prediction = None
        ml_confidence = 0
        for layer_result in analysis.get('layer_results', []):
            if layer_result.get('layer') == 'ML Classification':
                ml_prediction = layer_result.get('ml_prediction')
                ml_scores = layer_result.get('confidence_scores', {})
                ml_confidence = ml_scores.get('phishing', 0)
                break
        
        # Improved classification logic with LOWER threshold for phishing
        if isinstance(verdict, RiskLevel):
            # More sensitive thresholds
            if verdict in [RiskLevel.SAFE]:
                # Double-check with ML prediction - LOWER THRESHOLD
                if ml_prediction == 'phishing' and ml_confidence > 0.25:  # Was 0.3
                    safe = False
                    reason = f"ML detected phishing risk ({ml_confidence:.2f} confidence) despite low overall risk"
                else:
                    safe = True
                    reason = f"Safe ({risk_percentage:.0f}% risk, {confidence:.2f} confidence)"
            elif verdict in [RiskLevel.LOW]:
                # Be more cautious with low risk - LOWER THRESHOLD
                if ml_prediction == 'phishing' and ml_confidence > 0.3:  # Was 0.4
                    safe = False
                    reason = f"Low risk but ML suggests caution ({ml_confidence:.2f} phishing confidence)"
                else:
                    # Changed from safe=True to safe=False for LOW risk
                    safe = False
                    reason = f"Low risk detected ({risk_percentage:.0f}% risk, exercise caution)"
            elif verdict in [RiskLevel.MEDIUM]:
                safe = False
                reason = f"Suspicious ({risk_percentage:.0f}% risk, proceed with extreme caution)"
            elif verdict in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                safe = False
                reason = f"Dangerous ({risk_percentage:.0f}% risk, avoid this site)"
            else:
                safe = False
                reason = "Analysis error - treat as suspicious"
        else:
            safe = False
            reason = "Unknown verdict - treat as suspicious"
        
        # Additional safety check - LOWER threshold (was 60, now 50)
        high_risk_flags = 0
        for layer_result in analysis.get('layer_results', []):
            layer_risk = layer_result.get('risk_score', 0)
            if layer_risk > 50:  # Lower threshold
                high_risk_flags += 1
        
        if high_risk_flags >= 2 and safe:
            safe = False
            reason += " | Multiple layers detected high risk"
            
        # NEW: Check for specific high-risk flags
        has_high_risk_indicator = False
        for layer_result in analysis.get('layer_results', []):
            flags = layer_result.get('flags', [])
            for flag in flags:
                if any(term in flag.lower() for term in ['ip address', 'dns record', 'domain', 'shortened']):
                    has_high_risk_indicator = True
                    break
        
        if has_high_risk_indicator and safe:
            safe = False
            reason += " | High-risk indicators detected"
        
        # Add processing time info
        processing_time = analysis.get('processing_time', 0)
        reason += f" | Analyzed in {processing_time:.2f}s"
        
        return jsonify({
            'safe': safe, 
            'reason': reason,
            'risk_percentage': risk_percentage,
            'confidence': confidence,
            'verdict': verdict.value if isinstance(verdict, RiskLevel) else str(verdict),
            'ml_prediction': ml_prediction,
            'ml_confidence': ml_confidence
        })
        
    except Exception as e:
        logger.error(f"Analysis error for URL {url}: {e}")
        return jsonify({
            'safe': False, 
            'reason': f'Analysis failed: {str(e)} - treating as suspicious'
        }), 500

@app.route('/analyze_detailed', methods=['POST'])
def analyze_detailed():
    """
    Detailed analysis endpoint that returns full layered analysis results.
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        if detector is None:
            return jsonify({'error': 'Detector not initialized'}), 500
        
        # Get full analysis
        analysis = detector.analyze_url(url)
        
        # Process results for JSON serialization
        result = process_analysis_results(analysis)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Detailed analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'detector_loaded': detector is not None,
        'layers_count': len(detector.layers) if detector else 0,
        'timestamp': time.time()
    })

@app.route('/analyze_source', methods=['POST'])
def analyze_source_code():
    """
    Endpoint to analyze HTML source code sent from the extension.
    Uses content_analyzer module for deeper analysis.
    """
    try:
        data = request.get_json()
        
        url = data.get('url')
        html_content = data.get('source')
        
        if not url or not html_content:
            return jsonify({'error': 'URL and source code are required'}), 400
        
        # Use ContentAnalyzer if available or basic analysis otherwise
        try:
            from content_analyzer import ContentAnalyzer
            analyzer = ContentAnalyzer()
            analysis_result = analyzer.analyze_content(html_content, url)
            return jsonify(analysis_result)
        except ImportError:
            # Fallback to basic analysis if ContentAnalyzer not available
            risk_score = 0
            flags = []
            
            # Simple regex checks
            if re.search(r'eval\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}', html_content):
                flags.append("Obfuscated JavaScript detected")
                risk_score += 15
            
            if re.search(r'document\.cookie', html_content):
                flags.append("Cookie manipulation detected")
                risk_score += 10
            
            if len(re.findall(r'<input[^>]*type\s*=\s*["\']password["\']', html_content)) > 0:
                flags.append("Password field detected")
                risk_score += 5
                
                # Check if form submits to different domain
                form_actions = re.findall(r'<form[^>]*action\s*=\s*["\'](https?://[^"\']+)["\']', html_content)
                if form_actions:
                    try:
                        parsed_url = urllib.parse.urlparse(url)
                        current_domain = parsed_url.netloc
                        
                        for action in form_actions:
                            action_domain = urllib.parse.urlparse(action).netloc
                            if action_domain != current_domain:
                                flags.append("Form submits to external domain")
                                risk_score += 25
                                break
                    except:
                        pass
            
            return jsonify({
                'risk_score': min(risk_score, 100),
                'flags': flags,
                'basic_analysis': True
            })
            
    except Exception as e:
        logger.error(f"Source code analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def process_analysis_results(analysis):
    """Process analysis results for JSON serialization."""
    result = {
        'url': analysis['url'],
        'timestamp': analysis['timestamp'],
        'processing_time': analysis['processing_time'],
        'error': analysis.get('error')
    }
    
    # Process final result
    final_result = analysis.get('final_result', {})
    if final_result:
        verdict = final_result.get('final_verdict')
        result['final_result'] = {
            'verdict': verdict.value if isinstance(verdict, RiskLevel) else str(verdict),
            'risk_percentage': final_result.get('risk_percentage', 0),
            'confidence': final_result.get('confidence', 0),
            'recommendations': final_result.get('recommendations', []),
            'summary': final_result.get('summary', {}),
            'early_termination': final_result.get('early_termination', False)
        }
    
    # Process layer results
    result['layer_results'] = []
    for layer_result in analysis.get('layer_results', []):
        processed_layer = {
            'layer': layer_result.get('layer'),
            'risk_score': layer_result.get('risk_score', 0),
            'flags': layer_result.get('flags', []),
            'weight': layer_result.get('weight', 1.0)
        }
        
        # Add ML-specific info
        if 'ml_prediction' in layer_result:
            processed_layer['ml_prediction'] = layer_result['ml_prediction']
            processed_layer['confidence_scores'] = layer_result.get('confidence_scores', {})
            processed_layer['inference_time'] = layer_result.get('inference_time', 0)
            processed_layer['model_info'] = layer_result.get('model_info', {})
        
        # Add content analysis info
        if 'content_analysis' in layer_result:
            processed_layer['content_analysis'] = layer_result.get('content_analysis', {})
            processed_layer['ssl_info'] = layer_result.get('ssl_info', {})
            processed_layer['form_analysis'] = layer_result.get('form_analysis', {})
            processed_layer['js_analysis'] = layer_result.get('js_analysis', {})
        
        result['layer_results'].append(processed_layer)
    
    # Process ensemble result
    ensemble_result = analysis.get('ensemble_result', {})
    if ensemble_result:
        result['ensemble_result'] = {
            'weighted_risk_score': ensemble_result.get('weighted_risk_score', 0),
            'consensus': ensemble_result.get('consensus'),
            'conflicts': ensemble_result.get('conflicts', []),
            'layer_scores': ensemble_result.get('layer_scores', {})
        }
    
    return result

if __name__ == '__main__':
    print("🛡️  Phishing Detection API Server")
    print("="*50)
    print("✅ Starting Flask server...")
    
    # Report detector status
    if detector is not None:
        print("✅ Phishing detector initialized successfully")
        print(f"✅ Number of detection layers: {len(detector.layers)}")
    else:
        print("⚠️  Warning: Phishing detector not initialized")
        print("⚠️  API will run but analysis functions will return errors")
        print("💡 Fix by ensuring scikit-learn is installed and models are available")
    
    print("🌐 Chrome Extension endpoint: http://localhost:5000/check_url")
    print("🔍 Detailed analysis endpoint: http://localhost:5000/analyze_detailed")
    print("💚 Health check: http://localhost:5000/health")
    
    app.run(host='127.0.0.1', port=5000, debug=True)