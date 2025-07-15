from flask import Flask, request, jsonify
from flask_cors import CORS
from phishing_detector import LayeredPhishingDetector, RiskLevel
import logging
import time

app = Flask(__name__)
CORS(app)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the detector globally
detector = None

def initialize_detector():
    """Initialize the layered phishing detector."""
    global detector
    try:
        detector = LayeredPhishingDetector()
        logger.info("Layered phishing detector initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize detector: {e}")
        return False

# Initialize detector on startup
if not initialize_detector():
    logger.error("Failed to initialize detector - API will return errors")

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
        
        # Improved classification logic with lower threshold for phishing
        if isinstance(verdict, RiskLevel):
            # Use more sensitive thresholds
            if verdict in [RiskLevel.SAFE]:
                # Double-check with ML prediction
                if ml_prediction == 'phishing' and ml_confidence > 0.3:
                    safe = False
                    reason = f"ML detected phishing risk ({ml_confidence:.2f} confidence) despite low overall risk"
                else:
                    safe = True
                    reason = f"Safe ({risk_percentage:.0f}% risk, {confidence:.2f} confidence)"
            elif verdict in [RiskLevel.LOW]:
                # Be more cautious with low risk
                if ml_prediction == 'phishing' and ml_confidence > 0.4:
                    safe = False
                    reason = f"Low risk but ML suggests caution ({ml_confidence:.2f} phishing confidence)"
                else:
                    safe = True
                    reason = f"Low risk ({risk_percentage:.0f}% risk, monitor carefully)"
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
        
        # Additional safety check - if any layer shows high phishing indicators
        high_risk_flags = 0
        for layer_result in analysis.get('layer_results', []):
            layer_risk = layer_result.get('risk_score', 0)
            if layer_risk > 60:
                high_risk_flags += 1
        
        if high_risk_flags >= 2 and safe:
            safe = False
            reason += " | Multiple layers detected high risk"
        
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
        
        result['layer_results'].append(processed_layer)
    
    return result

if __name__ == '__main__':
    print("🛡️  Phishing Detection API Server")
    print("="*50)
    print("✅ Starting Flask server...")
    print("🌐 Chrome Extension endpoint: http://localhost:5000/check_url")
    print("🔍 Detailed analysis endpoint: http://localhost:5000/analyze_detailed")
    print("💚 Health check: http://localhost:5000/health")
    
    app.run(host='127.0.0.1', port=5000, debug=True)