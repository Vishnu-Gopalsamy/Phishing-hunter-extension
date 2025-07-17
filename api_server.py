from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import time
import os
import sys
import importlib.util
import re
import urllib.parse
import ssl
import socket
try:
    import whois
except ImportError:
    whois = None

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

# Update CORS configuration to be more permissive for development
app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Initialize the detector globally with retry mechanism
detector = None
MAX_INIT_ATTEMPTS = 3

def initialize_detector():
    """Initialize the layered phishing detector with retries."""
    global detector
    
    for attempt in range(1, MAX_INIT_ATTEMPTS + 1):
        try:
            logger.info(f"Initializing detector (attempt {attempt}/{MAX_INIT_ATTEMPTS})...")
            
            # Check if models exist before initializing
            models_dir = os.path.join(os.path.dirname(__file__), 'models')
            model_path = os.path.join(models_dir, 'phishing_classifier.pkl')
            vectorizer_path = os.path.join(models_dir, 'tfidf_vectorizer.pkl')
            
            if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
                logger.warning("ML models not found - detector will run with limited functionality")
                logger.info("To enable full ML capabilities, run: python training/train.py")
            
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

# Suppress SSL warnings globally for phishing detection
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add request logging middleware
@app.before_request
def log_request_info():
    logger.info(f"Received {request.method} request to {request.path}")
    logger.info(f"Headers: {dict(request.headers)}")
    if request.args:
        logger.info(f"Query params: {dict(request.args)}")

@app.route('/check_url', methods=['GET', 'OPTIONS'])
def check_url_api():
    """
    Simple API endpoint for Chrome extension compatibility.
    Returns basic safe/unsafe status with reason.
    Enhanced with better timeout handling and performance optimization.
    """
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response, 204
        
    url = request.args.get('url')
    logger.info(f"Analyzing URL: {url}")
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Add request timing
    start_time = time.time()
    
    try:
        if detector is None:
            return jsonify({
                'safe': False, 
                'reason': 'Detection system unavailable - detector not initialized'
            }), 500
        
        # Quick URL validation to fail fast
        if len(url) > 2000:
            return jsonify({
                'safe': False,
                'reason': 'URL too long (>2000 characters) - likely malicious',
                'risk_percentage': 95,
                'confidence': 0.9,
                'verdict': 'CRITICAL'
            })
        
        # Simplified analysis without threading to avoid signal issues
        try:
            logger.info(f"Starting analysis for URL: {url[:100]}...")
            
            # Set a simple timeout using time-based approach
            analysis_start = time.time()
            analysis = detector.analyze_url(url)
            analysis_duration = time.time() - analysis_start
            
            # Check if analysis took too long
            if analysis_duration > 15:  # 15 second timeout
                logger.warning(f"Analysis took {analysis_duration:.2f}s (slow)")
            
        except Exception as analysis_error:
            logger.error(f"Analysis error: {analysis_error}")
            # For model-related errors, provide more specific guidance
            error_str = str(analysis_error).lower()
            if 'model' in error_str or 'classifier' in error_str:
                return jsonify({
                    'safe': False,
                    'reason': 'ML model unavailable - ensure models are trained and saved',
                    'risk_percentage': 50,
                    'confidence': 0.3,
                    'verdict': 'ERROR',
                    'error': True,
                    'processing_time': time.time() - start_time
                }), 500
            else:
                # Use basic rule-based analysis as fallback
                from phishing_detector import extract_features, rule_based_classification
                try:
                    features = extract_features(url)
                    basic_result = rule_based_classification(features)
                    
                    safe = basic_result['prediction'] == 'legitimate'
                    risk_percentage = (1 - basic_result['confidence']) * 100 if safe else basic_result['confidence'] * 100
                    
                    return jsonify({
                        'safe': safe,
                        'reason': f"Basic analysis: {basic_result['prediction']} (fallback mode)",
                        'risk_percentage': risk_percentage,
                        'confidence': basic_result['confidence'],
                        'verdict': 'MEDIUM' if not safe else 'LOW',
                        'fallback_mode': True,
                        'processing_time': time.time() - start_time
                    })
                except:
                    return jsonify({
                        'safe': False,
                        'reason': 'Analysis failed - treating as suspicious',
                        'risk_percentage': 60,
                        'confidence': 0.3,
                        'verdict': 'ERROR',
                        'error': True,
                        'processing_time': time.time() - start_time
                    }), 500
        
        final_result = analysis.get('final_result', {})
        
        # Extract verdict and risk info
        verdict = final_result.get('final_verdict', RiskLevel.ERROR)
        risk_percentage = final_result.get('risk_percentage', 50)
        confidence = final_result.get('confidence', 0)
        
        # Get ML prediction for additional context
        ml_prediction = None
        ml_confidence = 0
        for layer_result in analysis.get('layer_results', []):
            if layer_result.get('layer') == 'ML Classification' and not layer_result.get('error'):
                ml_prediction = layer_result.get('ml_prediction')
                ml_scores = layer_result.get('confidence_scores', {})
                ml_confidence = ml_scores.get('phishing', 0)
                break
        
        # Check for legitimate brand sites (reduced false positives)
        is_legitimate_brand = check_legitimate_brand(url)
        
        # Count high-risk flags for later use
        high_risk_flags = 0
        specific_high_risk_indicators = []
        for layer_result in analysis.get('layer_results', []):
            if layer_result.get('error'):
                continue  # Skip error layers
            layer_risk = layer_result.get('risk_score', 0)
            if layer_risk > 50:  # Lower threshold
                high_risk_flags += 1
            
            # Collect specific high-risk indicators
            flags = layer_result.get('flags', [])
            for flag in flags:
                if any(term in flag.lower() for term in ['ip address', 'dns record', 'domain', 'shortened']):
                    specific_high_risk_indicators.append(flag)
                    specific_high_risk_indicators.append(flag)

        # NEW: Basic heuristics for non-whitelisted but legitimate sites
        # These will help prevent false positives on regular websites
        is_likely_legitimate = False
        
        # Check if the site has no serious red flags despite not being in our whitelist
        if risk_percentage < 35 and high_risk_flags == 0 and not specific_high_risk_indicators:
            is_likely_legitimate = True
        
        # Parse the domain and check some additional features
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check domain structure (no suspicious patterns)
            if (not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) and  # No IP address
                not re.search(r'[0-9]{5,}', domain) and  # No long number sequences
                not re.search(r'(secure|login|banking|account)\d+\.', domain) and  # No suspicious numbered keywords
                len(domain) < 40):  # Not excessively long domain
                
                # More likely to be legitimate if it passes these basic checks
                is_likely_legitimate = True
        except:
            pass
        
        # Improved classification logic with LOWER threshold for phishing
        # But HIGHER threshold for known legitimate brands
        if isinstance(verdict, RiskLevel):
            # More sensitive thresholds
            if verdict in [RiskLevel.SAFE]:
                # Double-check with ML prediction - LOWER THRESHOLD
                if ml_prediction == 'phishing' and ml_confidence > 0.40 and not (is_legitimate_brand or is_likely_legitimate):
                    safe = False
                    reason = f"ML detected phishing risk ({ml_confidence:.2f} confidence) despite low overall risk"
                else:
                    safe = True
                    reason = f"Safe ({risk_percentage:.0f}% risk, {confidence:.2f} confidence)"
            elif verdict in [RiskLevel.LOW]:
                # NEW: Be more lenient with Low risk - assume safe unless strong evidence otherwise
                if ml_prediction == 'phishing' and ml_confidence > 0.60 and not (is_legitimate_brand or is_likely_legitimate):
                    safe = False
                    reason = f"Low risk but ML suggests caution ({ml_confidence:.2f} phishing confidence)"
                else:
                    safe = True
                    reason = f"Low risk detected ({risk_percentage:.0f}% risk)"
                    
                    # Add info if it's recognized as legitimate 
                    if is_legitimate_brand:
                        reason += " - recognized brand site"
            elif verdict in [RiskLevel.MEDIUM]:
                # For legitimate brands with MEDIUM risk, consider context
                if is_legitimate_brand or is_likely_legitimate:
                    # Require higher confidence for ML to flag as phishing
                    if ml_prediction == 'phishing' and ml_confidence > 0.75:
                        safe = False
                        reason = f"Medium risk from likely legitimate site - unusual behavior detected ({risk_percentage:.0f}% risk)"
                    else:
                        safe = True
                        reason = f"Medium risk but verified or likely legitimate site ({risk_percentage:.0f}%)"
                else:
                    # Check ML prediction as additional evidence
                    if ml_prediction == 'phishing' and ml_confidence > 0.40:
                        safe = False
                        reason = f"Suspicious ({risk_percentage:.0f}% risk, proceed with extreme caution)"
                    else:
                        # If ML disagrees with medium risk, be more lenient
                        safe = True  
                        reason = f"Medium risk but ML indicates likely safe ({risk_percentage:.0f}% risk, monitor carefully)"
            elif verdict in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                # Even legitimate brands could be compromised
                safe = False
                reason = f"Dangerous ({risk_percentage:.0f}% risk, avoid this site)"
                if is_legitimate_brand:
                    reason = f"High risk on legitimate brand site - possible compromise ({risk_percentage:.0f}% risk)"
            else:
                safe = False
                reason = "Analysis error - treat as suspicious"
        else:
            safe = False
            reason = "Unknown verdict - treat as suspicious"
        
        # Don't flag legitimate sites as unsafe just for having high-risk flags
        # unless there are multiple severe flags
        if high_risk_flags >= 3 and safe and not is_legitimate_brand:  # Increased threshold from 2 to 3
            safe = False
            reason += f" | {high_risk_flags} layers detected high risk"
        
        # For legitimate brands, we need stronger evidence to flag as unsafe
        if len(specific_high_risk_indicators) >= 2 and safe and not is_legitimate_brand:  # Increased from 1 to 2
            safe = False
            reason += " | Multiple high-risk indicators detected"
        
        # Add fallback mode indicator if applicable
        if final_result.get('fallback_result'):
            reason += " | Limited analysis mode"
        
        # Add processing time info
        processing_time = time.time() - start_time
        
        response_data = {
            'safe': safe, 
            'reason': reason,
            'risk_percentage': risk_percentage,
            'confidence': confidence,
            'verdict': verdict.value if isinstance(verdict, RiskLevel) else str(verdict),
            'ml_prediction': ml_prediction,
            'ml_confidence': ml_confidence,
            'is_legitimate_brand': is_legitimate_brand,
            'is_likely_legitimate': is_likely_legitimate,
            'processing_time': processing_time,
            'server_time': time.time(),
            'fallback_mode': final_result.get('fallback_result', False)
        }
        
        logger.info(f"Analysis completed in {processing_time:.2f}s: {verdict}")
        response = jsonify(response_data)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response
        
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"Analysis error for URL {url[:100]}: {e} (took {processing_time:.2f}s)")
        
        error_response = jsonify({
            'safe': False, 
            'reason': f'Analysis failed: {str(e)[:200]} - treating as suspicious',
            'risk_percentage': 60,
            'confidence': 0.3,
            'verdict': 'ERROR',
            'error': True,
            'processing_time': processing_time
        })
        error_response.headers.add('Access-Control-Allow-Origin', '*')
        error_response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        error_response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return error_response, 500

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
                        from urllib.parse import urlparse
                        current_domain = urlparse(url).netloc
                        for action in form_actions:
                            action_domain = urlparse(action).netloc
                            if action_domain != current_domain:
                                flags.append(f"Form submits to different domain: {action_domain}")
                                risk_score += 25
                    except:
                        pass
            # Check for external resources
            external_resources = re.findall(r'src\s*=\s*["\'](https?://[^"\']+)["\']', html_content)
            if external_resources:
                try:
                    from urllib.parse import urlparse
                    current_domain = urlparse(url).netloc
                    
                    for resource in external_resources:
                        resource_domain = urlparse(resource).netloc
                        if resource_domain != current_domain:
                            flags.append("Page loads resources from external domains")
                            risk_score += 5
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

@app.route('/health')
def health_check():
    """Enhanced health check endpoint with more details."""
    health_data = {
        'status': 'healthy',
        'detector_loaded': detector is not None,
        'layers_count': len(detector.layers) if detector else 0,
        'timestamp': time.time(),
        'server_uptime': time.time() - server_start_time,
        'python_version': sys.version.split()[0],
        'dependencies': {},
        'cors': "enabled"
    }
    
    # Check key dependencies
    try:
        import sklearn
        health_data['dependencies']['sklearn'] = sklearn.__version__
    except ImportError:
        health_data['dependencies']['sklearn'] = 'missing'
    
    try:
        import flask
        health_data['dependencies']['flask'] = flask.__version__
    except ImportError:
        health_data['dependencies']['flask'] = 'missing'
    
    # Skip detector test for health check to make it faster
    if detector:
        health_data['detector_status'] = 'initialized'
    else:
        health_data['detector_status'] = 'not initialized'
        health_data['status'] = 'degraded'
    
    # Add debug info for CORS
    health_data['allowed_origins'] = '*'
    health_data['allowed_methods'] = ['GET', 'POST', 'OPTIONS']
    
    response = jsonify(health_data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    return response

# Add helper function to check legitimate brands
def check_legitimate_brand(url):
    """Check if URL belongs to a legitimate brand website."""
    try:
        from urllib.parse import urlparse
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove 'www.' prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # List of legitimate brand domains and their common subdomains
        legitimate_brands = {
            'instagram.com': ['www', 'about', 'help', 'business'],
            'facebook.com': ['www', 'business', 'm', 'developers'],
            'google.com': ['www', 'mail', 'drive', 'docs'],
            'youtube.com': ['www', 'music', 'studio', 'tv'],
            'microsoft.com': ['www', 'account', 'login', 'office'],
            'apple.com': ['www', 'support', 'id', 'developer'],
            'amazon.com': ['www', 'smile', 'pay', 'music'],
            'twitter.com': ['www', 'mobile', 'api'],
            'linkedin.com': ['www', 'business', 'developer'],
            'github.com': ['www', 'gist', 'api'],
            'paypal.com': ['www', 'developer', 'checkout']
        }
        
        # Check for direct domain match
        if domain in legitimate_brands:
            return True
            
        # Check for subdomain of a legitimate brand
        for brand_domain, subdomains in legitimate_brands.items():
            if domain.endswith(f'.{brand_domain}'):
                subdomain = domain.replace(f'.{brand_domain}', '')
                # Check if it's a known subdomain or follows common patterns
                if subdomain in subdomains or re.match(r'^(help|about|support|developer|api|business|login|account|secure)$', subdomain):
                    return True
                    
        # Additional checks for government, education domains
        if domain.endswith('.gov') or domain.endswith('.edu'):
            return True

        # NEW: Domain age as indicator of legitimacy
        try:
            import whois
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                # Get the creation date (handle list or single date)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # If domain is older than 1 year, it's more likely legitimate
                from datetime import datetime
                domain_age_days = (datetime.now() - creation_date).days
                if domain_age_days > 365:  # Domain older than 1 year
                    logger.info(f"Domain {domain} is older than 1 year ({domain_age_days} days), likely legitimate")
                    return True
        except:
            pass
            
        return False
    except Exception as e:
        logger.error(f"Error checking legitimate brand: {e}")
        return False

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
    # Track server start time
    server_start_time = time.time()
    
    print("🛡️  Phishing Detection API Server v2.0")
    print("="*50)
    print("✅ Starting Flask server with enhanced timeout handling...")
    
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
    print("\n⚡ Performance optimizations:")
    print("   - 12s timeout for analysis requests")
    print("   - Fast failure for invalid URLs")
    print("   - Enhanced error reporting")
    print("   - SSL warnings suppressed for phishing detection")
    
    try:
        # Update server configuration
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=True,  # Enable debug mode for development
            threaded=True,
            use_reloader=True
        )
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("Trying alternative configuration...")
        try:
            # Fall back to a simpler configuration
            app.run(host='127.0.0.1', port=5000)
        except Exception as e2:
            print(f"❌ Failed to start server with alternative configuration: {e2}")
            sys.exit(1)