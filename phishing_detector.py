"""
Phishing URL Detection App - Layered Approach

This module implements a multi-layered detection system where URLs pass through
progressively sophisticated analysis layers for comprehensive phishing detection.
"""

import os
import sys
import re
import urllib.parse
import tldextract
import socket
import whois
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import joblib
import json
import logging
from enum import Enum

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration for clear classification."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"

class DetectionLayer:
    """Base class for detection layers."""
    
    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight
        self.enabled = True
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL and return results."""
        raise NotImplementedError

class Layer1_BasicValidation(DetectionLayer):
    """
    Layer 1: Basic URL Validation & Quick Checks
    - URL format validation
    - Basic malicious patterns
    - Quick blacklist checks
    """
    
    def __init__(self):
        super().__init__("Basic Validation", weight=0.8)
        
        # Known malicious patterns
        self.malicious_patterns = [
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Multiple dashes
            r'(paypal|ebay|amazon|microsoft|apple|google).*[0-9]+\..*',  # Brand + numbers
            r'(secure|login|account|verify|update).*[0-9]+\.',  # Security terms + numbers
        ]
        
        # Quick blacklist (simplified)
        self.blacklisted_domains = {
            'malicious-site.com', 'phishing-test.org', 'fake-bank.net'
        }
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform basic validation checks."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'details': {},
            'passed': True
        }
        
        try:
            # 1. URL format validation
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                results['flags'].append("Invalid URL format")
                results['risk_score'] += 30
                results['passed'] = False
            
            # 2. Length check (extreme cases)
            if len(url) > 2000:
                results['flags'].append("Extremely long URL")
                results['risk_score'] += 20
            elif len(url) > 200:
                results['flags'].append("Very long URL")
                results['risk_score'] += 10
            
            # 3. Malicious pattern detection
            for pattern in self.malicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    results['flags'].append(f"Malicious pattern detected: {pattern}")
                    results['risk_score'] += 25
            
            # 4. Quick blacklist check
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            if domain in self.blacklisted_domains:
                results['flags'].append("Domain in blacklist")
                results['risk_score'] += 50
                results['passed'] = False
            
            # 5. Protocol check
            if parsed.scheme not in ['http', 'https']:
                results['flags'].append("Unusual protocol")
                results['risk_score'] += 15
            
            results['details'] = {
                'url_length': len(url),
                'domain': domain,
                'protocol': parsed.scheme,
                'pattern_matches': len([p for p in self.malicious_patterns if re.search(p, url, re.IGNORECASE)])
            }
            
        except Exception as e:
            results['flags'].append(f"Validation error: {str(e)}")
            results['risk_score'] = 40
            results['passed'] = False
        
        return results

class Layer2_FeatureAnalysis(DetectionLayer):
    """
    Layer 2: Advanced Feature Analysis
    - Comprehensive URL feature extraction
    - Domain-based analysis
    - Structural analysis
    """
    
    def __init__(self):
        super().__init__("Feature Analysis", weight=1.0)
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive feature analysis."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'features': {},
            'feature_scores': {}
        }
        
        try:
            # Extract features using existing function
            features = extract_features(url)
            results['features'] = features
            
            # Score each feature
            feature_scores = self._score_features(features)
            results['feature_scores'] = feature_scores
            
            # Calculate total risk score
            total_score = sum(feature_scores.values())
            results['risk_score'] = min(total_score, 100)  # Cap at 100
            
            # Generate flags based on high-risk features
            if features.get('has_ip_address'):
                results['flags'].append("Uses IP address instead of domain")
            
            if features.get('https_token_in_domain'):
                results['flags'].append("HTTPS token in domain name")
            
            if features.get('double_slash_redirect'):
                results['flags'].append("Double slash redirection detected")
            
            if features.get('domain_age') == 'Phishing':
                results['flags'].append("Young or suspicious domain age")
            
            if not features.get('dns_record'):
                results['flags'].append("No DNS record found")
            
        except Exception as e:
            results['flags'].append(f"Feature analysis error: {str(e)}")
            results['risk_score'] = 30
        
        return results
    
    def _score_features(self, features: Dict[str, Any]) -> Dict[str, float]:
        """Score individual features."""
        scores = {}
        
        # High-risk features (0-25 points each)
        scores['ip_address'] = 25 if features.get('has_ip_address') else 0
        scores['https_token'] = 25 if features.get('https_token_in_domain') else 0
        scores['double_slash'] = 20 if features.get('double_slash_redirect') else 0
        scores['no_dns'] = 25 if not features.get('dns_record') else 0
        
        # URL length scoring
        url_length = features.get('url_length', 'Legitimate')
        if url_length == 'Phishing':
            scores['url_length'] = 15
        elif url_length == 'Suspicious':
            scores['url_length'] = 8
        else:
            scores['url_length'] = 0
        
        # Domain features
        scores['domain_age'] = 15 if features.get('domain_age') == 'Phishing' else 0
        scores['registration_length'] = 10 if features.get('domain_registration_length') == 'Phishing' else 0
        
        # Medium-risk features
        scores['shortened_url'] = 10 if features.get('is_shortened') else 0
        scores['dash_in_domain'] = 8 if features.get('has_dash_in_domain') else 0
        
        # Subdomain analysis
        subdomain_level = features.get('subdomain_level', 'Legitimate')
        if subdomain_level == 'Phishing':
            scores['subdomain'] = 12
        elif subdomain_level == 'Suspicious':
            scores['subdomain'] = 6
        else:
            scores['subdomain'] = 0
        
        return scores

class Layer3_MLClassification(DetectionLayer):
    """
    Layer 3: Machine Learning Classification with GPU Support
    - TF-IDF based URL analysis
    - XGBoost/RandomForest classification
    - GPU-accelerated inference
    - Confidence scoring
    """
    
    def __init__(self):
        super().__init__("ML Classification", weight=1.5)  # Increased weight
        self.model = None
        self.vectorizer = None
        self.model_info = {}
        self._load_models()
    
    def _load_models(self):
        """Load ML models with GPU support detection."""
        try:
            models_dir = os.path.join(os.path.dirname(__file__), 'models')
            model_path = os.path.join(models_dir, 'phishing_classifier.pkl')
            vectorizer_path = os.path.join(models_dir, 'tfidf_vectorizer.pkl')
            results_path = os.path.join(models_dir, 'evaluation_results.json')
            
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                
                # Load model info
                if os.path.exists(results_path):
                    with open(results_path, 'r') as f:
                        self.model_info = json.load(f)
                    
                    model_type = self.model_info.get('model_type', 'Unknown')
                    gpu_accelerated = self.model_info.get('gpu_accelerated', False)
                    accuracy = self.model_info.get('accuracy', 0)
                    
                    logger.info(f"ML model loaded: {model_type}")
                    logger.info(f"GPU accelerated: {gpu_accelerated}")
                    logger.info(f"Model accuracy: {accuracy:.4f}")
                else:
                    logger.info("ML models loaded successfully")
            else:
                logger.warning("ML models not found")
                self.enabled = False
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            self.enabled = False
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform ML-based classification with GPU acceleration."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'ml_prediction': None,
            'confidence_scores': {},
            'enabled': self.enabled,
            'model_info': {
                'type': self.model_info.get('model_type', 'Unknown'),
                'gpu_accelerated': self.model_info.get('gpu_accelerated', False),
                'accuracy': self.model_info.get('accuracy', 0)
            }
        }
        
        if not self.enabled:
            results['flags'].append("ML models not available")
            return results
        
        try:
            import time
            start_time = time.time()
            
            # Transform URL
            url_vec = self.vectorizer.transform([url])
            
            # Get prediction and probabilities
            prediction = self.model.predict(url_vec)[0]
            probabilities = self.model.predict_proba(url_vec)[0]
            
            inference_time = time.time() - start_time
            
            results['ml_prediction'] = 'phishing' if prediction == 1 else 'legitimate'
            results['confidence_scores'] = {
                'legitimate': float(probabilities[0]),
                'phishing': float(probabilities[1])
            }
            results['inference_time'] = inference_time
            
            # More sensitive risk scoring for phishing detection
            if prediction == 1:  # Phishing
                results['risk_score'] = probabilities[1] * 100
                results['flags'].append(f"ML classified as phishing (confidence: {probabilities[1]:.3f})")
            else:  # Legitimate
                # But if phishing probability is still significant, add some risk
                if probabilities[1] > 0.3:
                    results['risk_score'] = probabilities[1] * 60  # More conservative
                    results['flags'].append(f"ML classified as legitimate but phishing probability is {probabilities[1]:.3f}")
                else:
                    results['risk_score'] = probabilities[1] * 30  # Lower penalty for clearly legitimate
            
            # Add performance info
            if self.model_info.get('gpu_accelerated'):
                results['flags'].append(f"GPU-accelerated inference ({inference_time*1000:.1f}ms)")
            
        except Exception as e:
            results['flags'].append(f"ML classification error: {str(e)}")
            results['risk_score'] = 50  # Treat as suspicious if ML fails
        
        return results

class Layer4_EnsembleDecision(DetectionLayer):
    """
    Layer 4: Ensemble Decision Making
    - Combines results from all previous layers
    - Weighted scoring
    - Conflict resolution
    """
    
    def __init__(self):
        super().__init__("Ensemble Decision", weight=1.0)
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Combine and weight results from previous layers."""
        results = {
            'layer': self.name,
            'weighted_risk_score': 0.0,
            'layer_scores': {},
            'consensus': None,
            'conflicts': []
        }
        
        if not context or 'layer_results' not in context:
            results['conflicts'].append("No previous layer results available")
            return results
        
        layer_results = context['layer_results']
        total_weight = 0
        weighted_sum = 0
        
        # Calculate weighted average of risk scores
        for layer_result in layer_results:
            if 'risk_score' in layer_result:
                weight = layer_result.get('weight', 1.0)
                score = layer_result['risk_score']
                
                weighted_sum += score * weight
                total_weight += weight
                
                results['layer_scores'][layer_result['layer']] = {
                    'score': score,
                    'weight': weight,
                    'weighted_score': score * weight
                }
        
        if total_weight > 0:
            results['weighted_risk_score'] = weighted_sum / total_weight
        
        # Determine consensus
        risk_score = results['weighted_risk_score']
        if risk_score >= 70:
            results['consensus'] = 'phishing'
        elif risk_score >= 40:
            results['consensus'] = 'suspicious'
        else:
            results['consensus'] = 'legitimate'
        
        # Check for conflicts between layers
        predictions = []
        for layer_result in layer_results:
            if 'ml_prediction' in layer_result:
                predictions.append(layer_result['ml_prediction'])
            elif layer_result.get('risk_score', 0) > 50:
                predictions.append('phishing')
            else:
                predictions.append('legitimate')
        
        if len(set(predictions)) > 1:
            results['conflicts'].append("Disagreement between detection layers")
        
        return results

class Layer5_FinalVerdict(DetectionLayer):
    """
    Layer 5: Final Verdict Generation
    - Risk level assignment
    - Confidence calculation
    - Recommendation generation
    """
    
    def __init__(self):
        super().__init__("Final Verdict", weight=1.0)
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate final verdict and recommendations."""
        results = {
            'layer': self.name,
            'final_verdict': RiskLevel.ERROR,
            'confidence': 0.0,
            'risk_percentage': 0.0,
            'recommendations': [],
            'summary': {}
        }
        
        if not context:
            return results
        
        # Get ensemble results
        ensemble_result = context.get('ensemble_result', {})
        risk_score = ensemble_result.get('weighted_risk_score', 50)
        consensus = ensemble_result.get('consensus', 'unknown')
        
        # Check for ML prediction to adjust thresholds
        ml_prediction = None
        ml_phishing_confidence = 0
        for layer_result in context.get('layer_results', []):
            if layer_result.get('layer') == 'ML Classification':
                ml_prediction = layer_result.get('ml_prediction')
                ml_scores = layer_result.get('confidence_scores', {})
                ml_phishing_confidence = ml_scores.get('phishing', 0)
                break
        
        # Adjust risk score based on ML prediction (more sensitive to phishing)
        if ml_prediction == 'phishing' and ml_phishing_confidence > 0.4:
            risk_score = max(risk_score, 60)  # Boost risk if ML detects phishing
        elif ml_prediction == 'phishing' and ml_phishing_confidence > 0.6:
            risk_score = max(risk_score, 75)  # Higher boost for higher ML confidence
        
        # More sensitive thresholds for final verdict
        if risk_score >= 75:
            results['final_verdict'] = RiskLevel.CRITICAL
        elif risk_score >= 60:
            results['final_verdict'] = RiskLevel.HIGH
        elif risk_score >= 35:  # Lowered from 40
            results['final_verdict'] = RiskLevel.MEDIUM
        elif risk_score >= 15:  # Lowered from 20
            results['final_verdict'] = RiskLevel.LOW
        else:
            results['final_verdict'] = RiskLevel.SAFE
        
        # Additional check: if ML strongly suggests phishing, upgrade verdict
        if (ml_prediction == 'phishing' and ml_phishing_confidence > 0.7 and 
            results['final_verdict'] in [RiskLevel.SAFE, RiskLevel.LOW]):
            results['final_verdict'] = RiskLevel.MEDIUM
            risk_score = max(risk_score, 40)
        
        results['risk_percentage'] = risk_score
        
        # Calculate confidence based on layer agreement
        layer_results = context.get('layer_results', [])
        agreements = 0
        total_layers = len(layer_results)
        
        for layer_result in layer_results:
            layer_score = layer_result.get('risk_score', 0)
            if (risk_score >= 40 and layer_score >= 40) or (risk_score < 40 and layer_score < 40):
                agreements += 1
        
        results['confidence'] = (agreements / total_layers) if total_layers > 0 else 0.5
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(
            results['final_verdict'], risk_score, context
        )
        
        # Create summary
        results['summary'] = {
            'url': url,
            'verdict': results['final_verdict'].value,
            'risk_percentage': round(risk_score, 1),
            'confidence': round(results['confidence'], 3),
            'total_flags': sum(len(lr.get('flags', [])) for lr in layer_results),
            'ml_prediction': ml_prediction,
            'ml_confidence': ml_phishing_confidence
        }
        
        return results
    
    def _generate_recommendations(self, verdict: RiskLevel, risk_score: float, context: Dict[str, Any]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if verdict in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.extend([
                "🚨 DO NOT visit this website",
                "🚨 DO NOT enter any personal information",
                "🚨 DO NOT download any files",
                "📞 Report this URL to security authorities"
            ])
        elif verdict == RiskLevel.MEDIUM:
            recommendations.extend([
                "⚠️ Exercise extreme caution",
                "⚠️ Verify website authenticity through official channels",
                "⚠️ Do not enter sensitive information",
                "🔍 Check URL carefully for typos"
            ])
        elif verdict == RiskLevel.LOW:
            recommendations.extend([
                "💡 Proceed with caution",
                "💡 Verify the website's legitimacy",
                "💡 Check for HTTPS encryption"
            ])
        else:  # SAFE
            recommendations.extend([
                "✅ URL appears to be safe",
                "💡 Always verify authenticity for sensitive transactions"
            ])
        
        # Add specific recommendations based on detected issues
        layer_results = context.get('layer_results', [])
        for layer_result in layer_results:
            flags = layer_result.get('flags', [])
            if 'Uses IP address instead of domain' in flags:
                recommendations.append("🔍 URL uses IP address - highly suspicious")
            if 'Shortened URL' in flags:
                recommendations.append("🔍 Expand shortened URL to see actual destination")
        
        return recommendations

class LayeredPhishingDetector:
    """
    Main class implementing the layered phishing detection system.
    """
    
    def __init__(self):
        self.layers = [
            Layer1_BasicValidation(),
            Layer2_FeatureAnalysis(),
            Layer3_MLClassification(),
            Layer4_EnsembleDecision(),
            Layer5_FinalVerdict()
        ]
        
        logger.info(f"Initialized {len(self.layers)} detection layers")
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL through all detection layers.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            Dict[str, Any]: Comprehensive analysis results
        """
        analysis_results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'layer_results': [],
            'ensemble_result': {},
            'final_result': {},
            'processing_time': 0.0
        }
        
        start_time = datetime.now()
        
        try:
            # Pass URL through each layer
            context = {}
            
            for i, layer in enumerate(self.layers):
                if not layer.enabled:
                    logger.warning(f"Layer {layer.name} is disabled, skipping")
                    continue
                
                logger.info(f"Processing layer {i+1}: {layer.name}")
                
                # Special handling for ensemble and final layers
                if isinstance(layer, Layer4_EnsembleDecision):
                    context['layer_results'] = analysis_results['layer_results']
                    layer_result = layer.analyze(url, context)
                    analysis_results['ensemble_result'] = layer_result
                
                elif isinstance(layer, Layer5_FinalVerdict):
                    context['ensemble_result'] = analysis_results['ensemble_result']
                    context['layer_results'] = analysis_results['layer_results']
                    layer_result = layer.analyze(url, context)
                    analysis_results['final_result'] = layer_result
                
                else:
                    layer_result = layer.analyze(url, context)
                    layer_result['weight'] = layer.weight
                    analysis_results['layer_results'].append(layer_result)
                
                # Early termination for critical issues in Layer 1
                if (isinstance(layer, Layer1_BasicValidation) and 
                    not layer_result.get('passed', True) and 
                    layer_result.get('risk_score', 0) > 80):
                    
                    logger.warning("Critical issues detected in Layer 1, terminating analysis")
                    analysis_results['final_result'] = {
                        'final_verdict': RiskLevel.CRITICAL,
                        'risk_percentage': layer_result['risk_score'],
                        'confidence': 0.9,
                        'early_termination': True,
                        'recommendations': [
                            "🚨 Critical security threat detected",
                            "🚨 DO NOT proceed with this URL"
                        ]
                    }
                    break
        
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            analysis_results['error'] = str(e)
            analysis_results['final_result'] = {
                'final_verdict': RiskLevel.ERROR,
                'error': str(e)
            }
        
        # Calculate processing time
        end_time = datetime.now()
        analysis_results['processing_time'] = (end_time - start_time).total_seconds()
        
        return analysis_results
    
    def get_quick_verdict(self, url: str) -> str:
        """Get a quick verdict for simple use cases."""
        results = self.analyze_url(url)
        final_result = results.get('final_result', {})
        verdict = final_result.get('final_verdict', RiskLevel.ERROR)
        
        if isinstance(verdict, RiskLevel):
            return verdict.value
        return str(verdict)

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract features from a URL for phishing detection.
    
    Address Bar-based Features:
    - has_ip_address: Boolean indicating if the hostname is an IPv4 address
    - url_length: Classification based on URL length:
        - "Legitimate" if length < 54
        - "Suspicious" if length 54-75 (inclusive)  
        - "Phishing" if length > 75
    - is_shortened: Boolean indicating if the URL uses a known shortening service
    - double_slash_redirect: Boolean indicating if "//" appears after position 7
    - has_dash_in_domain: Boolean indicating if the domain contains a dash "-"
    - subdomain_level: Classification based on subdomain count:
        - "Legitimate" if subdomain count <= 1
        - "Suspicious" if subdomain count == 2
        - "Phishing" if subdomain count > 2
    - https_token_in_domain: Boolean indicating if "https" appears in domain name
    
    Domain-based Features:
    - domain_age: Classification based on domain age via WHOIS:
        - "Legitimate" if age >= 6 months
        - "Phishing" if age < 6 months or unavailable
    - domain_registration_length: Classification based on domain expiry:
        - "Legitimate" if expires > 1 year from now
        - "Phishing" if expires <= 1 year or unavailable
    - dns_record: Boolean indicating if DNS record exists for domain
    - alexa_rank: Classification based on website popularity:
        - "Legitimate" if rank < 100,000
        - "Suspicious" if rank 100,000-999,999
        - "Phishing" if rank > 999,999 or not found
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        Dict[str, Any]: A dictionary containing extracted features
    """
    features = {}
    
    try:
        # Parse the URL to extract components
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc
        
        # Remove port number if present (e.g., "192.168.1.1:8080" -> "192.168.1.1")
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Check if hostname is an IPv4 address using regex
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        features["has_ip_address"] = bool(re.match(ipv4_pattern, hostname))
        
        # Classify URL based on length
        url_length = len(url)
        if url_length < 54:
            features["url_length"] = "Legitimate"
        elif 54 <= url_length <= 75:
            features["url_length"] = "Suspicious"
        else:  # url_length > 75
            features["url_length"] = "Phishing"
        
        # Check if URL uses a known shortening service
        known_shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", 
            "is.gd", "buff.ly", "rebrand.ly", "short.link", "tiny.cc",
            "url.ie", "v.gd", "lnkd.in", "youtu.be", "amzn.to"
        ]
        
        # Extract domain (remove www. prefix if present)
        domain = hostname.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        features["is_shortened"] = domain in known_shorteners
        
        # 1. Check for double slash redirection (// after position 7)
        last_double_slash_pos = url.rfind('//')
        features["double_slash_redirect"] = last_double_slash_pos > 7
        
        # Use tldextract for accurate domain parsing
        extracted = tldextract.extract(url)
        full_domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        
        # 2. Check for dash in domain name (check both domain and subdomain)
        has_dash_domain = '-' in extracted.domain
        has_dash_subdomain = '-' in extracted.subdomain if extracted.subdomain else False
        features["has_dash_in_domain"] = has_dash_domain or has_dash_subdomain
        
        # 3. Subdomain count classification
        # Count dots in subdomain part (tldextract automatically excludes www, domain, and suffix)
        subdomain_parts = extracted.subdomain.split('.') if extracted.subdomain else []
        # Remove empty parts and 'www' if present
        subdomain_parts = [part for part in subdomain_parts if part and part.lower() != 'www']
        subdomain_count = len(subdomain_parts)
        
        if subdomain_count <= 1:
            features["subdomain_level"] = "Legitimate"
        elif subdomain_count == 2:
            features["subdomain_level"] = "Suspicious"
        else:  # subdomain_count > 2
            features["subdomain_level"] = "Phishing"
        
        # 4. Check for "https" token in domain name (check subdomain + domain + suffix)
        # Combine all parts except the protocol
        all_domain_parts = []
        if extracted.subdomain:
            all_domain_parts.append(extracted.subdomain)
        if extracted.domain:
            all_domain_parts.append(extracted.domain)
        if extracted.suffix:
            all_domain_parts.append(extracted.suffix)
        
        complete_domain = '.'.join(all_domain_parts).lower()
        features["https_token_in_domain"] = 'https' in complete_domain
        
        # =================== DOMAIN-BASED FEATURES ===================
        
        # Get the main domain for WHOIS and DNS checks
        main_domain = full_domain if full_domain else f"{extracted.domain}.{extracted.suffix}"
        
        # 5. Domain Age using WHOIS
        try:
            domain_info = whois.whois(main_domain)
            creation_date = domain_info.creation_date
            
            if creation_date:
                # Handle case where creation_date might be a list
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # Calculate domain age
                domain_age_days = (datetime.now() - creation_date).days
                domain_age_months = domain_age_days / 30.44  # Average days per month
                
                if domain_age_months >= 6:
                    features["domain_age"] = "Legitimate"
                else:
                    features["domain_age"] = "Phishing"
            else:
                features["domain_age"] = "Phishing"  # No creation date found
                
        except Exception as e:
            features["domain_age"] = "Phishing"  # WHOIS lookup failed
        
        # 6. Domain Registration Length using WHOIS
        try:
            if 'domain_info' in locals() and domain_info.expiration_date:
                expiration_date = domain_info.expiration_date
                
                # Handle case where expiration_date might be a list
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                
                # Calculate time until expiration
                days_until_expiry = (expiration_date - datetime.now()).days
                
                if days_until_expiry <= 365:  # 1 year or less
                    features["domain_registration_length"] = "Phishing"
                else:
                    features["domain_registration_length"] = "Legitimate"
            else:
                features["domain_registration_length"] = "Phishing"  # No expiration date
                
        except Exception as e:
            features["domain_registration_length"] = "Phishing"  # Failed to get expiration
        
        # 7. DNS Record Exists
        try:
            socket.gethostbyname(main_domain)
            features["dns_record"] = True
        except socket.gaierror:
            features["dns_record"] = False
        except Exception as e:
            features["dns_record"] = False
        
        # 8. Alexa Rank (using dummy implementation for now)
        # In a real implementation, you would use an API like Alexa or similar ranking service
        try:
            # For demonstration, we'll use domain length as a proxy
            # In reality, you'd call an API like: alexa_rank = get_alexa_rank(main_domain)
            domain_length = len(main_domain)
            
            # Dummy logic: shorter domains tend to be more popular
            if domain_length <= 10:
                dummy_rank = 50000  # High ranking (legitimate)
            elif domain_length <= 15:
                dummy_rank = 150000  # Medium ranking
            else:
                dummy_rank = 999999  # Low ranking
            
            if dummy_rank < 100000:
                features["alexa_rank"] = "Legitimate"
            elif dummy_rank <= 999999:
                features["alexa_rank"] = "Suspicious"
            else:
                features["alexa_rank"] = "Phishing"
                
        except Exception as e:
            features["alexa_rank"] = "Phishing"  # No rank found
        
    except Exception as e:
        # If URL parsing fails, set default values for all features
        features["has_ip_address"] = False
        features["is_shortened"] = False
        features["double_slash_redirect"] = False
        features["has_dash_in_domain"] = False
        features["subdomain_level"] = "Legitimate"
        features["https_token_in_domain"] = False
        
        # Domain-based features defaults
        features["domain_age"] = "Phishing"
        features["domain_registration_length"] = "Phishing"
        features["dns_record"] = False
        features["alexa_rank"] = "Phishing"
        
        # Still classify URL length even if parsing fails
        url_length = len(url)
        if url_length < 54:
            features["url_length"] = "Legitimate"
        elif 54 <= url_length <= 75:
            features["url_length"] = "Suspicious"
        else:
            features["url_length"] = "Phishing"
    
    # TODO: Implement additional feature extraction logic
    # Features might include:
    # - URL length
    # - Number of dots, slashes, special characters
    # - Presence of suspicious keywords
    # - Domain-based features
    # - HTTPS usage
    # - etc.
    
    return features


def check_url(url: str) -> str:
    """
    Simple function to quickly check if a URL is suspicious.
    
    Args:
        url (str): URL to check
        
    Returns:
        str: Simple assessment ("SAFE", "SUSPICIOUS", "DANGEROUS")
    """
    try:
        features = extract_features(url)
        
        # Count high-risk indicators
        danger_count = 0
        if features['has_ip_address']:
            danger_count += 1
        if features['url_length'] == 'Phishing':
            danger_count += 1
        if features['double_slash_redirect']:
            danger_count += 1
        if features['https_token_in_domain']:
            danger_count += 1
        if features['domain_age'] == 'Phishing':
            danger_count += 1
        if not features['dns_record']:
            danger_count += 1
            
        # Count medium-risk indicators
        suspect_count = 0
        if features['is_shortened']:
            suspect_count += 1
        if features['has_dash_in_domain']:
            suspect_count += 1
        if features['subdomain_level'] in ['Suspicious', 'Phishing']:
            suspect_count += 1
        if features['url_length'] == 'Suspicious':
            suspect_count += 1
            
        # Make assessment
        if danger_count >= 2:
            return "DANGEROUS"
        elif danger_count >= 1 or suspect_count >= 3:
            return "SUSPICIOUS"
        elif suspect_count >= 1:
            return "CAUTION"
        else:
            return "SAFE"
            
    except Exception:
        return "ERROR"


def load_model() -> Tuple[Any, Any]:
    """
    Load a pre-trained machine learning model and vectorizer for phishing detection.
    
    Returns:
        Tuple[Any, Any]: The loaded ML model and vectorizer, or (None, None) if loading fails
    """
    try:
        models_dir = os.path.join(os.path.dirname(__file__), 'models')
        model_path = os.path.join(models_dir, 'phishing_classifier.pkl')
        vectorizer_path = os.path.join(models_dir, 'tfidf_vectorizer.pkl')
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            model = joblib.load(model_path)
            vectorizer = joblib.load(vectorizer_path)
            logger.info("Successfully loaded ML model and vectorizer")
            
            # Load evaluation results if available
            results_path = os.path.join(models_dir, 'evaluation_results.json')
            if os.path.exists(results_path):
                with open(results_path, 'r') as f:
                    results = json.load(f)
                logger.info(f"Model accuracy: {results['accuracy']:.4f}")
            
            return model, vectorizer
        else:
            logger.warning("Model or vectorizer files not found")
            return None, None
    except Exception as e:
        logger.error(f"Could not load model: {e}")
        return None, None


def predict_with_ml(url: str, model: Any, vectorizer: Any) -> Dict[str, Any]:
    """
    Use the trained ML model to predict if a URL is phishing.
    
    Args:
        url (str): URL to analyze
        model: Trained ML model
        vectorizer: Fitted TF-IDF vectorizer
        
    Returns:
        Dict[str, Any]: Prediction results with confidence scores
    """
    try:
        # Transform URL using the same vectorizer used in training
        url_vec = vectorizer.transform([url])
        
        # Get prediction and confidence
        prediction = model.predict(url_vec)[0]
        confidence_scores = model.predict_proba(url_vec)[0]
        
        return {
            'prediction': 'phishing' if prediction == 1 else 'legitimate',
            'confidence': float(max(confidence_scores)),
            'confidence_scores': {
                'legitimate': float(confidence_scores[0]),
                'phishing': float(confidence_scores[1])
            },
            'method': 'machine_learning'
        }
    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        return None


def features_to_vector(features: Dict[str, Any]) -> list:
    """Convert feature dictionary to numerical vector for ML models."""
    vector = []
    
    # Boolean features (0 or 1)
    vector.append(1 if features['has_ip_address'] else 0)
    vector.append(1 if features['is_shortened'] else 0)
    vector.append(1 if features['double_slash_redirect'] else 0)
    vector.append(1 if features['has_dash_in_domain'] else 0)
    vector.append(1 if features['https_token_in_domain'] else 0)
    vector.append(1 if features['dns_record'] else 0)
    
    # Categorical features (convert to numerical)
    url_length_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(url_length_map.get(features['url_length'], 2))
    
    subdomain_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(subdomain_map.get(features['subdomain_level'], 2))
    
    domain_age_map = {'Legitimate': 0, 'Phishing': 1}
    vector.append(domain_age_map.get(features['domain_age'], 1))
    
    reg_length_map = {'Legitimate': 0, 'Phishing': 1}
    vector.append(reg_length_map.get(features['domain_registration_length'], 1))
    
    alexa_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(alexa_map.get(features['alexa_rank'], 2))
    
    return vector


def rule_based_classification(features: Dict[str, Any]) -> Dict[str, Any]:
    """Simple rule-based classification as fallback."""
    phishing_score = 0
    
    # High risk indicators
    if features['has_ip_address']:
        phishing_score += 2
    if features['url_length'] == 'Phishing':
        phishing_score += 2
    if features['double_slash_redirect']:
        phishing_score += 2
    if features['https_token_in_domain']:
        phishing_score += 2
    if features['domain_age'] == 'Phishing':
        phishing_score += 2
    if not features['dns_record']:
        phishing_score += 2
    
    # Medium risk indicators
    if features['is_shortened']:
        phishing_score += 1
    if features['has_dash_in_domain']:
        phishing_score += 1
    if features['subdomain_level'] == 'Phishing':
        phishing_score += 1
    elif features['subdomain_level'] == 'Suspicious':
        phishing_score += 0.5
    if features['url_length'] == 'Suspicious':
        phishing_score += 0.5
    
    # Classification based on score
    if phishing_score >= 4:
        prediction = 'phishing'
        confidence = 0.9
    elif phishing_score >= 2:
        prediction = 'phishing'
        confidence = 0.7
    else:
        prediction = 'legitimate'
        confidence = 0.6
    
    return {
        'prediction': prediction,
        'confidence': confidence,
        'phishing_score': phishing_score,
        'method': 'rule_based'
    }


def classify_url(features: Dict[str, Any] = None, url: str = None, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Classify a URL as phishing or legitimate using both ML and rule-based methods.
    
    Args:
        features (Dict[str, Any]): Dictionary of extracted features (optional)
        url (str): URL to classify (required for ML method)
        model: Pre-trained ML model (optional)
        vectorizer: Fitted vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Classification result including prediction and confidence
    """
    try:
        # Try ML prediction first if model and URL are available
        if model is not None and vectorizer is not None and url is not None:
            ml_result = predict_with_ml(url, model, vectorizer)
            if ml_result is not None:
                # Also get rule-based prediction for comparison
                if features is None:
                    features = extract_features(url)
                rule_result = rule_based_classification(features)
                
                # Combine results
                ml_result['rule_based_prediction'] = rule_result['prediction']
                ml_result['rule_based_score'] = rule_result['phishing_score']
                ml_result['features'] = features
                
                return ml_result
        
        # Fall back to rule-based classification
        if features is None and url is not None:
            features = extract_features(url)
        elif features is None:
            raise ValueError("Either features or url must be provided")
            
        return rule_based_classification(features)
        
    except Exception as e:
        logger.error(f"Classification failed: {e}")
        # Return safe default
        return {
            'prediction': 'error',
            'confidence': 0.0,
            'method': 'error',
            'error': str(e)
        }


def check_url_enhanced(url: str, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Enhanced URL checking with detailed analysis.
    
    Args:
        url (str): URL to check
        model: ML model (optional)
        vectorizer: Vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Detailed analysis results
    """
    try:
        # Extract features
        features = extract_features(url)
        
        # Get classification
        classification = classify_url(features=features, url=url, model=model, vectorizer=vectorizer)
        
        # Calculate risk assessment
        risk_level = "LOW"
        if classification['prediction'] == 'phishing':
            if classification['confidence'] > 0.8:
                risk_level = "HIGH"
            elif classification['confidence'] > 0.6:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW-MEDIUM"
        
        return {
            'url': url,
            'risk_level': risk_level,
            'classification': classification,
            'features': features,
            'recommendations': get_recommendations(features, classification)
        }
        
    except Exception as e:
        logger.error(f"Enhanced URL check failed: {e}")
        return {
            'url': url,
            'risk_level': "ERROR",
            'error': str(e)
        }


def get_recommendations(features: Dict[str, Any], classification: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on analysis."""
    recommendations = []
    
    if classification['prediction'] == 'phishing':
        recommendations.append("⚠️  DO NOT enter personal information on this site")
        recommendations.append("⚠️  DO NOT download files from this site")
        
    if features.get('has_ip_address'):
        recommendations.append("🔍 URL uses IP address instead of domain name")
    
    if features.get('is_shortened'):
        recommendations.append("🔍 Shortened URL - check the actual destination")
    
    if features.get('https_token_in_domain'):
        recommendations.append("🔍 Domain contains 'https' - potential impersonation")
    
    if not features.get('dns_record'):
        recommendations.append("🔍 Domain has no DNS record - highly suspicious")
    
    if classification['prediction'] == 'legitimate':
        recommendations.append("✅ URL appears to be legitimate")
        recommendations.append("💡 Still verify the site's authenticity through official channels")
    
    return recommendations


def main() -> None:
    """
    Main function demonstrating the layered detection system with GPU support.
    """
    print("🛡️  Layered Phishing Detection System v3.0 - GPU Accelerated")
    print("="*70)
    
    # Initialize the layered detector
    detector = LayeredPhishingDetector()
    
    # Check GPU status
    try:
        import xgboost as xgb
        gpu_count = xgb.gpu.get_gpu_count()
        if gpu_count > 0:
            print(f"🚀 GPU acceleration available: {gpu_count} device(s)")
        else:
            print("🔄 Running on CPU")
    except:
        print("🔄 Running on CPU")
    
    # Test URLs
    test_urls = [
        "https://google.com",
        "https://github.com", 
        "http://192.168.1.1/login",
        "https://bit.ly/3abc123",
        "https://https-paypal-security.suspicious-bank.com/login//redirect.php",
        "smilesvoegol.servebbs.org/voegol.php",
        "https://amazon-security-verification-account-suspended-click-here-now.malicious-site.net/update",
    ]
    
    # Performance summary
    total_processing_time = 0
    for i, url in enumerate(test_urls, 1):
        print(f"\n{'='*80}")
        print(f"🌐 Test {i}: {url}")
        print(f"📏 Length: {len(url)} characters")
        print("-" * 80)
        
        # Analyze URL through all layers
        analysis = detector.analyze_url(url)
        total_processing_time += analysis['processing_time']
        
        # Display results
        final_result = analysis.get('final_result', {})
        
        if 'error' not in analysis:
            verdict = final_result.get('final_verdict', RiskLevel.ERROR)
            risk_pct = final_result.get('risk_percentage', 0)
            confidence = final_result.get('confidence', 0)
            
            print(f"🎯 FINAL VERDICT: {verdict.value if isinstance(verdict, RiskLevel) else verdict}")
            print(f"📊 Risk Level: {risk_pct:.1f}%")
            print(f"🎪 Confidence: {confidence:.3f}")
            print(f"⏱️  Processing Time: {analysis['processing_time']:.3f}s")
            
            # Show ML layer performance info
            for layer_result in analysis['layer_results']:
                if layer_result.get('layer') == 'ML Classification':
                    model_info = layer_result.get('model_info', {})
                    inference_time = layer_result.get('inference_time', 0)
                    print(f"🤖 ML Model: {model_info.get('type', 'Unknown')} "
                          f"({'GPU' if model_info.get('gpu_accelerated') else 'CPU'}) - "
                          f"{inference_time*1000:.1f}ms")
            
            # Show layer-by-layer results
            print(f"\n📋 Layer Analysis:")
            for j, layer_result in enumerate(analysis['layer_results'], 1):
                layer_name = layer_result.get('layer', f'Layer {j}')
                risk_score = layer_result.get('risk_score', 0)
                flags = layer_result.get('flags', [])
                
                print(f"   Layer {j} ({layer_name}): {risk_score:.1f}% risk")
                if flags:
                    for flag in flags[:2]:  # Show first 2 flags
                        print(f"     • {flag}")
                    if len(flags) > 2:
                        print(f"     • ... and {len(flags)-2} more issues")
            
            # Show recommendations
            recommendations = final_result.get('recommendations', [])
            if recommendations:
                print(f"\n💡 Recommendations:")
                for rec in recommendations[:3]:  # Show top 3
                    print(f"   {rec}")
                if len(recommendations) > 3:
                    print(f"   ... and {len(recommendations)-3} more recommendations")
        
        else:
            print(f"❌ Analysis Error: {analysis.get('error', 'Unknown error')}")
    
    # Performance summary
    avg_time = total_processing_time / len(test_urls)
    urls_per_second = len(test_urls) / total_processing_time
    
    print(f"\n{'='*70}")
    print(f"📊 PERFORMANCE SUMMARY")
    print(f"{'='*70}")
    print(f"🌐 Total URLs processed: {len(test_urls)}")
    print(f"⏱️  Total processing time: {total_processing_time:.3f}s")
    print(f"📈 Average time per URL: {avg_time:.3f}s")
    print(f"🚀 URLs per second: {urls_per_second:.1f}")

if __name__ == "__main__":
    main()
