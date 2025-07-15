"""
Fix Missing Classes Script

This script adds any missing layer classes to the phishing_detector.py file.
"""

import os
import re
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("fix_dependencies")

PHISHING_DETECTOR_PATH = os.path.join(os.path.dirname(__file__), "phishing_detector.py")

def check_for_missing_classes():
    """Check for missing classes in the phishing_detector.py file."""
    if not os.path.exists(PHISHING_DETECTOR_PATH):
        logger.error(f"Could not find phishing_detector.py at {PHISHING_DETECTOR_PATH}")
        return False
    
    with open(PHISHING_DETECTOR_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Required layer classes
    required_classes = [
        "Layer1_BasicValidation",
        "Layer2_FeatureAnalysis",
        "Layer2_ContentAnalysis", 
        "Layer3_MLClassification",
        "Layer4_EnsembleDecision", 
        "Layer5_FinalVerdict"
    ]
    
    missing_classes = []
    
    # Check which classes are missing
    for class_name in required_classes:
        if f"class {class_name}" not in content:
            missing_classes.append(class_name)
    
    return missing_classes

def add_missing_classes(missing_classes):
    """Add missing classes to phishing_detector.py file."""
    if not missing_classes:
        logger.info("No missing classes found.")
        return True
    
    with open(PHISHING_DETECTOR_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Define class templates
    class_templates = {
        "Layer2_FeatureAnalysis": '''
class Layer2_FeatureAnalysis(DetectionLayer):
    """
    Layer 2: Feature Analysis
    - Domain-based features
    - URL structure analysis
    - WHOIS data analysis
    """
    
    def __init__(self):
        super().__init__("Feature Analysis", weight=1.0)
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL features."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'details': {}
        }
        
        try:
            # Extract features
            features = extract_features(url)
            
            # Assess risk based on features
            risk_score = 0.0
            
            # 1. Check for IP address in URL
            if features.get('has_ip_address', False):
                results['flags'].append("IP address used in URL")
                risk_score += 20
            
            # 2. Check URL length
            if features.get('url_length') == 'Suspicious':
                results['flags'].append("Suspicious URL length")
                risk_score += 15
            elif features.get('url_length') == 'Phishing':
                results['flags'].append("Very long URL")
                risk_score += 30
            
            # 3. Check for shortened URL
            if features.get('is_shortened', False):
                results['flags'].append("URL shortening service detected")
                risk_score += 25
            
            # 4. Check for double slash redirect
            if features.get('double_slash_redirect', False):
                results['flags'].append("Double slash redirect detected")
                risk_score += 10
            
            # 5. Check for dash in domain
            if features.get('has_dash_in_domain', False):
                results['flags'].append("Domain contains dashes")
                risk_score += 15
            
            # 6. Check subdomain level
            if features.get('subdomain_level') == 'Suspicious':
                results['flags'].append("Suspicious subdomain depth")
                risk_score += 20
            elif features.get('subdomain_level') == 'Phishing':
                results['flags'].append("Excessive subdomain levels")
                risk_score += 35
            
            # 7. Check for HTTPS in domain (not in protocol)
            if features.get('https_token_in_domain', False):
                results['flags'].append("HTTPS token in domain name")
                risk_score += 40
            
            # 8. Check domain age
            if features.get('domain_age') == 'Phishing':
                results['flags'].append("Domain registered less than 6 months ago")
                risk_score += 25
            
            # 9. Check domain expiry
            if features.get('domain_registration_length') == 'Phishing':
                results['flags'].append("Domain expires in less than 1 year")
                risk_score += 15
            
            # 10. Check DNS record
            if not features.get('dns_record', True):
                results['flags'].append("No DNS record found")
                risk_score += 30
            
            # Set final risk score (cap at 100)
            results['risk_score'] = min(100, risk_score)
            results['details'] = features
            
        except Exception as e:
            results['flags'].append(f"Feature analysis error: {str(e)}")
            results['risk_score'] = 10  # Small default risk for errors
        
        return results
''',
        "Layer3_MLClassification": '''
class Layer3_MLClassification(DetectionLayer):
    """
    Layer 3: Machine Learning Classification
    - Uses trained ML model to classify URLs
    - Provides confidence scores for phishing probability
    """
    
    def __init__(self):
        super().__init__("ML Classification", weight=1.5)  # Higher weight for ML predictions
        self.model = None
        self.vectorizer = None
        self._load_model()
    
    def _load_model(self):
        """Load ML model and vectorizer."""
        try:
            self.model, self.vectorizer = load_model()
            if self.model is not None and self.vectorizer is not None:
                logger.info("ML model and vectorizer loaded successfully")
            else:
                logger.warning("ML model or vectorizer not loaded")
                self.enabled = False
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.enabled = False
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL using ML model."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': []
        }
        
        try:
            if not self.model or not self.vectorizer:
                results['flags'].append("ML model not available")
                results['risk_score'] = 0
                return results
            
            # Start timing for inference
            start_time = datetime.now()
            
            # Get ML prediction
            prediction = predict_with_ml(url, self.model, self.vectorizer)
            
            # End timing
            inference_time = (datetime.now() - start_time).total_seconds()
            
            if prediction is None:
                results['flags'].append("ML prediction failed")
                results['risk_score'] = 30
                return results
            
            # Extract information from prediction
            is_phishing = prediction['prediction'] == 'phishing'
            confidence = prediction.get('confidence', 0)
            confidence_scores = prediction.get('confidence_scores', {})
            
            # Add results
            results['ml_prediction'] = prediction['prediction']
            results['confidence_scores'] = confidence_scores
            results['inference_time'] = inference_time
            
            # Set risk score based on phishing probability
            if is_phishing:
                phish_confidence = confidence_scores.get('phishing', confidence)
                # Scale to risk score from 0-100
                results['risk_score'] = min(100, phish_confidence * 100)
                
                # Add flags based on confidence
                if phish_confidence > 0.8:
                    results['flags'].append("High probability of phishing")
                elif phish_confidence > 0.6:
                    results['flags'].append("Medium probability of phishing")
                else:
                    results['flags'].append("Low probability of phishing")
            else:
                # If legitimate, risk score is inverse of legitimate confidence
                legit_confidence = confidence_scores.get('legitimate', 1 - confidence)
                results['risk_score'] = min(100, (1 - legit_confidence) * 80)  # Cap at 80 for negative predictions
            
            # Add model info
            try:
                model_type = "RandomForest"
                if "XGBClassifier" in str(type(self.model)):
                    model_type = "XGBoost"
                
                # Check if model uses GPU
                gpu_accelerated = False
                if hasattr(self.model, 'get_params'):
                    params = self.model.get_params()
                    if 'tree_method' in params:
                        gpu_accelerated = 'gpu' in params['tree_method']
                
                results['model_info'] = {
                    'type': model_type,
                    'accuracy': 0.8147,  # Placeholder - should come from evaluation
                    'gpu_accelerated': gpu_accelerated
                }
            except:
                # Ignore if model info collection fails
                pass
            
        except Exception as e:
            results['flags'].append(f"ML classification error: {str(e)}")
            results['risk_score'] = 10  # Small default risk for errors
        
        return results
''',
        "Layer4_EnsembleDecision": '''
class Layer4_EnsembleDecision(DetectionLayer):
    """
    Layer 4: Ensemble Decision
    - Combines results from previous layers
    - Resolves conflicts between layers
    - Produces weighted risk score
    """
    
    def __init__(self):
        super().__init__("Ensemble Decision")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Combine results from previous layers."""
        results = {
            'layer': self.name,
            'weighted_risk_score': 0.0,
            'layer_scores': {},
            'consensus': None,
            'conflicts': []
        }
        
        try:
            if not context or 'layer_results' not in context:
                results['weighted_risk_score'] = 50
                results['consensus'] = "ERROR"
                results['conflicts'].append("No layer results found")
                return results
            
            layer_results = context['layer_results']
            
            # Calculate weighted risk score
            total_weight = 0
            weighted_score = 0
            layer_votes = {'phishing': 0, 'legitimate': 0, 'unknown': 0}
            
            # Track scores for each layer
            for layer_result in layer_results:
                layer_name = layer_result.get('layer', 'Unknown')
                risk_score = layer_result.get('risk_score', 0)
                weight = layer_result.get('weight', 1.0)
                
                # Add to weighted score
                weighted_score += risk_score * weight
                total_weight += weight
                
                # Record layer score
                results['layer_scores'][layer_name] = risk_score
                
                # Determine layer vote
                if risk_score >= 60:  # High risk
                    layer_votes['phishing'] += 1
                elif risk_score <= 30:  # Low risk
                    layer_votes['legitimate'] += 1
                else:
                    layer_votes['unknown'] += 1
            
            # Calculate final weighted score
            if total_weight > 0:
                results['weighted_risk_score'] = weighted_score / total_weight
            else:
                results['weighted_risk_score'] = 50
            
            # Determine consensus
            if layer_votes['phishing'] > layer_votes['legitimate'] + layer_votes['unknown']:
                results['consensus'] = "PHISHING"
            elif layer_votes['legitimate'] > layer_votes['phishing'] + layer_votes['unknown']:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['phishing'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['legitimate'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "PHISHING"
            else:
                results['consensus'] = "UNCERTAIN"
            
            # Check for conflicts
            if layer_votes['phishing'] > 0 and layer_votes['legitimate'] > 0:
                results['conflicts'].append("Layers disagree on classification")
            
            # Check for strong ML disagreement
            ml_result = None
            for layer_result in layer_results:
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction == 'phishing' and results['weighted_risk_score'] < 40:
                        results['conflicts'].append("ML says phishing but other layers disagree")
                    elif ml_prediction == 'legitimate' and results['weighted_risk_score'] > 60:
                        results['conflicts'].append("ML says legitimate but other layers disagree")
                    ml_result = layer_result
                    break
            
            # If ML is very confident, increase its influence
            if ml_result and 'confidence_scores' in ml_result:
                ml_confidence = max(ml_result['confidence_scores'].values()) if ml_result['confidence_scores'] else 0
                if ml_confidence > 0.9:  # Very high confidence
                    ml_prediction = ml_result.get('ml_prediction')
                    if ml_prediction == 'phishing':
                        results['weighted_risk_score'] = max(results['weighted_risk_score'], 
                                                            results['weighted_risk_score'] * 1.2)  # Increase by 20%
                    elif ml_prediction == 'legitimate':
                        results['weighted_risk_score'] = min(results['weighted_risk_score'], 
                                                           results['weighted_risk_score'] * 0.8)  # Decrease by 20%
            
        except Exception as e:
            results['weighted_risk_score'] = 50
            results['consensus'] = "ERROR"
            results['conflicts'].append(f"Ensemble error: {str(e)}")
        
        return results
''',
        "Layer5_FinalVerdict": '''
class Layer5_FinalVerdict(DetectionLayer):
    """
    Layer 5: Final Verdict
    - Determines final risk level
    - Provides recommendations
    - Aggregates warnings and details
    """
    
    def __init__(self):
        super().__init__("Final Verdict")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate final verdict and recommendations."""
        results = {
            'final_verdict': RiskLevel.ERROR,
            'risk_percentage': 50,
            'confidence': 0.0,
            'recommendations': [],
            'summary': {},
            'early_termination': False
        }
        
        try:
            if not context:
                results['final_verdict'] = RiskLevel.ERROR
                results['risk_percentage'] = 50
                results['recommendations'].append("Analysis failed - insufficient data")
                return results
            
            # Check for early termination
            if 'final_result' in context and context['final_result'].get('early_termination', False):
                return context['final_result']
            
            # Get ensemble result
            ensemble_result = context.get('ensemble_result', {})
            risk_score = ensemble_result.get('weighted_risk_score', 50)
            consensus = ensemble_result.get('consensus', 'UNCERTAIN')
            conflicts = ensemble_result.get('conflicts', [])
            
            # Set risk percentage
            results['risk_percentage'] = risk_score
            
            # Determine confidence based on conflicts
            if not conflicts:
                confidence = 0.9  # High confidence if no conflicts
            elif len(conflicts) == 1:
                confidence = 0.7  # Medium confidence with one conflict
            else:
                confidence = 0.5  # Low confidence with multiple conflicts
                
            results['confidence'] = confidence
            
            # Determine final risk level
            if risk_score >= 75:
                results['final_verdict'] = RiskLevel.CRITICAL
            elif risk_score >= 60:
                results['final_verdict'] = RiskLevel.HIGH
            elif risk_score >= 35:
                results['final_verdict'] = RiskLevel.MEDIUM
            elif risk_score >= 15:
                results['final_verdict'] = RiskLevel.LOW
            else:
                results['final_verdict'] = RiskLevel.SAFE
            
            # Generate recommendations based on risk level
            if results['final_verdict'] in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                results['recommendations'].extend([
                    "Do NOT proceed to this website",
                    "Do NOT enter any personal information",
                    "Do NOT download any files from this site"
                ])
            elif results['final_verdict'] == RiskLevel.MEDIUM:
                results['recommendations'].extend([
                    "Proceed with extreme caution",
                    "Verify the website through other channels before sharing information",
                    "Check the URL carefully for typos or unusual characters"
                ])
            elif results['final_verdict'] == RiskLevel.LOW:
                results['recommendations'].extend([
                    "Exercise normal caution",
                    "Verify the website if sharing sensitive information"
                ])
            else:  # SAFE
                results['recommendations'].extend([
                    "Website appears safe",
                    "Follow normal security practices"
                ])
            
            # Add any specific warnings from layers
            layer_flags = []
            for layer_result in context.get('layer_results', []):
                layer_flags.extend(layer_result.get('flags', []))
            
            if layer_flags:
                results['summary']['warnings'] = layer_flags[:5]  # Include top 5 warnings
                
            # If ML prediction exists, add to summary
            for layer_result in context.get('layer_results', []):
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction:
                        results['summary']['ml_prediction'] = ml_prediction
                    break
            
        except Exception as e:
            results['final_verdict'] = RiskLevel.ERROR
            results['risk_percentage'] = 50
            results['recommendations'].append(f"Analysis error: {str(e)}")
        
        return results
'''
    }
    
    # Find location to insert classes - after the last class definition
    last_class_pos = 0
    for match in re.finditer(r'class\s+[A-Za-z0-9_]+\(', content):
        last_class_pos = max(last_class_pos, match.start())
    
    # Find end of last class
    if last_class_pos > 0:
        # Find the indentation level of the class
        class_line = content[last_class_pos:content.find('\n', last_class_pos)]
        indentation_match = re.match(r'(\s*)', class_line)
        indentation = indentation_match.group(1) if indentation_match else ''
        
        # Find end of class by looking for next unindented def/class or end of file
        end_pos = len(content)
        next_class_pos = content.find(f"\n{indentation}class", last_class_pos + 1)
        next_def_pos = content.find(f"\n{indentation}def", last_class_pos + 1)
        
        if next_class_pos > 0:
            end_pos = min(end_pos, next_class_pos)
        if next_def_pos > 0:
            end_pos = min(end_pos, next_def_pos)
        
        # Move to the end of the current class
        while end_pos < len(content):
            if content[end_pos:].lstrip().startswith('class') or content[end_pos:].lstrip().startswith('def'):
                break
            end_pos += 1
            if content[end_pos-1:end_pos] == '\n':
                line_start = content.rfind('\n', 0, end_pos-1) + 1
                line = content[line_start:end_pos-1]
                if not line.strip() or line.strip() and not line.startswith(indentation + ' '):
                    break
    else:
        # If no class found, insert at the end
        end_pos = len(content)
    
    # Construct code to add
    code_to_add = "\n\n"
    
    for class_name in missing_classes:
        if class_name in class_templates:
            code_to_add += class_templates[class_name] + "\n\n"
            logger.info(f"Added template for {class_name}")
        else:
            logger.warning(f"No template available for {class_name}")
    
    # Insert the code
    new_content = content[:end_pos] + code_to_add + content[end_pos:]
    
    # Write back to file
    with open(PHISHING_DETECTOR_PATH, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    logger.info(f"Successfully updated {PHISHING_DETECTOR_PATH}")
    return True

def fix_detector_imports():
    """Check and fix imports in the phishing_detector.py file."""
    with open(PHISHING_DETECTOR_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    required_imports = [
        ('from enum import Enum', 'import enum'),
        ('from datetime import datetime', 'import datetime'),
        ('from typing import Dict, List, Any, Optional, Tuple', 'import typing')
    ]
    
    modified = False
    for req_import, alt_import in required_imports:
        if req_import not in content and alt_import not in content:
            # Find the last import line
            import_lines = re.findall(r'^import.*$|^from.*import.*$', content, re.MULTILINE)
            if import_lines:
                last_import = import_lines[-1]
                last_import_pos = content.rfind(last_import) + len(last_import)
                content = content[:last_import_pos] + '\n' + req_import + content[last_import_pos:]
                modified = True
            else:
                # No imports found, add at the beginning
                content = req_import + '\n' + content
                modified = True
    
    if modified:
        with open(PHISHING_DETECTOR_PATH, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info("Added missing imports to phishing_detector.py")
    
    return modified

def fix_layered_detector_initialization():
    """Fix the LayeredPhishingDetector initialization to include all layers in the correct order."""
    with open(PHISHING_DETECTOR_PATH, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the LayeredPhishingDetector class
    detector_class_match = re.search(r'class LayeredPhishingDetector.*?def __init__\(self\):(.*?)self\.layers = \[(.*?)\]', 
                                    content, re.DOTALL)
    
    if not detector_class_match:
        logger.error("Could not find LayeredPhishingDetector initialization")
        return False
    
    layers_content = detector_class_match.group(2)
    
    # Define the correct layer order
    correct_layers = [
        "Layer1_BasicValidation()",
        "Layer2_FeatureAnalysis()",
        "Layer2_ContentAnalysis()",
        "Layer3_MLClassification()",
        "Layer4_EnsembleDecision()",
        "Layer5_FinalVerdict()"
    ]
    
    # Generate the new layers list
    new_layers = ',\n            '.join(correct_layers)
    new_layers_text = f"[\n            {new_layers}\n        ]"
    
    # Replace the existing layers list
    new_content = re.sub(r'self\.layers = \[(.*?)\]', f'self.layers = {new_layers_text}', 
                         content, flags=re.DOTALL)
    
    if new_content != content:
        with open(PHISHING_DETECTOR_PATH, 'w', encoding='utf-8') as f:
            f.write(new_content)
        logger.info("Fixed LayeredPhishingDetector initialization")
        return True
    
    return False

def main():
    """Main function to fix phishing_detector.py."""
    print("="*70)
    print("PHISHING DETECTOR FIXER")
    print("="*70)
    
    if not os.path.exists(PHISHING_DETECTOR_PATH):
        logger.error(f"phishing_detector.py not found at {PHISHING_DETECTOR_PATH}")
        return False
    
    # Check for missing classes
    missing_classes = check_for_missing_classes()
    
    if missing_classes:
        logger.info(f"Found missing classes: {', '.join(missing_classes)}")
        add_missing_classes(missing_classes)
    else:
        logger.info("All required classes are present.")
    
    # Fix imports
    fix_detector_imports()
    
    # Fix LayeredPhishingDetector initialization
    fix_layered_detector_initialization()
    
    print("\n✅ Fixes applied to phishing_detector.py")
    print("💡 Please restart your API server with: python api_server.py")
    return True

if __name__ == "__main__":
    main()
