"""
Phishing Detector Sensitivity Adjuster

This tool helps to:
1. Test specific URLs with different sensitivity settings
2. Adjust and calibrate detection thresholds
3. Report detailed detection breakdown
"""

import os
import sys
import logging
import argparse
from typing import List, Dict, Any, Optional
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from phishing_detector import LayeredPhishingDetector, RiskLevel
    from api_server import process_analysis_results
except ImportError:
    logger.error("Could not import detector modules. Make sure you're running from the project directory.")
    sys.exit(1)

# Known phishing URLs for testing (only to be used with permission)
TEST_PHISHING_URLS = [
    "https://amaz0n-account-login.com/signin",
    "https://secure-banking-login.suspicious-domain.com/update-account",
    "http://paypal-secure-login.info/verification",
    "https://update-your-account-information.com/login"
]

# Legitimate URLs for testing
TEST_LEGITIMATE_URLS = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://apple.com"
]

class SensitivityTester:
    """Tool for testing and adjusting phishing detection sensitivity."""
    
    def __init__(self, detector=None):
        """Initialize with optional detector instance."""
        self.detector = detector or LayeredPhishingDetector()
        self.current_thresholds = {
            "CRITICAL": 65,  # Default values
            "HIGH": 50,
            "MEDIUM": 30,
            "LOW": 10
        }
    
    def test_url(self, url: str, verbose: bool = False) -> Dict[str, Any]:
        """Test a single URL with the current detector configuration."""
        start_time = time.time()
        analysis = self.detector.analyze_url(url)
        processing_time = time.time() - start_time
        
        # Get results
        final_result = analysis.get('final_result', {})
        verdict = final_result.get('final_verdict')
        risk_percentage = final_result.get('risk_percentage', 0)
        
        # Extract ML prediction
        ml_prediction = None
        ml_confidence = 0
        for layer_result in analysis.get('layer_results', []):
            if layer_result.get('layer') == 'ML Classification':
                ml_prediction = layer_result.get('ml_prediction')
                ml_scores = layer_result.get('confidence_scores', {})
                ml_confidence = ml_scores.get('phishing', 0)
                break
        
        # Format result for display
        result = {
            'url': url,
            'verdict': verdict.value if hasattr(verdict, 'value') else str(verdict),
            'risk_percentage': risk_percentage,
            'processing_time': processing_time,
            'ml_prediction': ml_prediction,
            'ml_confidence': ml_confidence,
            'flags': []
        }
        
        # Collect flags from all layers
        for layer_result in analysis.get('layer_results', []):
            layer_name = layer_result.get('layer')
            flags = layer_result.get('flags', [])
            risk_score = layer_result.get('risk_score', 0)
            
            if flags:
                result['flags'].extend([f"{layer_name}: {flag}" for flag in flags])
        
        if verbose:
            # Show full analysis
            print(f"\n{'='*80}")
            print(f"DETAILED ANALYSIS FOR: {url}")
            print(f"{'='*80}")
            print(f"VERDICT: {result['verdict']}")
            print(f"RISK: {result['risk_percentage']:.1f}%")
            print(f"ML PREDICTION: {result['ml_prediction']} (confidence: {ml_confidence:.3f})")
            print(f"\nDETECTION FLAGS:")
            for flag in result['flags']:
                print(f"  - {flag}")
            print(f"\nLAYER BREAKDOWN:")
            
            for layer_result in analysis.get('layer_results', []):
                layer_name = layer_result.get('layer')
                risk_score = layer_result.get('risk_score', 0)
                weight = layer_result.get('weight', 1.0)
                print(f"  {layer_name}: {risk_score:.1f}% risk (weight: {weight})")
                
        return result
    
    def batch_test(self, urls: List[str], verbose: bool = False) -> Dict[str, Any]:
        """Run batch testing on a list of URLs."""
        results = []
        start_time = time.time()
        
        for url in urls:
            result = self.test_url(url, verbose=verbose)
            results.append(result)
            
        total_time = time.time() - start_time
        
        # Aggregate statistics
        stats = {
            'total_urls': len(urls),
            'total_time': total_time,
            'avg_time_per_url': total_time / len(urls),
            'verdict_counts': {},
            'flags_frequency': {}
        }
        
        # Count verdicts
        for result in results:
            verdict = result['verdict']
            if verdict not in stats['verdict_counts']:
                stats['verdict_counts'][verdict] = 0
            stats['verdict_counts'][verdict] += 1
            
            # Count flag frequency
            for flag in result['flags']:
                if flag not in stats['flags_frequency']:
                    stats['flags_frequency'][flag] = 0
                stats['flags_frequency'][flag] += 1
        
        return {'results': results, 'stats': stats}
    
    def adjust_thresholds(self, critical=None, high=None, medium=None, low=None):
        """Adjust risk level thresholds."""
        if critical is not None:
            self.current_thresholds["CRITICAL"] = critical
        if high is not None:
            self.current_thresholds["HIGH"] = high
        if medium is not None:
            self.current_thresholds["MEDIUM"] = medium
        if low is not None:
            self.current_thresholds["LOW"] = low
            
        # Update detector thresholds - would require implementation in the detector
        print(f"Updated thresholds: {self.current_thresholds}")
        
    def compare_sensitivity(self, urls: List[str]) -> Dict[str, Any]:
        """Compare different sensitivity settings."""
        original_thresholds = self.current_thresholds.copy()
        
        sensitivity_levels = {
            "Very Low": {"CRITICAL": 85, "HIGH": 70, "MEDIUM": 45, "LOW": 20},
            "Low": {"CRITICAL": 75, "HIGH": 60, "MEDIUM": 35, "LOW": 15},
            "Medium": {"CRITICAL": 65, "HIGH": 50, "MEDIUM": 30, "LOW": 10},
            "High": {"CRITICAL": 55, "HIGH": 40, "MEDIUM": 25, "LOW": 8},
            "Very High": {"CRITICAL": 45, "HIGH": 30, "MEDIUM": 20, "LOW": 5}
        }
        
        results = {}
        
        for name, thresholds in sensitivity_levels.items():
            print(f"Testing sensitivity level: {name}")
            self.adjust_thresholds(**thresholds)
            
            batch_results = self.batch_test(urls, verbose=False)
            results[name] = {
                'thresholds': thresholds.copy(),
                'verdict_counts': batch_results['stats']['verdict_counts']
            }
        
        # Restore original thresholds
        self.adjust_thresholds(**original_thresholds)
        
        return results
    
    def test_specific_url(self, url: str) -> None:
        """Interactive testing of a specific URL."""
        print(f"\n{'='*80}")
        print(f"INTERACTIVE URL TESTING: {url}")
        print(f"{'='*80}")
        
        result = self.test_url(url, verbose=True)
        
        # Show sensitivity comparison
        print(f"\n{'='*80}")
        print("SENSITIVITY COMPARISON")
        print(f"{'='*80}")
        
        sensitivity_levels = {
            "Very Low": {"CRITICAL": 85, "HIGH": 70, "MEDIUM": 45, "LOW": 20},
            "Low": {"CRITICAL": 75, "HIGH": 60, "MEDIUM": 35, "LOW": 15},
            "Medium": {"CRITICAL": 65, "HIGH": 50, "MEDIUM": 30, "LOW": 10},
            "High": {"CRITICAL": 55, "HIGH": 40, "MEDIUM": 25, "LOW": 8},
            "Very High": {"CRITICAL": 45, "HIGH": 30, "MEDIUM": 20, "LOW": 5}
        }
        
        print(f"{'Level':<12} {'Verdict':<12} {'Risk Score':<12}")
        print(f"{'-'*40}")
        
        original_thresholds = self.current_thresholds.copy()
        
        for name, thresholds in sensitivity_levels.items():
            self.adjust_thresholds(**thresholds)
            test_result = self.test_url(url, verbose=False)
            print(f"{name:<12} {test_result['verdict']:<12} {test_result['risk_percentage']:.1f}%")
        
        # Restore original thresholds
        self.adjust_thresholds(**original_thresholds)

def main():
    parser = argparse.ArgumentParser(description="Phishing Detector Sensitivity Testing Tool")
    parser.add_argument("--url", help="Test a specific URL")
    parser.add_argument("--test-known", action="store_true", help="Test with known phishing and legitimate URLs")
    parser.add_argument("--batch", help="Test a batch of URLs from a file (one URL per line)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    parser.add_argument("--sensitivity", choices=["very-low", "low", "medium", "high", "very-high"], 
                       help="Set sensitivity level")
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = SensitivityTester()
    
    # Apply sensitivity setting if specified
    if args.sensitivity:
        sensitivity_map = {
            "very-low": {"critical": 85, "high": 70, "medium": 45, "low": 20},
            "low": {"critical": 75, "high": 60, "medium": 35, "low": 15},
            "medium": {"critical": 65, "high": 50, "medium": 30, "low": 10},
            "high": {"critical": 55, "high": 40, "medium": 25, "low": 8},
            "very-high": {"critical": 45, "high": 30, "medium": 20, "low": 5}
        }
        tester.adjust_thresholds(**sensitivity_map[args.sensitivity])
    
    # Test a single URL
    if args.url:
        tester.test_specific_url(args.url)
        
    # Test with known URLs
    elif args.test_known:
        print("\n--- Testing Known Phishing URLs ---")
        phishing_results = tester.batch_test(TEST_PHISHING_URLS, verbose=args.verbose)
        print(f"\nPhishing URL results: {phishing_results['stats']['verdict_counts']}")
        
        print("\n--- Testing Known Legitimate URLs ---")
        legitimate_results = tester.batch_test(TEST_LEGITIMATE_URLS, verbose=args.verbose)
        print(f"\nLegitimate URL results: {legitimate_results['stats']['verdict_counts']}")
        
    # Test URLs from a file
    elif args.batch:
        if not os.path.exists(args.batch):
            print(f"Error: File not found - {args.batch}")
            return
            
        try:
            with open(args.batch, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            if not urls:
                print("Error: No URLs found in file")
                return
                
            print(f"Testing {len(urls)} URLs from file...")
            results = tester.batch_test(urls, verbose=args.verbose)
            
            print("\n--- Batch Test Results ---")
            print(f"Total URLs tested: {results['stats']['total_urls']}")
            print(f"Average time per URL: {results['stats']['avg_time_per_url']*1000:.2f}ms")
            print("\nVerdict counts:")
            for verdict, count in results['stats']['verdict_counts'].items():
                print(f"  {verdict}: {count}")
                
            if args.verbose:
                print("\nTop 10 detection flags:")
                flags = sorted(results['stats']['flags_frequency'].items(), 
                              key=lambda x: x[1], reverse=True)[:10]
                for flag, count in flags:
                    print(f"  {flag}: {count}")
                
        except Exception as e:
            print(f"Error processing batch file: {e}")
    
    else:
        # Default - show help
        parser.print_help()
        print("\nExample usage:")
        print("  python phishing_sensitivity_adjuster.py --url https://example.com")
        print("  python phishing_sensitivity_adjuster.py --test-known --verbose")
        print("  python phishing_sensitivity_adjuster.py --batch urls.txt --sensitivity high")
        

if __name__ == "__main__":
    main()
