"""
Phishing Detection Feature Tester

This script tests all features and components of the layered phishing detection system:
1. Basic URL validation
2. Feature extraction
3. ML classification
4. Layered analysis
5. GPU acceleration
6. Chrome extension API endpoints

Usage: python test_features.py [--verbose] [--test-gpu] [--benchmark] [--api-test]
"""

import os
import sys
import time
import argparse
import json
import logging
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List, Tuple

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("phishing_test_results.log")
    ]
)
logger = logging.getLogger(__name__)

# Import the detection system
try:
    from phishing_detector import (
        LayeredPhishingDetector, extract_features, 
        RiskLevel, load_model, predict_with_ml
    )
    logger.info("Successfully imported phishing detection modules")
except ImportError as e:
    logger.error(f"Failed to import phishing detection modules: {e}")
    print("❌ Error: Could not import phishing detection modules.")
    print("Make sure you're running this script from the project root directory.")
    sys.exit(1)

# Test URLs covering different scenarios
TEST_URLS = {
    "legitimate": [
        "https://google.com",
        "https://github.com",
        "https://www.microsoft.com/en-us/",
        "https://www.apple.com/iphone/",
        "https://www.amazon.com/books-used-books-textbooks/",
        "https://www.wikipedia.org",
        "https://stackoverflow.com/questions/tagged/python"
    ],
    "suspicious": [
        "http://bit.ly/2x9gFfU",
        "https://tinyurl.com/y8r7qbo",
        "https://www.goggle.com",  # Typosquatting
        "https://paypal-secure-login.com"  # Brand + security term
    ],
    "phishing": [
        "https://secure-banking-login.suspicious-domain.com/update-account",
        "http://192.168.1.1/login.php",  # IP-based URL
        "https://paypal.com.secure-login.info/verification",  # Domain spoofing
        "http://amaz0n-account-login.com/signin",  # Typosquatting with numbers
        "https://https-paypal-security.suspicious-bank.com/login//redirect.php"  # Multiple red flags
    ],
    "edge_cases": [
        "about:blank",
        "file:///C:/Users/document.html",
        "chrome://settings",
        "https://example.com?param=<script>alert('xss')</script>",  # XSS attempt
        "http://localhost:5000",
        "data:text/html,<html><body>Hello</body></html>"
    ]
}

def run_feature_extraction_test(verbose=False) -> Dict[str, Any]:
    """Test URL feature extraction functionality."""
    logger.info("Testing feature extraction...")
    results = {"success": True, "features_extracted": 0, "errors": []}
    
    # Select one URL from each category
    test_set = {
        "legitimate": TEST_URLS["legitimate"][0],
        "suspicious": TEST_URLS["suspicious"][0],
        "phishing": TEST_URLS["phishing"][0],
        "edge_case": TEST_URLS["edge_cases"][0]
    }
    
    for category, url in test_set.items():
        try:
            logger.info(f"Extracting features for {category} URL: {url}")
            features = extract_features(url)
            
            if not features:
                results["success"] = False
                results["errors"].append(f"No features extracted for {url}")
                continue
                
            feature_count = len(features)
            results["features_extracted"] = max(results["features_extracted"], feature_count)
            
            if verbose:
                print(f"\n🔍 Features for {category} URL: {url}")
                for k, v in features.items():
                    print(f"  - {k}: {v}")
            
            # Basic validation of expected features
            expected_features = [
                "has_ip_address", "url_length", "is_shortened", "double_slash_redirect", 
                "has_dash_in_domain", "subdomain_level", "https_token_in_domain",
                "domain_age", "domain_registration_length", "dns_record"
            ]
            
            missing = [f for f in expected_features if f not in features]
            if missing:
                results["success"] = False
                results["errors"].append(f"Missing features for {url}: {missing}")
                
        except Exception as e:
            results["success"] = False
            results["errors"].append(f"Error extracting features for {url}: {str(e)}")
            logger.error(f"Feature extraction failed for {url}: {e}", exc_info=True)
    
    return results

def run_ml_classification_test(verbose=False) -> Dict[str, Any]:
    """Test machine learning classification."""
    logger.info("Testing ML classification...")
    results = {"success": True, "correct_predictions": 0, "total_predictions": 0, "errors": []}
    
    try:
        # Load ML model and vectorizer
        model, vectorizer = load_model()
        
        if model is None or vectorizer is None:
            results["success"] = False
            results["errors"].append("Failed to load ML model or vectorizer")
            return results
            
        logger.info("ML model and vectorizer loaded successfully")
        
        # Test URLs
        test_data = []
        for category, urls in TEST_URLS.items():
            expected_phishing = category in ["phishing", "suspicious"]
            for url in urls[:2]:  # Test first 2 URLs from each category
                test_data.append((url, expected_phishing))
        
        # Run predictions
        for url, expected_phishing in test_data:
            try:
                results["total_predictions"] += 1
                prediction = predict_with_ml(url, model, vectorizer)
                
                if prediction is None:
                    results["errors"].append(f"Prediction failed for URL: {url}")
                    continue
                    
                is_phishing = prediction["prediction"] == "phishing"
                confidence = prediction.get("confidence", 0)
                
                if verbose:
                    print(f"\nML prediction for: {url}")
                    print(f"  Predicted: {'phishing' if is_phishing else 'legitimate'} " 
                          f"(confidence: {confidence:.3f})")
                    print(f"  Expected: {'phishing' if expected_phishing else 'legitimate'}")
                
                # Check if prediction matches expectation
                if is_phishing == expected_phishing:
                    results["correct_predictions"] += 1
                    
            except Exception as e:
                results["errors"].append(f"Error classifying {url}: {str(e)}")
                logger.error(f"ML classification failed for {url}: {e}", exc_info=True)
                
        # Calculate accuracy
        if results["total_predictions"] > 0:
            results["accuracy"] = results["correct_predictions"] / results["total_predictions"]
        else:
            results["accuracy"] = 0
            
    except Exception as e:
        results["success"] = False
        results["errors"].append(f"ML test failed: {str(e)}")
        logger.error("ML test failed", exc_info=True)
    
    return results

def run_layered_detection_test(verbose=False) -> Dict[str, Any]:
    """Test the complete layered detection system."""
    logger.info("Testing layered detection system...")
    results = {
        "success": True,
        "total_urls": 0,
        "processing_time": 0,
        "layer_results": {},
        "errors": [],
        "verdict_distribution": {}
    }
    
    try:
        detector = LayeredPhishingDetector()
        logger.info("Layered detector initialized successfully")
        
        # Flatten test URLs for full testing
        all_urls = []
        expected_results = {}
        
        for category, urls in TEST_URLS.items():
            for url in urls:
                all_urls.append(url)
                # Map expected risk levels
                if category == "legitimate":
                    expected_results[url] = [RiskLevel.SAFE, RiskLevel.LOW]
                elif category == "suspicious":
                    expected_results[url] = [RiskLevel.LOW, RiskLevel.MEDIUM]
                elif category == "phishing":
                    expected_results[url] = [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
                else:  # edge cases can have any result
                    expected_results[url] = None
        
        # Process URLs
        start_time = time.time()
        results["total_urls"] = len(all_urls)
        
        for url in all_urls:
            try:
                analysis = detector.analyze_url(url)
                results["processing_time"] += analysis.get("processing_time", 0)
                
                # Extract verdict
                final_result = analysis.get('final_result', {})
                verdict = final_result.get('final_verdict', RiskLevel.ERROR)
                risk_percentage = final_result.get('risk_percentage', 0)
                
                # Count layer results
                for layer_result in analysis.get('layer_results', []):
                    layer_name = layer_result.get('layer', 'unknown')
                    if layer_name not in results["layer_results"]:
                        results["layer_results"][layer_name] = 0
                    results["layer_results"][layer_name] += 1
                
                # Count verdict distribution
                verdict_str = verdict.value if isinstance(verdict, RiskLevel) else str(verdict)
                if verdict_str not in results["verdict_distribution"]:
                    results["verdict_distribution"][verdict_str] = 0
                results["verdict_distribution"][verdict_str] += 1
                
                if verbose:
                    print(f"\nLayered analysis for: {url}")
                    print(f"  Verdict: {verdict_str}")
                    print(f"  Risk: {risk_percentage:.1f}%")
                    print(f"  Processing time: {analysis['processing_time']:.3f}s")
                    print(f"  Layers analyzed: {len(analysis.get('layer_results', []))}")
                
                # Verify expected results (except for edge cases)
                if expected_results[url] is not None:
                    if isinstance(verdict, RiskLevel) and verdict not in expected_results[url]:
                        logger.warning(f"Unexpected verdict {verdict} for URL: {url}")
            
            except Exception as e:
                results["errors"].append(f"Error analyzing {url}: {str(e)}")
                logger.error(f"Layered detection failed for {url}: {e}", exc_info=True)
        
        # Calculate average processing time
        end_time = time.time()
        results["total_time"] = end_time - start_time
        
        if results["total_urls"] > 0:
            results["avg_processing_time"] = results["processing_time"] / results["total_urls"]
            results["urls_per_second"] = results["total_urls"] / max(results["total_time"], 0.001)
        
    except Exception as e:
        results["success"] = False
        results["errors"].append(f"Layered detection test failed: {str(e)}")
        logger.error("Layered detection test failed", exc_info=True)
    
    return results

def run_gpu_test() -> Dict[str, Any]:
    """Test GPU acceleration capabilities."""
    logger.info("Testing GPU acceleration...")
    results = {"gpu_available": False, "errors": []}
    
    try:
        # Test for XGBoost GPU support
        try:
            import xgboost as xgb
            gpu_count = xgb.gpu.get_gpu_count()
            results["gpu_available"] = gpu_count > 0
            results["gpu_count"] = gpu_count
            logger.info(f"XGBoost GPU count: {gpu_count}")
        except ImportError:
            results["errors"].append("XGBoost not available")
            logger.warning("XGBoost not available")
        except Exception as e:
            results["errors"].append(f"XGBoost GPU error: {str(e)}")
            logger.error(f"XGBoost GPU error: {e}")
        
        # Test for CuPy support
        try:
            import cupy as cp
            results["cupy_available"] = True
            results["cupy_version"] = cp.__version__
            
            # Simple CuPy test
            a = cp.array([1, 2, 3])
            b = cp.array([4, 5, 6])
            c = cp.add(a, b)
            results["cupy_test"] = c.tolist() == [5, 7, 9]
            logger.info(f"CuPy test successful: {results['cupy_test']}")
        except ImportError:
            results["cupy_available"] = False
            results["errors"].append("CuPy not available")
            logger.warning("CuPy not available")
        except Exception as e:
            results["cupy_available"] = False
            results["errors"].append(f"CuPy error: {str(e)}")
            logger.error(f"CuPy error: {e}")
        
        # Check CUDA availability
        try:
            # Check for CUDA toolkit
            results["cuda_available"] = False
            
            if results.get("cupy_available", False):
                import cupy as cp
                results["cuda_available"] = True
                results["cuda_version"] = cp.cuda.runtime.runtimeGetVersion()
                results["cuda_device_count"] = cp.cuda.runtime.getDeviceCount()
                logger.info(f"CUDA version: {results['cuda_version']}")
                logger.info(f"CUDA devices: {results['cuda_device_count']}")
                
                # Get device info for first device
                if results["cuda_device_count"] > 0:
                    device_props = cp.cuda.runtime.getDeviceProperties(0)
                    results["device_name"] = device_props["name"].decode('utf-8')
                    results["device_memory"] = device_props["totalGlobalMem"] / (1024**3)  # GB
                    logger.info(f"GPU device: {results['device_name']}")
        except Exception as e:
            results["errors"].append(f"CUDA check error: {str(e)}")
            logger.error(f"CUDA check error: {e}")
        
        # Load model and check if it uses GPU
        try:
            # Check if the model has GPU support
            models_dir = os.path.join(os.path.dirname(__file__), 'models')
            results_path = os.path.join(models_dir, 'evaluation_results.json')
            
            if os.path.exists(results_path):
                with open(results_path, 'r') as f:
                    eval_results = json.load(f)
                
                results["model_gpu_accelerated"] = eval_results.get("gpu_accelerated", False)
                results["model_type"] = eval_results.get("model_type", "Unknown")
                
                logger.info(f"Model type: {results['model_type']}")
                logger.info(f"Model GPU accelerated: {results['model_gpu_accelerated']}")
        except Exception as e:
            results["errors"].append(f"Model GPU check error: {str(e)}")
            logger.error(f"Model GPU check error: {e}")
            
    except Exception as e:
        results["errors"].append(f"GPU test failed: {str(e)}")
        logger.error("GPU test failed", exc_info=True)
    
    return results

def run_api_test() -> Dict[str, Any]:
    """Test the API server endpoints for Chrome extension."""
    logger.info("Testing API endpoints...")
    results = {"success": False, "errors": [], "endpoints_tested": 0, "endpoints_passed": 0}
    
    try:
        import requests
        base_url = "http://localhost:5000"
        
        # Test endpoints
        endpoints = [
            {"url": "/health", "method": "GET", "params": {}},
            {"url": "/check_url", "method": "GET", "params": {"url": "https://google.com"}},
            {"url": "/analyze_detailed", "method": "POST", 
             "json": {"url": "https://suspicious-phishing-site.com"}}
        ]
        
        for endpoint in endpoints:
            results["endpoints_tested"] += 1
            url = base_url + endpoint["url"]
            
            try:
                if endpoint["method"] == "GET":
                    response = requests.get(url, params=endpoint["params"], timeout=10)
                else:  # POST
                    response = requests.post(url, json=endpoint["json"], timeout=10)
                
                logger.info(f"API endpoint {endpoint['url']} response status: {response.status_code}")
                
                if response.status_code == 200:
                    results["endpoints_passed"] += 1
                    logger.info(f"API endpoint {endpoint['url']} successful")
                else:
                    results["errors"].append(f"Endpoint {endpoint['url']} failed: Status {response.status_code}")
                    logger.warning(f"API endpoint {endpoint['url']} failed with status {response.status_code}")
            
            except requests.exceptions.ConnectionError:
                results["errors"].append(f"Endpoint {endpoint['url']} failed: Connection error (is API server running?)")
                logger.error(f"API connection error for {endpoint['url']}")
            except Exception as e:
                results["errors"].append(f"Endpoint {endpoint['url']} failed: {str(e)}")
                logger.error(f"API test failed for {endpoint['url']}: {e}")
        
        # Check success status
        results["success"] = results["endpoints_passed"] > 0
        results["api_running"] = results["endpoints_passed"] > 0
        
    except ImportError:
        results["errors"].append("Requests library not available")
        logger.warning("Requests library not available for API testing")
    except Exception as e:
        results["errors"].append(f"API test failed: {str(e)}")
        logger.error("API test failed", exc_info=True)
    
    return results

def run_benchmark_test() -> Dict[str, Any]:
    """Run performance benchmark tests."""
    logger.info("Running benchmark tests...")
    results = {"success": True, "errors": [], "benchmarks": {}}
    
    try:
        # Create test detector
        detector = LayeredPhishingDetector()
        
        # Load model separately for direct ML benchmarks
        model, vectorizer = load_model()
        if model is None or vectorizer is None:
            results["errors"].append("Could not load ML model for benchmark")
        
        # Sample URLs for benchmark
        benchmark_urls = (
            TEST_URLS["legitimate"][:2] + 
            TEST_URLS["suspicious"][:2] + 
            TEST_URLS["phishing"][:2]
        )
        
        # 1. Feature extraction benchmark
        logger.info("Benchmarking feature extraction...")
        start_time = time.time()
        iterations = 50
        for _ in range(iterations):
            for url in benchmark_urls:
                extract_features(url)
        end_time = time.time()
        
        feature_extraction_time = end_time - start_time
        results["benchmarks"]["feature_extraction"] = {
            "total_time": feature_extraction_time,
            "iterations": iterations * len(benchmark_urls),
            "average_time": feature_extraction_time / (iterations * len(benchmark_urls)),
            "urls_per_second": (iterations * len(benchmark_urls)) / feature_extraction_time
        }
        
        # 2. ML prediction benchmark
        if model is not None and vectorizer is not None:
            logger.info("Benchmarking ML prediction...")
            start_time = time.time()
            iterations = 100
            for _ in range(iterations):
                for url in benchmark_urls:
                    predict_with_ml(url, model, vectorizer)
            end_time = time.time()
            
            ml_time = end_time - start_time
            results["benchmarks"]["ml_prediction"] = {
                "total_time": ml_time,
                "iterations": iterations * len(benchmark_urls),
                "average_time": ml_time / (iterations * len(benchmark_urls)),
                "urls_per_second": (iterations * len(benchmark_urls)) / ml_time
            }
        
        # 3. Full pipeline benchmark
        logger.info("Benchmarking full layered detection...")
        start_time = time.time()
        iterations = 10  # Lower due to higher complexity
        for _ in range(iterations):
            for url in benchmark_urls:
                detector.analyze_url(url)
        end_time = time.time()
        
        pipeline_time = end_time - start_time
        results["benchmarks"]["full_pipeline"] = {
            "total_time": pipeline_time,
            "iterations": iterations * len(benchmark_urls),
            "average_time": pipeline_time / (iterations * len(benchmark_urls)),
            "urls_per_second": (iterations * len(benchmark_urls)) / pipeline_time
        }
        
    except Exception as e:
        results["success"] = False
        results["errors"].append(f"Benchmark test failed: {str(e)}")
        logger.error("Benchmark test failed", exc_info=True)
    
    return results

def print_test_summary(results: Dict[str, Dict[str, Any]]):
    """Print a summary of all test results."""
    print("\n" + "="*80)
    print(f"📊 PHISHING DETECTION FEATURE TEST SUMMARY")
    print("="*80)
    
    # Determine overall status
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result.get("success", False))
    
    print(f"🧪 Tests run: {total_tests}")
    print(f"✅ Tests passed: {passed_tests}")
    print(f"❌ Tests failed: {total_tests - passed_tests}")
    
    # Print individual test results
    for test_name, result in results.items():
        status = "✅ PASS" if result.get("success", False) else "❌ FAIL"
        print(f"\n📝 {test_name.upper()}: {status}")
        
        # Print test-specific metrics
        if test_name == "feature_extraction":
            print(f"  Features extracted: {result.get('features_extracted', 0)}")
            
        elif test_name == "ml_classification":
            correct = result.get("correct_predictions", 0)
            total = result.get("total_predictions", 0)
            accuracy = result.get("accuracy", 0)
            print(f"  Correct predictions: {correct}/{total} ({accuracy*100:.1f}%)")
            
        elif test_name == "layered_detection":
            urls = result.get("total_urls", 0)
            time_per_url = result.get("avg_processing_time", 0)
            urls_per_sec = result.get("urls_per_second", 0)
            print(f"  URLs processed: {urls}")
            print(f"  Avg. processing time: {time_per_url*1000:.1f}ms per URL")
            print(f"  Performance: {urls_per_sec:.1f} URLs/second")
            
            # Show layer coverage
            layer_results = result.get("layer_results", {})
            if layer_results:
                print("  Layers coverage:")
                for layer, count in layer_results.items():
                    print(f"    - {layer}: {count}/{urls} URLs")
            
            # Show verdict distribution
            verdict_dist = result.get("verdict_distribution", {})
            if verdict_dist:
                print("  Verdict distribution:")
                for verdict, count in verdict_dist.items():
                    percentage = (count / urls) * 100
                    print(f"    - {verdict}: {count} URLs ({percentage:.1f}%)")
            
        elif test_name == "gpu_test":
            gpu_available = result.get("gpu_available", False)
            gpu_count = result.get("gpu_count", 0)
            cupy_available = result.get("cupy_available", False)
            model_gpu = result.get("model_gpu_accelerated", False)
            
            print(f"  GPU available: {gpu_available}")
            if gpu_available:
                print(f"  GPU count: {gpu_count}")
            print(f"  CuPy available: {cupy_available}")
            print(f"  Model GPU accelerated: {model_gpu}")
            
            if result.get("device_name"):
                print(f"  GPU device: {result['device_name']} ({result.get('device_memory', 0):.1f}GB)")
            
        elif test_name == "api_test":
            endpoints_tested = result.get("endpoints_tested", 0)
            endpoints_passed = result.get("endpoints_passed", 0)
            api_running = result.get("api_running", False)
            
            print(f"  API server running: {api_running}")
            print(f"  Endpoints tested: {endpoints_tested}")
            print(f"  Endpoints passed: {endpoints_passed}")
            
        elif test_name == "benchmark_test":
            benchmarks = result.get("benchmarks", {})
            
            if "feature_extraction" in benchmarks:
                fe_bench = benchmarks["feature_extraction"]
                print(f"  Feature extraction: {fe_bench.get('urls_per_second', 0):.1f} URLs/second " 
                      f"({fe_bench.get('average_time', 0)*1000:.1f}ms per URL)")
            
            if "ml_prediction" in benchmarks:
                ml_bench = benchmarks["ml_prediction"]
                print(f"  ML prediction: {ml_bench.get('urls_per_second', 0):.1f} URLs/second " 
                      f"({ml_bench.get('average_time', 0)*1000:.1f}ms per URL)")
            
            if "full_pipeline" in benchmarks:
                pipe_bench = benchmarks["full_pipeline"]
                print(f"  Full pipeline: {pipe_bench.get('urls_per_second', 0):.1f} URLs/second " 
                      f"({pipe_bench.get('average_time', 0)*1000:.1f}ms per URL)")
        
        # Print errors
        errors = result.get("errors", [])
        if errors:
            print(f"  ⚠️  {len(errors)} errors occurred:")
            for i, error in enumerate(errors[:3], 1):  # Show first 3 errors
                print(f"    {i}. {error}")
            if len(errors) > 3:
                print(f"    ... and {len(errors) - 3} more errors")
    
    print("\n" + "="*80)
    print(f"🏁 OVERALL RESULT: {'✅ PASSED' if passed_tests == total_tests else '❌ ISSUES FOUND'}")
    print("="*80)

def save_results(results: Dict[str, Dict[str, Any]]):
    """Save test results to a JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"phishing_test_results_{timestamp}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Test results saved to {filename}")
        print(f"\n📄 Test results saved to {filename}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        print(f"\n❌ Failed to save results: {e}")

def main():
    """Main function to run all tests."""
    parser = argparse.ArgumentParser(description="Test phishing detection features")
    parser.add_argument("--verbose", action="store_true", help="Print detailed output")
    parser.add_argument("--test-gpu", action="store_true", help="Run GPU tests")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmarks")
    parser.add_argument("--api-test", action="store_true", help="Test API server endpoints")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("🔍 PHISHING DETECTION FEATURE TESTER")
    print("="*80)
    print(f"Starting tests at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    results = {}
    
    # Basic tests (always run)
    print("\n🧪 Testing feature extraction...")
    results["feature_extraction"] = run_feature_extraction_test(args.verbose)
    
    print("\n🧪 Testing ML classification...")
    results["ml_classification"] = run_ml_classification_test(args.verbose)
    
    print("\n🧪 Testing layered detection...")
    results["layered_detection"] = run_layered_detection_test(args.verbose)
    
    # Optional tests
    if args.test_gpu or args.all:
        print("\n🧪 Testing GPU acceleration...")
        results["gpu_test"] = run_gpu_test()
    
    if args.api_test or args.all:
        print("\n🧪 Testing API endpoints...")
        results["api_test"] = run_api_test()
    
    if args.benchmark or args.all:
        print("\n🧪 Running performance benchmarks...")
        results["benchmark_test"] = run_benchmark_test()
    
    # Print summary and save results
    print_test_summary(results)
    save_results(results)

if __name__ == "__main__":
    main()
