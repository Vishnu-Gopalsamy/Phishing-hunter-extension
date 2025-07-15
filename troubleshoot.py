"""
Troubleshooting script for phishing detection system

Diagnoses common issues with the phishing detection system:
1. Server connectivity
2. API endpoints
3. Model loading
4. Content analysis dependencies
5. Chrome extension connectivity
"""

import os
import sys
import time
import json
import logging
import requests
from urllib.parse import quote
import importlib
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("troubleshoot")

# Base paths
BASE_DIR = Path(__file__).parent
MODELS_DIR = BASE_DIR / "models"
EXTENSION_DIR = BASE_DIR / "chrome_extension"

def check_server(host="127.0.0.1", port=5000):
    """Check if the API server is running"""
    logger.info(f"Checking server at http://{host}:{port}...")
    
    try:
        # Check if the server is responding (health endpoint)
        response = requests.get(f"http://{host}:{port}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            logger.info("✅ Server is running")
            logger.info(f"   Status: {data.get('status', 'unknown')}")
            logger.info(f"   Detector loaded: {data.get('detector_loaded', False)}")
            logger.info(f"   Layers count: {data.get('layers_count', 0)}")
            return True
        else:
            logger.error(f"❌ Server returned error: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        logger.error("❌ Could not connect to server - server is not running")
        logger.info("💡 Run 'python api_server.py' to start the server")
        return False
    except requests.exceptions.Timeout:
        logger.error("❌ Server connection timed out")
        return False
    except Exception as e:
        logger.error(f"❌ Error checking server: {e}")
        return False

def test_api_endpoints(host="127.0.0.1", port=5000):
    """Test the API endpoints with sample URLs"""
    logger.info(f"Testing API endpoints at http://{host}:{port}...")
    
    test_url = "https://google.com"
    endpoints = [
        {
            "name": "Health Check", 
            "url": f"http://{host}:{port}/health",
            "method": "GET",
            "data": None
        },
        {
            "name": "URL Check", 
            "url": f"http://{host}:{port}/check_url?url={quote(test_url)}",
            "method": "GET",
            "data": None
        },
        {
            "name": "Detailed Analysis", 
            "url": f"http://{host}:{port}/analyze_detailed",
            "method": "POST",
            "data": {"url": test_url}
        }
    ]
    
    all_passed = True
    
    for endpoint in endpoints:
        try:
            logger.info(f"Testing {endpoint['name']} endpoint...")
            if endpoint["method"] == "GET":
                response = requests.get(endpoint["url"], timeout=10)
            else:
                response = requests.post(endpoint["url"], json=endpoint["data"], timeout=10)
                
            if response.status_code == 200:
                logger.info(f"✅ {endpoint['name']} - Status: {response.status_code}")
                
                # Show partial response data
                resp_data = response.json()
                if isinstance(resp_data, dict):
                    data_preview = {k: v for i, (k, v) in enumerate(resp_data.items()) if i < 3}
                    logger.info(f"   Response preview: {data_preview}...")
            else:
                logger.error(f"❌ {endpoint['name']} - Error status: {response.status_code}")
                logger.error(f"   Response: {response.text[:200]}...")
                all_passed = False
                
        except Exception as e:
            logger.error(f"❌ {endpoint['name']} - Exception: {e}")
            all_passed = False
    
    return all_passed

def check_model_files():
    """Check if model files exist and are valid"""
    logger.info("Checking model files...")
    
    required_files = [
        "phishing_classifier.pkl",
        "tfidf_vectorizer.pkl",
        "evaluation_results.json"
    ]
    
    # Check if models directory exists
    if not MODELS_DIR.exists():
        logger.error(f"❌ Models directory not found: {MODELS_DIR}")
        logger.info("💡 Create the models directory and run training")
        return False
    
    # Check for required files
    all_found = True
    for filename in required_files:
        file_path = MODELS_DIR / filename
        if file_path.exists():
            # Check file size
            size_mb = file_path.stat().st_size / (1024 * 1024)
            logger.info(f"✅ Found {filename} ({size_mb:.2f} MB)")
            
            # Check evaluation results
            if filename == "evaluation_results.json":
                try:
                    with open(file_path, 'r') as f:
                        results = json.load(f)
                    accuracy = results.get('accuracy', 0)
                    model_type = results.get('model_type', 'Unknown')
                    logger.info(f"   Model type: {model_type}")
                    logger.info(f"   Accuracy: {accuracy:.4f}")
                except Exception as e:
                    logger.error(f"❌ Error reading evaluation results: {e}")
        else:
            logger.error(f"❌ Required file missing: {filename}")
            all_found = False
    
    return all_found

def check_dependencies():
    """Check if required packages are installed"""
    logger.info("Checking Python dependencies...")
    
    dependencies = [
        "flask", "flask_cors", "requests", "numpy", "scikit-learn",
        "joblib", "tldextract", "bs4", "whois", "xgboost"
    ]
    
    content_deps = [
        "beautifulsoup4", "pyOpenSSL", "cryptography"
    ]
    
    # Check core dependencies
    all_installed = True
    for package in dependencies:
        try:
            importlib.import_module(package.replace('-', '_'))
            logger.info(f"✅ {package} is installed")
        except ImportError:
            logger.error(f"❌ {package} is not installed")
            all_installed = False
    
    # Check content analysis dependencies
    logger.info("\nChecking content analysis dependencies...")
    for package in content_deps:
        try:
            importlib.import_module(package.replace('-', '_').replace('beautifulsoup4', 'bs4'))
            logger.info(f"✅ {package} is installed")
        except ImportError:
            logger.warning(f"⚠️ {package} is not installed - content analysis may be limited")
    
    # Check for GPU support
    logger.info("\nChecking GPU support...")
    try:
        import xgboost as xgb
        gpu_devices = xgb.gpu.get_gpu_count()
        logger.info(f"✅ XGBoost GPU devices: {gpu_devices}")
    except:
        logger.warning("⚠️ XGBoost GPU support not available")
    
    try:
        import cupy
        logger.info(f"✅ CuPy is installed (version {cupy.__version__})")
        # Try to get device count
        try:
            device_count = cupy.cuda.runtime.getDeviceCount()
            logger.info(f"✅ CuPy CUDA devices: {device_count}")
        except:
            logger.warning("⚠️ Could not get CuPy device count")
    except ImportError:
        logger.warning("⚠️ CuPy is not installed - GPU acceleration unavailable")
    
    if not all_installed:
        logger.info("\n💡 Install missing dependencies with: pip install -r requirements.txt")
    
    return all_installed

def check_chrome_extension():
    """Check Chrome extension files"""
    logger.info("Checking Chrome extension...")
    
    required_files = [
        "manifest.json",
        "popup.html",
        "popup.js",
        "background.js",
        "icon.png"
    ]
    
    # Check if extension directory exists
    if not EXTENSION_DIR.exists():
        logger.error(f"❌ Chrome extension directory not found: {EXTENSION_DIR}")
        return False
    
    # Check for required files
    all_found = True
    for filename in required_files:
        file_path = EXTENSION_DIR / filename
        if file_path.exists():
            logger.info(f"✅ Found {filename}")
            
            # Check manifest.json permissions
            if filename == "manifest.json":
                try:
                    with open(file_path, 'r') as f:
                        manifest = json.load(f)
                    
                    permissions = manifest.get('permissions', [])
                    host_permissions = manifest.get('host_permissions', [])
                    
                    logger.info(f"   Permissions: {permissions}")
                    logger.info(f"   Host permissions: {host_permissions}")
                    
                    # Check for required permissions
                    if "activeTab" not in permissions:
                        logger.warning("⚠️ Missing 'activeTab' permission in manifest")
                    
                    if "http://localhost/*" not in host_permissions:
                        logger.warning("⚠️ Missing 'http://localhost/*' host permission in manifest")
                except Exception as e:
                    logger.error(f"❌ Error reading manifest: {e}")
        else:
            logger.error(f"❌ Required file missing: {filename}")
            all_found = False
    
    # Check API endpoint in popup.js
    popup_js_path = EXTENSION_DIR / "popup.js"
    if popup_js_path.exists():
        try:
            with open(popup_js_path, 'r') as f:
                content = f.read()
            
            if "localhost:5000" in content:
                logger.info("✅ API endpoint configured in popup.js")
            else:
                logger.warning("⚠️ API endpoint might not be properly configured in popup.js")
        except Exception as e:
            logger.error(f"❌ Error reading popup.js: {e}")
    
    return all_found

def diagnose_500_error():
    """Diagnose common causes of 500 errors"""
    logger.info("\nDiagnosing 500 Internal Server Error...")
    
    # Check api_server.py for syntax errors
    api_server_path = BASE_DIR / "api_server.py"
    if api_server_path.exists():
        logger.info("Checking api_server.py for syntax errors...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(api_server_path)],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                logger.error(f"❌ Syntax error in api_server.py: {result.stderr}")
                return False
            logger.info("✅ No syntax errors found in api_server.py")
        except Exception as e:
            logger.error(f"❌ Error checking syntax: {e}")
    else:
        logger.error("❌ api_server.py not found")
    
    # Check if LayeredPhishingDetector class exists in phishing_detector.py
    phishing_detector_path = BASE_DIR / "phishing_detector.py"
    if phishing_detector_path.exists():
        logger.info("Checking phishing_detector.py for required classes...")
        try:
            with open(phishing_detector_path, 'r') as f:
                content = f.read()
            
            if "class LayeredPhishingDetector" in content and "class RiskLevel" in content:
                logger.info("✅ Required classes found in phishing_detector.py")
            else:
                logger.error("❌ Required classes not found in phishing_detector.py")
                return False
        except Exception as e:
            logger.error(f"❌ Error reading phishing_detector.py: {e}")
    else:
        logger.error("❌ phishing_detector.py not found")
    
    return True

def run_all_checks():
    """Run all diagnostic checks"""
    print("\n" + "="*80)
    print("PHISHING DETECTOR DIAGNOSTIC TOOL")
    print("="*80)
    
    # Check dependencies first
    deps_ok = check_dependencies()
    print("\n" + "-"*80)
    
    # Check model files
    model_ok = check_model_files()
    print("\n" + "-"*80)
    
    # Check Chrome extension
    extension_ok = check_chrome_extension()
    print("\n" + "-"*80)
    
    # Check server connectivity
    server_ok = check_server()
    
    if server_ok:
        print("\n" + "-"*80)
        # Test API endpoints
        api_ok = test_api_endpoints()
    else:
        api_ok = False
        print("\n" + "-"*80)
        # Diagnose 500 error if server is down
        diagnose_500_error()
    
    # Print summary
    print("\n" + "="*80)
    print("DIAGNOSTIC SUMMARY")
    print("="*80)
    print(f"Dependencies check: {'✅ PASSED' if deps_ok else '❌ FAILED'}")
    print(f"Model files check: {'✅ PASSED' if model_ok else '❌ FAILED'}")
    print(f"Chrome extension check: {'✅ PASSED' if extension_ok else '❌ FAILED'}")
    print(f"Server connectivity: {'✅ PASSED' if server_ok else '❌ FAILED'}")
    print(f"API endpoints: {'✅ PASSED' if api_ok else '❌ FAILED'}")
    
    # Provide overall assessment
    if deps_ok and model_ok and server_ok and api_ok:
        print("\n✅ All checks passed! System should be working properly.")
    else:
        print("\n⚠️ Some checks failed. See above for details and recommendations.")
        
        if not server_ok:
            print("\n💡 Most likely issue: API server is not running or has errors.")
            print("   Start the server with: python api_server.py")
        elif not model_ok:
            print("\n💡 Most likely issue: ML models are missing or corrupted.")
            print("   Run training with: python training/train.py")
        elif not deps_ok:
            print("\n💡 Most likely issue: Missing dependencies.")
            print("   Install with: pip install -r requirements.txt")

if __name__ == "__main__":
    run_all_checks()
