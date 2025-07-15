"""
Fix Detector Initialization

This script ensures scikit-learn is properly installed and fixes common issues with
the phishing detector initialization.
"""

import os
import sys
import subprocess
import logging
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("fix_detector")

def check_dependencies():
    """Check and install required dependencies."""
    try:
        import sklearn
        logger.info(f"✅ scikit-learn is installed (version {sklearn.__version__})")
        return True
    except ImportError:
        logger.warning("❌ scikit-learn is not installed. Installing now...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "scikit-learn>=1.0.0"])
            logger.info("✅ Successfully installed scikit-learn")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to install scikit-learn: {e}")
            logger.info("💡 Try manual installation: pip install scikit-learn>=1.0.0")
            return False

def restart_api_server():
    """Restart the API server process."""
    logger.info("Attempting to restart API server...")
    
    # Find API server process
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            cmdline = proc.info.get('cmdline', [])
            if len(cmdline) > 1 and 'python' in cmdline[0] and 'api_server.py' in cmdline[1]:
                logger.info(f"Found API server process (PID: {proc.info['pid']})")
                proc.terminate()
                logger.info("Terminated existing API server process")
                break
    except ImportError:
        logger.warning("psutil not installed, cannot automatically terminate existing server")
    except Exception as e:
        logger.warning(f"Error finding/terminating API server process: {e}")
    
    # Start new API server process
    try:
        api_script = os.path.join(os.path.dirname(__file__), "api_server.py")
        if not os.path.exists(api_script):
            logger.error(f"❌ API server script not found at: {api_script}")
            return False
            
        logger.info("Starting new API server process...")
        # Start server in background
        if os.name == 'nt':  # Windows
            subprocess.Popen([sys.executable, api_script], 
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:  # Linux/Mac
            subprocess.Popen([sys.executable, api_script],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           start_new_session=True)
        
        logger.info("✅ API server process started")
        logger.info("Waiting for server to initialize...")
        time.sleep(3)  # Give some time for the server to start
        return True
    except Exception as e:
        logger.error(f"❌ Failed to start API server: {e}")
        return False

def check_server_health():
    """Check if the API server is healthy."""
    try:
        import requests
        for _ in range(3):  # Try a few times
            try:
                response = requests.get("http://localhost:5000/health", timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"✅ Server is running with status: {data.get('status')}")
                    logger.info(f"✅ Detector loaded: {data.get('detector_loaded')}")
                    return data.get('detector_loaded', False)
            except requests.RequestException:
                pass
            time.sleep(1)
        
        logger.warning("❌ Server health check failed")
        return False
    except ImportError:
        logger.warning("requests package not installed, skipping server health check")
        return False

if __name__ == "__main__":
    print("\n" + "="*80)
    print("PHISHING DETECTOR FIXER")
    print("="*80)
    
    # Step 1: Check dependencies
    deps_ok = check_dependencies()
    if not deps_ok:
        print("❌ Failed to ensure dependencies. Please install them manually.")
        sys.exit(1)
    
    # Step 2: Restart API server
    server_restarted = restart_api_server()
    if not server_restarted:
        print("⚠️ Could not automatically restart server.")
        print("💡 Please manually restart the API server: python api_server.py")
    
    # Step 3: Check server health
    detector_loaded = check_server_health()
    
    if detector_loaded:
        print("\n✅ SUCCESS! The phishing detector is now running properly.")
        print("🚀 Chrome extension should now work correctly.")
    else:
        print("\n⚠️ The server is running but the detector might not be initialized.")
        print("💡 Try these steps:")
        print("   1. Ensure scikit-learn is installed: pip install scikit-learn")
        print("   2. Restart the API server: python api_server.py")
        print("   3. Check if models are available in the 'models' directory")

    print("\n" + "="*80)
