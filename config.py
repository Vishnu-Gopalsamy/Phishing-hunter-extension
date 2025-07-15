# Configuration file for Phishing Detection App

# Model settings
MODEL_PATH = "models/"
DEFAULT_MODEL_NAME = "phishing_classifier.pkl"

# Feature extraction settings
FEATURE_EXTRACTION = {
    "include_lexical": True,
    "include_domain": True,
    "include_network": False,  # Set to True if network features are implemented
}

# Classification thresholds
CLASSIFICATION_THRESHOLD = 0.5

# Logging settings
LOG_LEVEL = "INFO"
LOG_FILE = "phishing_detector.log"

# API settings (for future web interface)
API_HOST = "localhost"
API_PORT = 5000
DEBUG_MODE = True
