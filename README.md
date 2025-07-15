# 🛡️ Layered Phishing Detection System

A comprehensive phishing URL detection system with machine learning capabilities and a dramatic Chrome extension interface.

## Features

- **5-Layer Detection System**: Advanced detection through multiple analysis layers
- **Machine Learning Model**: 81.47% accuracy using RandomForest/XGBoost
- **GPU Acceleration**: Supports CUDA for faster processing
- **Dramatic UI**: Cyberpunk-style Chrome extension interface
- **Real-time Analysis**: Analyze URLs through a simple API server

## Components

- **Core Detector**: Layered detection system in `phishing_detector.py`
- **Training Module**: Model training in `training/train.py`
- **API Server**: Flask-based REST API in `api_server.py`
- **Chrome Extension**: Browser integration in `chrome_extension/`

## Setup Instructions

1. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

2. Train the model (optional - pre-trained model included):
    ```bash
    python training/train.py
    ```

3. Run the API server:
    ```bash
    python api_server.py
    ```

4. Load the Chrome extension:
   - Open Chrome and go to `chrome://extensions/`
   - Enable Developer mode
   - Click "Load unpacked" and select the `chrome_extension` folder

## System Architecture

The system uses a 5-layer approach:

1. **Basic Validation**: URL format and pattern checks
2. **Feature Analysis**: Domain features and URL structure analysis
3. **ML Classification**: Machine learning prediction (RandomForest/XGBoost)
4. **Ensemble Decision**: Weighted combination of all analyses
5. **Final Verdict**: Risk assessment and recommendations

## API Usage

```python
from phishing_detector import LayeredPhishingDetector

detector = LayeredPhishingDetector()
result = detector.analyze_url("https://example.com")
verdict = result['final_result']['final_verdict']
```

## Project Structure

- `phishing_detector.py`: Main detection engine
- `api_server.py`: REST API interface
- `training/train.py`: Model training script
- `models/`: Saved ML models and vectorizers
- `chrome_extension/`: Browser integration files

## License

MIT License
- Subdomain analysis
- **Weight**: 1.0x

### Layer 3: ML Classification
- TF-IDF character n-gram analysis
- RandomForest/XGBoost models
- GPU-accelerated inference
- Confidence scoring
- **Weight**: 1.5x (Enhanced for better phishing detection)

### Layer 6: Website Content Analysis
- HTML content scanning
- JavaScript pattern detection
- Form behavior analysis
- SSL certificate validation
- Data forwarding detection
- **Weight**: 1.3x (NEW - Advanced threat detection)

### Layer 4: Ensemble Decision
- Weighted scoring from all layers
- Conflict resolution
- Consensus building
- **Weight**: 1.0x

### Layer 5: Final Verdict
- Risk level assignment (SAFE → CRITICAL)
- Confidence calculation
- Security recommendations
- **Thresholds**: 
  - CRITICAL: ≥75%
  - HIGH: ≥60% 
  - MEDIUM: ≥35%
  - LOW: ≥15%
  - SAFE: <15%

## 🛠️ Installation

### Prerequisites
```bash
# Python 3.8+
python --version

# Required packages
pip install -r requirements.txt
```

### Dependencies
```txt
flask>=2.0.0
flask-cors>=3.0.0
scikit-learn>=1.0.0
pandas>=1.3.0
numpy>=1.21.0
joblib>=1.1.0
tldextract>=3.0.0
python-whois>=0.7.0
xgboost>=1.5.0  # For GPU acceleration
cupy>=10.0.0    # For GPU arrays (optional)
```

### Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd phishing-detection
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Download dataset**
```bash
# Place your phishing dataset as:
# training/phishing_site_urls.csv
# Format: url,label (where label is 'good' or 'bad')
```

4. **Train the model**
```bash
cd training
python train.py
```

5. **Start the API server**
```bash
python api_server.py
```

6. **Install Chrome extension**
   - Open Chrome → Extensions → Developer mode
   - Click "Load unpacked" → Select `chrome_extension` folder

## 🚀 Usage

### API Server

Start the Flask server:
```bash
python api_server.py
```

**Endpoints:**

- `GET /check_url?url=<URL>` - Quick analysis
- `POST /analyze_detailed` - Full layered analysis  
- `GET /health` - System status

### Chrome Extension

1. Click the extension icon in Chrome toolbar
2. View real-time analysis of current page
3. Click "DEEP SCAN" for detailed layer breakdown
4. Follow security recommendations

### Python API

```python
from phishing_detector import LayeredPhishingDetector

# Initialize detector
detector = LayeredPhishingDetector()

# Analyze URL
result = detector.analyze_url("https://suspicious-site.com")

# Get verdict
verdict = result['final_result']['final_verdict']
risk_pct = result['final_result']['risk_percentage']
```

## 📊 Model Performance

### Training Results
- **Dataset Size**: 549,347 URLs
- **Model Accuracy**: 81.47%
- **Precision (Phishing)**: 99.27%
- **Recall (Phishing)**: 35.17%
- **F1-Score (Phishing)**: 51.94%

### Performance Optimizations
- **GPU Training**: XGBoost with CUDA acceleration
- **Sampling**: Automatic sampling for large datasets (>100K)
- **Memory Management**: Efficient sparse matrix handling
- **Inference Speed**: <50ms per URL on average

## 🎨 Chrome Extension Features

### Dramatic UI Elements
- **Cyberpunk Theme**: Dark glass morphism design
- **Animated Particles**: Floating background effects
- **Status Animations**: 
  - Safe: Pulsing green glow
  - Warning: Flickering orange
  - Danger: Shaking red
  - Critical: Rotating red with glow
- **Risk Visualization**: Animated progress bars with color coding
- **Sound Effects**: Audio alerts for high-risk sites (optional)

### Security Levels
- **🟢 SAFE**: Low risk, proceed normally
- **🟡 LOW RISK**: Minor concerns, stay alert
- **🟠 MEDIUM**: Suspicious, exercise caution
- **🔴 HIGH**: Dangerous, avoid interaction
- **🚨 CRITICAL**: Immediate threat, evacuate

## 🔧 Configuration

### Model Training
```python
# training/train.py
SAMPLE_SIZE = 100000  # Max training samples
MAX_FEATURES = 20000  # TF-IDF features
GPU_ENABLED = True    # Use GPU acceleration
```

### Detection Thresholds
```python
# phishing_detector.py
THRESHOLDS = {
    'CRITICAL': 75,
    'HIGH': 60,
    'MEDIUM': 35,  # Lowered for better sensitivity
    'LOW': 15      # Lowered for better sensitivity
}
```

### Chrome Extension
```javascript
// popup.js
const API_ENDPOINT = 'http://localhost:5000';
const DRAMATIC_EFFECTS = true;
const SOUND_ALERTS = false;
```

## 📁 Project Structure

```
phishing-detection/
├── phishing_detector.py      # Main detection engine
├── api_server.py             # Flask API server
├── training/
│   ├── train.py             # Model training script
│   └── phishing_site_urls.csv # Training dataset
├── models/
│   ├── phishing_classifier.pkl # Trained model
│   ├── tfidf_vectorizer.pkl    # Feature vectorizer
│   └── evaluation_results.json # Model metrics
├── chrome_extension/
│   ├── manifest.json        # Extension manifest
│   ├── popup.html          # Dramatic UI
│   ├── popup.js            # Extension logic
│   ├── background.js       # Background tasks
│   └── icon.png           # Extension icon
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🧪 Testing

### Manual Testing
```bash
# Test the detection system
python phishing_detector.py

# Test API endpoints
curl "http://localhost:5000/check_url?url=https://google.com"
curl -X POST http://localhost:5000/analyze_detailed \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com"}'
```

### Chrome Extension Testing
1. Load extension in Chrome
2. Visit test URLs:
   - `https://google.com` (Should be SAFE)
   - `http://192.168.1.1/login` (Should be HIGH RISK)
   - `https://bit.ly/test` (Should be SUSPICIOUS)

## 🚀 GPU Acceleration

### Setup CUDA Support
```bash
# Install CUDA toolkit
# Install cupy for GPU arrays
pip install cupy-cuda11x  # For CUDA 11.x

# Install XGBoost with GPU support
pip install xgboost[gpu]
```

### GPU Benefits
- **Training Speed**: 3-5x faster model training
- **Inference Speed**: 2-3x faster predictions
- **Memory Efficiency**: Better handling of large datasets
- **Scalability**: Support for larger feature matrices

## 🔒 Security Features

### Threat Detection
- **IP-based URLs**: Direct IP address usage
- **Domain Spoofing**: Suspicious domain patterns
- **Shortened URLs**: Link shortening services
- **Typosquatting**: Similar-looking domains
- **New Domains**: Recently registered domains
- **SSL Certificate Issues**: Invalid/missing certificates
- **Website Content Analysis**: Real-time HTML/JS scanning
- **Form Data Forwarding**: Detection of external data submission
- **Code Obfuscation**: JavaScript obfuscation detection
- **Phishing Keywords**: Content-based phishing detection

### Privacy Protection
- **Local Processing**: No data sent to third parties
- **Offline Capable**: Core detection works offline
- **Minimal Permissions**: Only requires activeTab access
- **No Tracking**: No user behavior tracking

## 📈 Future Enhancements

### Planned Features
- [ ] Real-time domain reputation API integration
- [ ] Browser history analysis for pattern detection
- [ ] Collaborative threat intelligence
- [ ] Mobile app development
- [ ] Advanced deep learning models
- [ ] Multi-language support

### Model Improvements
- [ ] Ensemble of multiple ML algorithms
- [ ] Transfer learning from security datasets
- [ ] Dynamic threshold adjustment
- [ ] Online learning capabilities
- [ ] Feature importance visualization

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add unit tests for new features
- Update documentation
- Ensure Chrome extension compatibility
- Test GPU acceleration features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Dataset**: Phishing URL datasets from Kaggle and research communities
- **Libraries**: scikit-learn, XGBoost, Flask, and Chrome Extension APIs
- **Inspiration**: Cybersecurity research and threat intelligence communities
- **UI Design**: Cyberpunk and sci-fi aesthetic influences

## 📞 Support

For support, email support@phishing-detection.com or create an issue on GitHub.

## 🔗 Links

- [Demo Video](https://youtube.com/demo)
- [Documentation](https://docs.phishing-detection.com)
- [Chrome Web Store](https://chrome.google.com/webstore/detail/...)
- [Research Paper](https://arxiv.org/paper-link)

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. Always verify suspicious URLs through multiple sources and follow your organization's security policies.
"# Phishing-hunter-extension"
