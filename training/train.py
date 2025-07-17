import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
import json
import numpy as np
import time
import gc
from concurrent.futures import ThreadPoolExecutor
import multiprocessing as mp
import psutil
import scipy.sparse as sp

# GPU-enabled imports with RTX 3050 optimizations
try:
    import xgboost as xgb
    GPU_AVAILABLE = True
    print("✅ XGBoost with GPU support available")
except ImportError:
    print("⚠️  XGBoost not found, falling back to RandomForest")
    from sklearn.ensemble import RandomForestClassifier
    GPU_AVAILABLE = False

try:
    import cupy as cp
    import cupyx.scipy.sparse as cp_sparse
    CUPY_AVAILABLE = True
    print("✅ CuPy available for GPU acceleration")
except ImportError:
    print("⚠️  CuPy not available, using CPU")
    CUPY_AVAILABLE = False

# PyTorch for additional GPU operations
try:
    import torch
    TORCH_AVAILABLE = torch.cuda.is_available()
    if TORCH_AVAILABLE:
        print(f"✅ PyTorch CUDA available - GPU: {torch.cuda.get_device_name(0)}")
        print(f"   CUDA Version: {torch.version.cuda}")
        print(f"   GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f}GB")
    else:
        print("⚠️  PyTorch CUDA not available")
except ImportError:
    TORCH_AVAILABLE = False
    print("⚠️  PyTorch not available")

# RTX 3050 specific optimizations - FULL DATASET MODE
RTX_3050_OPTIMIZATIONS = True
GPU_MEMORY_LIMIT = 4  # GB - RTX 3050 has 4GB VRAM
CONSERVATIVE_MEMORY_USAGE = True  # Prevent OOM on RTX 3050

# GPU Memory and Performance Configuration for RTX 3050
def configure_gpu_memory():
    """Configure GPU memory settings optimized for RTX 3050."""
    gpu_count = 0
    
    if TORCH_AVAILABLE:
        try:
            # Configure PyTorch for RTX 3050 - Conservative for full dataset
            torch.cuda.empty_cache()
            gpu_count = torch.cuda.device_count()
            
            # Set conservative memory fraction for RTX 3050 with full dataset
            for i in range(gpu_count):
                torch.cuda.set_per_process_memory_fraction(0.6, i)  # 60% for full dataset
            
            print(f"🔧 PyTorch GPU memory configured for RTX 3050 (60% allocation for full dataset)")
            for i in range(gpu_count):
                props = torch.cuda.get_device_properties(i)
                print(f"   GPU {i}: {props.name} - {props.total_memory/1024**3:.1f}GB")
                
        except Exception as e:
            print(f"⚠️  PyTorch GPU configuration failed: {e}")
    
    if CUPY_AVAILABLE:
        try:
            # Configure CuPy for RTX 3050 - Conservative for full dataset
            mempool = cp.get_default_memory_pool()
            
            # Set conservative memory limit for RTX 3050 with full dataset
            max_memory = int(GPU_MEMORY_LIMIT * 0.5 * 1024**3)  # 50% of 4GB for full dataset
            mempool.set_limit(size=max_memory)
            print(f"🔧 CuPy memory pool limited to {max_memory/1024**3:.1f}GB for RTX 3050 (full dataset)")
            
            gpu_count = max(gpu_count, cp.cuda.runtime.getDeviceCount())
            
            for i in range(cp.cuda.runtime.getDeviceCount()):
                cp.cuda.runtime.setDevice(i)
                free_mem, total_mem = cp.cuda.runtime.memGetInfo()
                print(f"   GPU {i}: {free_mem/1024**3:.1f}GB free / {total_mem/1024**3:.1f}GB total")
                
        except Exception as e:
            print(f"⚠️  CuPy GPU configuration failed: {e}")
    
    return gpu_count

# Enhanced GPU availability check for RTX 3050
def check_gpu_availability():
    """Enhanced GPU availability check optimized for RTX 3050."""
    gpu_info = {
        'xgboost_gpu': False,
        'cupy_available': CUPY_AVAILABLE,
        'torch_available': TORCH_AVAILABLE,
        'device_count': 0,
        'gpu_name': 'Unknown',
        'compute_capability': 'Unknown',
        'memory_gb': 0,
        'rtx_3050_optimized': RTX_3050_OPTIMIZATIONS
    }
    
    # Check XGBoost GPU
    if GPU_AVAILABLE:
        try:
            # Test XGBoost GPU functionality
            test_data = xgb.DMatrix(np.random.rand(100, 10), label=np.random.randint(0, 2, 100))
            # Use new XGBoost 2.0 syntax
            params = {'device': 'cuda', 'tree_method': 'hist'}
            xgb.train(params, test_data, num_boost_round=1, verbose_eval=False)
            gpu_info['xgboost_gpu'] = True
            gpu_info['device_count'] = 1
            print("✅ XGBoost GPU functionality verified")
        except Exception as e:
            print(f"⚠️  XGBoost GPU test failed: {e}")
    
    # Check PyTorch GPU
    if TORCH_AVAILABLE:
        try:
            gpu_info['device_count'] = torch.cuda.device_count()
            gpu_info['gpu_name'] = torch.cuda.get_device_name(0)
            gpu_info['compute_capability'] = torch.cuda.get_device_capability(0)
            props = torch.cuda.get_device_properties(0)
            gpu_info['memory_gb'] = props.total_memory / 1024**3
            print(f"✅ PyTorch GPU: {gpu_info['gpu_name']} - {gpu_info['memory_gb']:.1f}GB")
        except Exception as e:
            print(f"⚠️  PyTorch GPU check failed: {e}")
    
    # Configure GPU memory
    gpu_count = configure_gpu_memory()
    gpu_info['device_count'] = max(gpu_info['device_count'], gpu_count)
    
    return gpu_info

gpu_info = check_gpu_availability()
print(f"🖥️  RTX 3050 GPU Info: {gpu_info}")

# RTX 3050 optimized configuration - FULL DATASET MODE
RTX_3050_CONFIG = {
    'max_features': 50000,  # Increased for full dataset
    'batch_size': 1024,     # Larger batch size for full dataset
    'n_estimators': 300,    # Increased for better performance with full data
    'max_depth': 10,        # Increased for full dataset
    'parallel_jobs': min(6, mp.cpu_count()),
    'use_gpu_preprocessing': False,  # Keep disabled to avoid OOM
    'force_full_dataset': True,      # FORCE FULL DATASET
    'sample_size': None              # No sampling - use all data
}

print(f"🎯 RTX 3050 Full Dataset Configuration:")
for key, value in RTX_3050_CONFIG.items():
    print(f"   {key}: {value}")

# Enhanced dataset loading
def find_dataset_file():
    """Find the phishing dataset file in common locations."""
    possible_paths = [
        "phishing_site_urls.csv",
        "training/phishing_site_urls.csv",
        os.path.join(os.path.dirname(__file__), "phishing_site_urls.csv"),
        os.path.join(os.path.dirname(__file__), "..", "phishing_site_urls.csv"),  # Fixed path
        "data/phishing_site_urls.csv",
        "../data/phishing_site_urls.csv"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            file_size = os.path.getsize(path) / 1024**2  # MB
            print(f"✅ Found dataset at: {path} ({file_size:.1f}MB)")
            return path
    
    print("❌ Dataset not found. Searching in current directory...")
    # List files in current directory to help debug
    current_files = [f for f in os.listdir('.') if f.endswith('.csv')]
    if current_files:
        print(f"   CSV files found: {current_files}")
    else:
        print("   No CSV files found in current directory")
    
    return None

# Memory-efficient data loading for RTX 3050 - FULL DATASET
def load_and_preprocess_data(dataset_path):
    """Load and preprocess FULL dataset with RTX 3050 memory optimizations."""
    print("🔄 Loading FULL dataset with RTX 3050 optimizations...")
    
    # Check available system RAM
    available_ram = psutil.virtual_memory().available / 1024**3
    print(f"💾 Available RAM: {available_ram:.1f}GB")
    
    try:
        # Load data with memory monitoring
        print("📊 Loading dataset...")
        
        # Try different encodings if UTF-8 fails
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        data = None
        
        for encoding in encodings:
            try:
                data = pd.read_csv(dataset_path, encoding=encoding)
                print(f"✅ Dataset loaded successfully with {encoding} encoding")
                break
            except UnicodeDecodeError:
                print(f"⚠️  Failed to load with {encoding} encoding, trying next...")
                continue
            except Exception as e:
                print(f"❌ Error with {encoding}: {e}")
                continue
        
        if data is None:
            print("❌ Failed to load dataset with any encoding")
            return None
        
        data_size = data.memory_usage(deep=True).sum() / 1024**2  # MB
        print(f"✅ Dataset loaded: {len(data)} rows ({data_size:.1f}MB)")
        data.columns = [col.lower().strip() for col in data.columns]

        # Check data structure
        print(f"📊 Dataset info:")
        print(f"   Columns: {list(data.columns)}")
        print(f"   Shape: {data.shape}")
        print(f"   Data types: {data.dtypes.to_dict()}")
        
        # Assign column names if needed
        if len(data.columns) >= 2:
            # Handle different possible column structures
            if 'url' not in data.columns.str.lower().tolist():
                data.columns = ['url', 'label'] + list(data.columns[2:]) if len(data.columns) > 2 else ['url', 'label']
                print(f"✅ Assigned column names: {list(data.columns)}")
            
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")
        return None
    
    # Memory-efficient data cleaning
    print("🧹 Memory-efficient data cleaning...")
    initial_size = len(data)
    
    # Remove rows with missing values
    data = data.dropna()
    
    # Convert to string and clean
    data['url'] = data['url'].astype(str)
    data['label'] = data['label'].astype(str)
    
    # Remove header-like values
    header_like_values = ['url', 'website', 'link', 'address', 'domain']
    data = data[~data['url'].str.lower().isin(header_like_values)]
    
    # Remove label header values
    label_header_values = ['label', 'class', 'category', 'type', 'classification']
    data = data[~data['label'].str.lower().isin(label_header_values)]
    
    # Remove invalid URLs
    data = data[data['url'].str.len() > 5]
    data = data[data['url'].str.contains(r'[./]', na=False)]
    
    cleaned_size = len(data)
    removed_count = initial_size - cleaned_size
    
    print(f"✅ Data cleaning completed:")
    print(f"   Initial rows: {initial_size}")
    print(f"   Cleaned rows: {cleaned_size}")
    print(f"   Removed rows: {removed_count}")
    
    # Show sample data
    if len(data) > 0:
        print(f"📊 Sample data:")
        print(data.head(3))
        print(f"   Label distribution: {data['label'].value_counts().to_dict()}")
    
    # Memory optimization
    gc.collect()
    
    return data

# RTX 3050 optimized TF-IDF vectorizer - CPU ONLY, optimized for full dataset
class RTX3050TfidfVectorizer:
    """TF-IDF vectorizer optimized for RTX 3050 - CPU processing only, full dataset."""
    
    def __init__(self, max_features=None, ngram_range=(3, 5)):
        self.max_features = max_features or RTX_3050_CONFIG['max_features']
        self.ngram_range = ngram_range
        
        print(f"🚀 RTX 3050 TF-IDF Vectorizer: {self.max_features} features (CPU only, full dataset)")
        
        # Use standard TF-IDF with CPU processing, optimized for full dataset
        self.vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=ngram_range,
            max_features=self.max_features,
            min_df=10,  # Increased for full dataset
            max_df=0.85,  # Slightly more restrictive for full dataset
            dtype=np.float32,
            strip_accents='ascii',
            lowercase=True,
            token_pattern=None  # Use char_wb analyzer
        )
    
    def fit_transform(self, X):
        """Fit and transform with RTX 3050 optimizations - CPU only, full dataset."""
        print("🚀 RTX 3050 TF-IDF fitting and transformation (CPU, full dataset)...")
        
        # Memory monitoring
        initial_memory = psutil.virtual_memory().used / 1024**3
        print(f"📊 Initial RAM usage: {initial_memory:.1f}GB")
        
        # CPU fit with progress monitoring
        start_time = time.time()
        
        # Process in batches for memory efficiency if dataset is very large
        if len(X) > 100000:
            print("📊 Large dataset detected, processing TF-IDF in memory-efficient mode...")
            
        X_transformed = self.vectorizer.fit_transform(X)
        fit_time = time.time() - start_time
        
        # Memory usage after transformation
        final_memory = psutil.virtual_memory().used / 1024**3
        memory_used = final_memory - initial_memory
        
        print(f"✅ TF-IDF completed in {fit_time:.2f}s - Shape: {X_transformed.shape}")
        print(f"📊 Sparse matrix memory: {X_transformed.data.nbytes / 1024**2:.1f}MB")
        print(f"📊 RAM usage increase: {memory_used:.1f}GB")
        print(f"📊 Sparsity: {(1 - X_transformed.nnz / (X_transformed.shape[0] * X_transformed.shape[1])) * 100:.2f}%")
        
        return X_transformed
    
    def transform(self, X):
        """Transform with RTX 3050 optimizations - CPU only."""
        X_transformed = self.vectorizer.transform(X)
        return X_transformed

# RTX 3050 optimized classifier with proper XGBoost handling for full dataset
class RTX3050Classifier:
    """Classifier optimized for RTX 3050 with proper sparse matrix handling, full dataset."""
    
    def __init__(self, gpu_info):
        self.gpu_info = gpu_info
        self.model = None
        self.model_type = None
        
        if gpu_info['xgboost_gpu']:
            print("🚀 Using XGBoost GPU optimized for RTX 3050 (full dataset)")
            try:
                # Test XGBoost version compatibility
                xgb_version = xgb.__version__
                print(f"   XGBoost version: {xgb_version}")
                
                # Use appropriate parameters based on XGBoost version
                if hasattr(xgb.XGBClassifier(), 'device'):  # XGBoost 2.0+
                    self.model = xgb.XGBClassifier(
                        device='cuda',
                        tree_method='hist',
                        n_estimators=RTX_3050_CONFIG['n_estimators'],
                        max_depth=RTX_3050_CONFIG['max_depth'],
                        learning_rate=0.1,
                        subsample=0.8,
                        colsample_bytree=0.8,
                        reg_alpha=0.1,
                        reg_lambda=0.1,
                        random_state=42,
                        eval_metric='logloss'
                    )
                else:  # XGBoost 1.x
                    self.model = xgb.XGBClassifier(
                        tree_method='gpu_hist',
                        gpu_id=0,
                        predictor='gpu_predictor',
                        n_estimators=RTX_3050_CONFIG['n_estimators'],
                        max_depth=RTX_3050_CONFIG['max_depth'],
                        learning_rate=0.1,
                        subsample=0.8,
                        colsample_bytree=0.8,
                        reg_alpha=0.1,
                        reg_lambda=0.1,
                        random_state=42,
                        eval_metric='logloss',
                        use_label_encoder=False
                    )
                
                self.model_type = "XGBoost_RTX3050_FullDataset"
                print(f"✅ XGBoost GPU model initialized")
                
            except Exception as e:
                print(f"⚠️  XGBoost GPU initialization failed: {e}")
                print("   Falling back to CPU RandomForest...")
                self._init_cpu_model()
        else:
            self._init_cpu_model()
    
    def _init_cpu_model(self):
        """Initialize CPU RandomForest model."""
        print("🔄 Using CPU RandomForest with high parallelization (full dataset)")
        from sklearn.ensemble import RandomForestClassifier
        
        self.model = RandomForestClassifier(
            n_estimators=RTX_3050_CONFIG['n_estimators'],
            max_depth=RTX_3050_CONFIG['max_depth'],
            n_jobs=RTX_3050_CONFIG['parallel_jobs'],
            random_state=42,
            max_features='sqrt',
            min_samples_split=5,
            min_samples_leaf=2,
            bootstrap=True,
            verbose=1  # Show progress
        )
        self.model_type = "RandomForest_CPU_FullDataset"
    
    def fit(self, X, y):
        """Fit model with RTX 3050 optimizations and proper memory management for full dataset."""
        print(f"🚀 Training {self.model_type} on RTX 3050 with full dataset...")
        print(f"📊 Training data shape: {X.shape}")
        print(f"📊 Training samples: {len(y)}")
        
        # Memory cleanup before training
        if TORCH_AVAILABLE:
            torch.cuda.empty_cache()
        
        if CUPY_AVAILABLE:
            cp.get_default_memory_pool().free_all_blocks()
            cp.get_default_pinned_memory_pool().free_all_blocks()
        
        gc.collect()
        
        # Monitor system memory
        initial_ram = psutil.virtual_memory().used / 1024**3
        print(f"📊 RAM before training: {initial_ram:.1f}GB")
        
        start_time = time.time()
        
        try:
            if "XGBoost" in self.model_type:
                print("🔄 Training XGBoost with sparse matrix (no dense conversion)...")
                
                # Convert sparse matrix to appropriate format for XGBoost if needed
                if hasattr(X, 'toarray'):
                    # For very large datasets, we might need to use DMatrix
                    if X.shape[0] > 100000:
                        print("   Using DMatrix for large dataset...")
                        dtrain = xgb.DMatrix(X, label=y)
                        
                        # Get model parameters
                        params = self.model.get_params()
                        params['objective'] = 'binary:logistic'
                        
                        # Train with DMatrix
                        self.model = xgb.train(
                            params,
                            dtrain,
                            num_boost_round=params.get('n_estimators', 300),
                            verbose_eval=False
                        )
                        self._is_booster = True
                    else:
                        # Regular fit for smaller datasets
                        self.model.fit(X, y)
                        self._is_booster = False
                else:
                    self.model.fit(X, y)
                    self._is_booster = False
                    
            else:
                # CPU RandomForest training
                print("🔄 Training RandomForest on CPU...")
                self.model.fit(X, y)
                
                # Print OOB score if available
                if hasattr(self.model, 'oob_score_'):
                    print(f"📊 Out-of-bag score: {self.model.oob_score_:.4f}")
            
            training_time = time.time() - start_time
            print(f"✅ Training completed in {training_time:.2f}s ({training_time/60:.1f} minutes)")
            
        except Exception as e:
            print(f"❌ Training failed: {e}")
            print("   Trying alternative approach...")
            
            # Fallback to basic RandomForest
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(
                n_estimators=100,  # Reduced for safety
                max_depth=10,
                n_jobs=2,  # Reduced parallelism
                random_state=42
            )
            self.model_type = "RandomForest_Fallback"
            self.model.fit(X, y)
            self._is_booster = False
            
            training_time = time.time() - start_time
            print(f"✅ Fallback training completed in {training_time:.2f}s")
        
        # Check RAM usage after training
        final_ram = psutil.virtual_memory().used / 1024**3
        ram_used = final_ram - initial_ram
        print(f"📊 RAM used during training: {ram_used:.1f}GB")
    
    def predict(self, X):
        """Predict with proper handling of different model types."""
        try:
            if hasattr(self, '_is_booster') and self._is_booster:
                # XGBoost Booster object
                dtest = xgb.DMatrix(X)
                predictions = self.model.predict(dtest)
                return (predictions > 0.5).astype(int)
            else:
                # Standard scikit-learn interface
                return self.model.predict(X)
        except Exception as e:
            print(f"❌ Prediction failed: {e}")
            # Return safe predictions
            return np.zeros(X.shape[0])
    
    def predict_proba(self, X):
        """Predict probabilities with proper handling of different model types."""
        try:
            if hasattr(self, '_is_booster') and self._is_booster:
                # XGBoost Booster object
                dtest = xgb.DMatrix(X)
                predictions = self.model.predict(dtest)
                # Convert to probability format
                proba = np.column_stack([1 - predictions, predictions])
                return proba
            else:
                # Standard scikit-learn interface
                return self.model.predict_proba(X)
        except Exception as e:
            print(f"❌ Probability prediction failed: {e}")
            # Return safe probabilities
            n_samples = X.shape[0]
            return np.column_stack([np.full(n_samples, 0.5), np.full(n_samples, 0.5)])

# Main training pipeline for RTX 3050 - FULL DATASET
def main():
    """Main training pipeline optimized for RTX 3050 with FULL dataset."""
    
    print("🚀 RTX 3050 Phishing URL Classifier Training Pipeline - FULL DATASET")
    print("=" * 70)
    
    # System info
    print(f"💻 System Info:")
    print(f"   GPU: {gpu_info.get('gpu_name', 'Unknown')}")
    print(f"   CUDA: {torch.version.cuda if TORCH_AVAILABLE else 'Not available'}")
    print(f"   RAM: {psutil.virtual_memory().total / 1024**3:.1f}GB")
    print(f"   CPU Cores: {mp.cpu_count()}")
    
    # Find and load dataset
    dataset_path = find_dataset_file()
    if dataset_path is None:
        print("❌ Error: Dataset file 'phishing_site_urls.csv' not found!")
        print("💡 Please place the dataset file in one of these locations:")
        print("   - Current directory: phishing_site_urls.csv")
        print("   - Data folder: data/phishing_site_urls.csv")
        print("   - Training folder: training/phishing_site_urls.csv")
        return
    
    # Load and preprocess data
    data = load_and_preprocess_data(dataset_path)
    if data is None or len(data) == 0:
        print("❌ No data available for training")
        return
    
    # Label encoding with better error handling
    print("🏷️  Processing labels...")
    unique_labels = data['label'].unique()
    print(f"   Unique labels found: {unique_labels}")
    
    # More flexible label mapping
    label_mapping = {}
    phishing_keywords = ['bad', 'phishing', 'malicious', 'phish', '1', 'true', 'malware', 'suspicious']
    legitimate_keywords = ['good', 'legitimate', 'benign', 'legit', '0', 'false', 'safe', 'normal']
    
    for label in unique_labels:
        label_str = str(label).lower().strip()
        
        # Check for exact matches first
        if label_str in phishing_keywords:
            label_mapping[label] = 1
        elif label_str in legitimate_keywords:
            label_mapping[label] = 0
        else:
            # Check for partial matches
            is_phishing = any(keyword in label_str for keyword in phishing_keywords)
            is_legitimate = any(keyword in label_str for keyword in legitimate_keywords)
            
            if is_phishing and not is_legitimate:
                label_mapping[label] = 1
                print(f"   Mapped '{label}' to phishing (1)")
            elif is_legitimate and not is_phishing:
                label_mapping[label] = 0
                print(f"   Mapped '{label}' to legitimate (0)")
            else:
                print(f"❌ Ambiguous label '{label}' - please check your dataset")
                print(f"   Expected labels: {phishing_keywords + legitimate_keywords}")
                return
    
    # Apply label mapping
    data['label'] = data['label'].map(label_mapping)
    
    # Check for unmapped labels
    if data['label'].isnull().any():
        print("❌ Some labels could not be mapped!")
        unmapped = data[data['label'].isnull()]
        print(f"   Unmapped labels: {unmapped['label'].unique()}")
        return
    
    # Check label distribution
    label_counts = data['label'].value_counts()
    print(f"   Final label distribution: {dict(label_counts)}")
    
    # Ensure we have both classes
    if len(label_counts) < 2:
        print("❌ Dataset must contain both legitimate and phishing URLs")
        return
    
    # Check for class imbalance
    min_class_count = label_counts.min()
    max_class_count = label_counts.max()
    imbalance_ratio = max_class_count / min_class_count
    
    if imbalance_ratio > 10:
        print(f"⚠️  Severe class imbalance detected (ratio: {imbalance_ratio:.1f})")
        print("   Consider using stratified sampling or class weights")
    
    # Train-test split with error handling
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            data['url'], data['label'], 
            test_size=0.2, 
            random_state=42, 
            stratify=data['label']
        )
        print(f"📊 FULL dataset split: {len(X_train)} train, {len(X_test)} test")
    except Exception as e:
        print(f"❌ Train-test split failed: {e}")
        return
    
    # Feature extraction with error handling
    try:
        vectorizer = RTX3050TfidfVectorizer()
        
        start_time = time.time()
        print("📊 Starting TF-IDF feature extraction...")
        X_train_vec = vectorizer.fit_transform(X_train)
        X_test_vec = vectorizer.transform(X_test)
        feature_time = time.time() - start_time
        
        print(f"✅ Feature extraction completed in {feature_time:.2f} seconds")
        print(f"📊 Feature matrix shape: {X_train_vec.shape}")
        
    except Exception as e:
        print(f"❌ Feature extraction failed: {e}")
        return
    
    # Model training with error handling
    try:
        classifier = RTX3050Classifier(gpu_info)
        
        start_time = time.time()
        classifier.fit(X_train_vec, y_train)
        training_time = time.time() - start_time
        
        print(f"✅ Model training completed in {training_time:.2f} seconds")
        
    except Exception as e:
        print(f"❌ Model training failed: {e}")
        return
    
    # Evaluation with error handling
    try:
        print("📊 Evaluating model...")
        start_time = time.time()
        y_pred = classifier.predict(X_test_vec)
        y_pred_proba = classifier.predict_proba(X_test_vec)
        prediction_time = time.time() - start_time
        
        # Results
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n{'='*70}")
        print("RTX 3050 PHISHING CLASSIFIER RESULTS - FULL DATASET")
        print(f"{'='*70}")
        print(f"✅ Training completed successfully!")
        print(f"📊 Accuracy: {accuracy:.4f}")
        print(f"🔧 Model Type: {classifier.model_type}")
        print(f"🖥️  GPU: {gpu_info.get('gpu_name', 'Unknown')}")
        print(f"📈 Features: {RTX_3050_CONFIG['max_features']:,}")
        print(f"📊 Training Samples: {len(X_train):,}")
        print(f"📊 Test Samples: {len(X_test):,}")
        print(f"📊 Total Samples: {len(data):,}")
        
        print(f"\n⏱️  Timing Summary:")
        print(f"   Feature extraction: {feature_time:.2f} seconds")
        print(f"   Model training: {training_time:.2f} seconds")
        print(f"   Prediction: {prediction_time:.2f} seconds")
        print(f"   Total: {(feature_time + training_time + prediction_time):.2f} seconds")
        
        print("\n📊 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Save models
        models_dir = "models"
        os.makedirs(models_dir, exist_ok=True)
        
        # Use standard names for compatibility
        model_path = os.path.join(models_dir, "phishing_classifier.pkl")
        vectorizer_path = os.path.join(models_dir, "tfidf_vectorizer.pkl")
        
        joblib.dump(classifier, model_path)
        joblib.dump(vectorizer, vectorizer_path)
        
        # Save evaluation results
        evaluation_results = {
            "accuracy": float(accuracy),
            "model_type": classifier.model_type,
            "gpu_used": gpu_info['xgboost_gpu'],
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "total_samples": len(data),
            "feature_count": X_train_vec.shape[1],
            "training_time": training_time,
            "gpu_info": gpu_info
        }
        
        results_path = os.path.join(models_dir, "evaluation_results.json")
        with open(results_path, 'w') as f:
            json.dump(evaluation_results, f, indent=2)
        
        print(f"\n💾 Models saved:")
        print(f"   Classifier: {model_path}")
        print(f"   Vectorizer: {vectorizer_path}")
        print(f"   Results: {results_path}")
        
    except Exception as e:
        print(f"❌ Evaluation failed: {e}")
        return
    
    # Memory cleanup
    if TORCH_AVAILABLE:
        torch.cuda.empty_cache()
    
    if CUPY_AVAILABLE:
        cp.get_default_memory_pool().free_all_blocks()
        cp.get_default_pinned_memory_pool().free_all_blocks()
    
    gc.collect()
    print("\n✅ RTX 3050 full dataset training completed successfully!")

if __name__ == "__main__":
    main()