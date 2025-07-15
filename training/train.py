import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
import json
import numpy as np

# GPU-enabled imports
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
    CUPY_AVAILABLE = True
    print("✅ CuPy available for GPU acceleration")
except ImportError:
    print("⚠️  CuPy not available, using CPU")
    CUPY_AVAILABLE = False

# Check for GPU availability
def check_gpu_availability():
    """Check if GPU is available for training."""
    gpu_info = {
        'xgboost_gpu': False,
        'cupy_available': CUPY_AVAILABLE,
        'device_count': 0
    }
    
    if GPU_AVAILABLE:
        try:
            # Check XGBoost GPU support
            import xgboost as xgb
            gpu_info['xgboost_gpu'] = xgb.gpu.get_gpu_count() > 0
            gpu_info['device_count'] = xgb.gpu.get_gpu_count()
        except:
            pass
    
    return gpu_info

gpu_info = check_gpu_availability()
print(f"🖥️  GPU Info: {gpu_info}")

# Step 1: Load the dataset with proper file path handling
def find_dataset_file():
    """Find the phishing dataset file in common locations."""
    possible_paths = [
        "phishing_site_urls.csv",
        "training/phishing_site_urls.csv",
        os.path.join(os.path.dirname(__file__), "phishing_site_urls.csv"),
        os.path.join(os.path.dirname(__file__), "..", "training", "phishing_site_urls.csv"),
        "data/phishing_site_urls.csv",
        "../data/phishing_site_urls.csv"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            print(f"✅ Found dataset at: {path}")
            return path
    
    return None

# Try to find the dataset file
dataset_path = find_dataset_file()

if dataset_path is None:
    print("❌ Error: Dataset file 'phishing_site_urls.csv' not found!")
    print("\n📋 Please ensure the dataset file is available in one of these locations:")
    print("   1. Current directory: phishing_site_urls.csv")
    print("   2. Training directory: training/phishing_site_urls.csv")
    print("   3. Data directory: data/phishing_site_urls.csv")
    print("\n💡 You can download a phishing dataset from:")
    print("   - Kaggle: https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls")
    print("   - GitHub: https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques")
    exit(1)

try:
    # Try reading with different possible formats
    try:
        # First try: assume header exists
        data = pd.read_csv(dataset_path)
        print(f"✅ Successfully loaded dataset with header from: {dataset_path}")
        
        # Check if first row looks like header
        first_row_values = data.iloc[0].values if not data.empty else []
        if any(str(val).lower() in ['url', 'label', 'website', 'class', 'category'] for val in first_row_values):
            print("📋 Header row detected in data, using existing column names")
            # Rename columns to standard names
            if len(data.columns) >= 2:
                data.columns = ['url', 'label'] + list(data.columns[2:])
        else:
            # No header, assign column names
            if len(data.columns) >= 2:
                data.columns = ['url', 'label'] + list(data.columns[2:])
                print("⚠️  No header detected, assigned column names 'url' and 'label'")
    except:
        # Second try: assume no header, two columns
        data = pd.read_csv(dataset_path, names=["url", "label"])
        print(f"✅ Successfully loaded dataset without header from: {dataset_path}")
        
except Exception as e:
    print(f"❌ Error loading dataset: {e}")
    exit(1)

# Check if data is loaded correctly
if data.empty:
    print("❌ Error: Dataset is empty!")
    exit(1)

# Validate columns
if 'url' not in data.columns or 'label' not in data.columns:
    print("❌ Error: Dataset must have 'url' and 'label' columns")
    print(f"Found columns: {list(data.columns)}")
    exit(1)

# Clean the data - remove header rows that might be mixed in the data
print("🧹 Cleaning dataset...")
initial_size = len(data)

# Remove rows where URL column contains header-like values
header_like_values = ['url', 'website', 'link', 'address', 'domain']
data = data[~data['url'].astype(str).str.lower().isin(header_like_values)]

# Remove rows where label column contains header-like values  
label_header_values = ['label', 'class', 'category', 'type', 'classification']
data = data[~data['label'].astype(str).str.lower().isin(label_header_values)]

# Remove any completely empty rows
data = data.dropna(subset=['url', 'label'])

# Remove rows with invalid URLs (too short or clearly not URLs)
data = data[data['url'].astype(str).str.len() > 5]  # Minimum URL length
data = data[data['url'].astype(str).str.contains(r'[./]', na=False)]  # Must contain . or /

cleaned_size = len(data)
removed_rows = initial_size - cleaned_size
if removed_rows > 0:
    print(f"🗑️  Removed {removed_rows} invalid/header rows from dataset")

print(f"Dataset size after cleaning: {len(data)}")
print(f"Label distribution after cleaning:\n{data['label'].value_counts()}")

# Check if we have enough data
if len(data) < 10:
    print("⚠️  Warning: Very small dataset detected. Results may not be reliable.")

# Step 2: Handle different label formats and encode properly
unique_labels = data['label'].unique()
print(f"Unique labels found: {unique_labels}")

# Handle different label formats - be more specific about mapping
label_mapping = {}
for label in unique_labels:
    label_str = str(label).lower().strip()
    if label_str in ['bad', 'phishing', 'malicious', 'phish', '1', 'true', 'malware']:
        label_mapping[label] = 1
    elif label_str in ['good', 'legitimate', 'benign', 'legit', '0', 'false', 'safe']:
        label_mapping[label] = 0
    else:
        # For unknown labels, try to infer from context
        if 'bad' in label_str or 'phish' in label_str or 'malicious' in label_str:
            label_mapping[label] = 1
            print(f"⚠️  Inferred label '{label}' as phishing (1)")
        elif 'good' in label_str or 'legit' in label_str or 'safe' in label_str:
            label_mapping[label] = 0
            print(f"⚠️  Inferred label '{label}' as legitimate (0)")
        else:
            print(f"❌ Unknown label '{label}' found. Please check your dataset format.")
            print("Expected labels: 'good'/'bad', 'legitimate'/'phishing', '0'/'1'")
            exit(1)

data['label'] = data['label'].map(label_mapping)
print(f"Label mapping applied: {label_mapping}")

# Verify label encoding
if data['label'].isnull().any():
    print("❌ Error: Some labels could not be encoded!")
    print(data[data['label'].isnull()])
    exit(1)

# Ensure we have both classes
label_counts = data['label'].value_counts()
if len(label_counts) < 2:
    print("❌ Error: Dataset must contain both legitimate and phishing URLs")
    exit(1)

print(f"Final label distribution:\n{label_counts}")

# Additional data validation
print("\n📊 Dataset Statistics:")
print(f"Total URLs: {len(data)}")
print(f"Legitimate URLs: {(data['label'] == 0).sum()}")
print(f"Phishing URLs: {(data['label'] == 1).sum()}")
print(f"Average URL length: {data['url'].str.len().mean():.1f} characters")
print(f"URL length range: {data['url'].str.len().min()} - {data['url'].str.len().max()}")

# Show sample of the data
print(f"\n📋 Sample URLs from dataset:")
print("Legitimate URLs:")
legit_samples = data[data['label'] == 0]['url'].head(3)
for i, url in enumerate(legit_samples, 1):
    print(f"  {i}. {url}")

print("Phishing URLs:")
phish_samples = data[data['label'] == 1]['url'].head(3)
for i, url in enumerate(phish_samples, 1):
    print(f"  {i}. {url}")

# Step 3: Train-test split with minimum size check
min_samples_per_class = 3
test_size = 0.2

# Check if we have enough samples for each class
for label in [0, 1]:
    count = (data['label'] == label).sum()
    if count < min_samples_per_class:
        print(f"⚠️  Warning: Only {count} samples for label {label}. Need at least {min_samples_per_class}")
        test_size = max(0.1, min(0.3, 1/count))  # Adjust test size

# Ensure minimum dataset size for train-test split
if len(data) < 5:
    print("❌ Error: Dataset too small for training (minimum 5 samples required)")
    exit(1)

try:
    X_train, X_test, y_train, y_test = train_test_split(
        data['url'], data['label'], test_size=test_size, random_state=42, stratify=data['label']
    )
    print(f"✅ Train-test split successful: {len(X_train)} train, {len(X_test)} test samples")
except ValueError as e:
    print(f"⚠️  Stratified split failed, using simple split: {e}")
    X_train, X_test, y_train, y_test = train_test_split(
        data['url'], data['label'], test_size=test_size, random_state=42
    )

# Step 4: TF-IDF feature extraction using character-level n-grams (GPU accelerated if available)
print("Extracting features using TF-IDF...")
print(f"Processing {len(X_train)} training samples and {len(X_test)} test samples...")

# For very large datasets, use sampling for faster training
if len(X_train) > 100000:
    print("⚠️  Large dataset detected. Using sampling for faster training...")
    sample_size = min(100000, len(X_train))
    print(f"Sampling {sample_size} URLs for training (you can increase this if needed)")
    
    # Stratified sampling to maintain class balance
    from sklearn.model_selection import train_test_split
    X_train_sampled, _, y_train_sampled, _ = train_test_split(
        X_train, y_train, 
        train_size=sample_size, 
        random_state=42, 
        stratify=y_train
    )
    
    print(f"Sampled dataset: {len(X_train_sampled)} training samples")
    print(f"Sampled label distribution: {y_train_sampled.value_counts().to_dict()}")
    
    X_train = X_train_sampled
    y_train = y_train_sampled

# Optimize TF-IDF parameters for large datasets
max_features = 10000
if len(X_train) > 50000:
    max_features = 20000
elif len(X_train) > 20000:
    max_features = 15000

print(f"Using max_features={max_features} for TF-IDF vectorization")

# Use GPU acceleration for TF-IDF if CuPy is available
if CUPY_AVAILABLE and gpu_info['device_count'] > 0:
    print("🚀 Using GPU-accelerated feature extraction")
    vectorizer = TfidfVectorizer(
        analyzer='char_wb', 
        ngram_range=(3, 5), 
        max_features=max_features,
        min_df=3,  # Increased min_df for large datasets
        max_df=0.95,  # Remove very common features
        dtype=np.float32,  # Use float32 for GPU efficiency
        strip_accents='ascii',  # Faster preprocessing
        lowercase=True
    )
else:
    vectorizer = TfidfVectorizer(
        analyzer='char_wb', 
        ngram_range=(3, 5), 
        max_features=max_features,
        min_df=3,  # Increased min_df for large datasets  
        max_df=0.95,  # Remove very common features
        strip_accents='ascii',  # Faster preprocessing
        lowercase=True
    )

# Add progress monitoring for feature extraction
print("📊 Starting TF-IDF feature extraction...")
print("   This may take a few minutes for large datasets...")

import time
start_time = time.time()

# Fit and transform training data with progress monitoring
print("   Step 1/2: Fitting TF-IDF vectorizer on training data...")
X_train_vec = vectorizer.fit_transform(X_train)

fit_time = time.time() - start_time
print(f"   ✅ Training data vectorized in {fit_time:.2f} seconds")

# Transform test data
print("   Step 2/2: Transforming test data...")
transform_start = time.time()
X_test_vec = vectorizer.transform(X_test)

transform_time = time.time() - transform_start
total_time = time.time() - start_time

print(f"   ✅ Test data vectorized in {transform_time:.2f} seconds")
print(f"   🎯 Total vectorization time: {total_time:.2f} seconds")
print(f"Feature matrix shape: {X_train_vec.shape}")
print(f"Memory usage: Training={X_train_vec.data.nbytes / 1024**2:.1f}MB, Test={X_test_vec.data.nbytes / 1024**2:.1f}MB")

# Check memory usage and optimize if needed
total_memory_mb = (X_train_vec.data.nbytes + X_test_vec.data.nbytes) / 1024**2
if total_memory_mb > 1000:  # More than 1GB
    print(f"⚠️  High memory usage detected: {total_memory_mb:.1f}MB")
    print("   Consider reducing max_features or using sampling for very large datasets")

# Convert to GPU arrays if CuPy is available and dataset is manageable
USE_GPU_ARRAYS = False
if CUPY_AVAILABLE and total_memory_mb < 2000:  # Only if less than 2GB
    try:
        print("🔄 Converting data to GPU arrays...")
        gpu_start = time.time()
        
        X_train_gpu = cp.sparse.csr_matrix(X_train_vec)
        X_test_gpu = cp.sparse.csr_matrix(X_test_vec)
        y_train_gpu = cp.array(y_train.values)
        y_test_gpu = cp.array(y_test.values)
        
        gpu_time = time.time() - gpu_start
        print(f"✅ Data converted to GPU in {gpu_time:.2f} seconds")
        USE_GPU_ARRAYS = True
    except Exception as e:
        print(f"⚠️  GPU conversion failed: {e}, using CPU arrays")
        USE_GPU_ARRAYS = False
else:
    if CUPY_AVAILABLE:
        print("⚠️  Dataset too large for GPU memory, using CPU arrays")

# Step 5: Model selection and hyperparameter tuning with GPU acceleration
print("\n" + "="*50)
print("MODEL TRAINING")
print("="*50)
print("Performing model training with optimized parameters...")

# Adjust model complexity based on dataset size
if len(X_train) < 1000:
    complexity = "simple"
elif len(X_train) < 10000:
    complexity = "medium"
else:
    complexity = "complex"

print(f"Dataset complexity level: {complexity}")

if GPU_AVAILABLE and gpu_info['xgboost_gpu'] and total_memory_mb < 4000:
    print("🚀 Using XGBoost with GPU acceleration")
    
    # XGBoost parameters optimized for different dataset sizes
    if complexity == "simple":
        param_grid = {
            'max_depth': [3, 6],
            'learning_rate': [0.1, 0.3],
            'n_estimators': [50, 100],
            'subsample': [0.8, 1.0]
        }
        cv_folds = 3
    elif complexity == "medium":
        param_grid = {
            'max_depth': [3, 6, 10],
            'learning_rate': [0.1, 0.3],
            'n_estimators': [100, 200],
            'subsample': [0.8, 1.0],
            'colsample_bytree': [0.8, 1.0]
        }
        cv_folds = 3
    else:  # complex
        param_grid = {
            'max_depth': [6, 10],
            'learning_rate': [0.1, 0.2],
            'n_estimators': [200, 300],
            'subsample': [0.8, 0.9],
            'colsample_bytree': [0.8, 0.9],
            'reg_alpha': [0, 0.1]
        }
        cv_folds = 3  # Reduced for speed
    
    # XGBoost classifier with GPU support
    xgb_model = xgb.XGBClassifier(
        tree_method='gpu_hist',  # GPU-accelerated training
        gpu_id=0,  # Use first GPU
        predictor='gpu_predictor',  # GPU prediction
        random_state=42,
        eval_metric='logloss',
        use_label_encoder=False,
        n_jobs=1  # Let GPU handle parallelization
    )
    
    # Grid search with reduced verbosity for large datasets
    print(f"Starting hyperparameter search with {cv_folds}-fold CV...")
    grid_search = GridSearchCV(
        xgb_model, 
        param_grid, 
        cv=cv_folds, 
        scoring='accuracy', 
        n_jobs=1,  # XGBoost handles parallelization internally
        verbose=1 if len(X_train) < 10000 else 0  # Reduce verbosity for large datasets
    )
    
    # Fit the model with timing
    training_start = time.time()
    grid_search.fit(X_train_vec, y_train)
    training_time = time.time() - training_start
    
    model = grid_search.best_estimator_
    print(f"🎯 XGBoost training completed in {training_time:.2f} seconds")
    
else:
    print("🔄 Using RandomForest (CPU)")
    from sklearn.ensemble import RandomForestClassifier

    # Further reduce complexity for large datasets
    if len(X_train) > 50000:
        print("⚡ Large dataset detected: using fewer trees and features for speed")
        param_grid = {
            'n_estimators': [50],  # Fewer trees
            'max_depth': [10],     # Shallower trees
            'min_samples_split': [2]
        }
        cv_folds = 2  # Reduce folds for speed
        max_features_rf = 'sqrt'  # Use sqrt for feature selection
    else:
        # Adjust parameters based on dataset size and complexity
        if complexity == "simple":
            param_grid = {
                'n_estimators': [50, 100],
                'max_depth': [10, 20],
                'min_samples_split': [2, 5]
            }
            cv_folds = 3
        elif complexity == "medium":
            param_grid = {
                'n_estimators': [100, 200],
                'max_depth': [15, 25],
                'min_samples_split': [2, 5],
                'min_samples_leaf': [1, 2]
            }
            cv_folds = 3
        else:  # complex
            param_grid = {
                'n_estimators': [150, 250],
                'max_depth': [20, 30],
                'min_samples_split': [2, 3],
                'min_samples_leaf': [1, 2]
            }
            cv_folds = 3

        max_features_rf = None

    n_jobs = -1 if len(X_train) < 50000 else max(1, os.cpu_count() // 2)

    rf = RandomForestClassifier(
        random_state=42,
        n_jobs=n_jobs,
        warm_start=True,
        max_features=max_features_rf if max_features_rf else 'auto'
    )

    print(f"Starting RandomForest hyperparameter search with {cv_folds}-fold CV...")
    print("⏳ Fitting RandomForest model (this may take a while for large datasets)...")
    training_start = time.time()
    grid_search = GridSearchCV(
        rf,
        param_grid,
        cv=cv_folds,
        scoring='accuracy',
        n_jobs=1,
        verbose=1 if len(X_train) < 10000 else 0
    )
    grid_search.fit(X_train_vec, y_train)
    training_time = time.time() - training_start
    print(f"✅ RandomForest training completed in {training_time:.2f} seconds")

    model = grid_search.best_estimator_

print(f"Best parameters: {grid_search.best_params_}")
print(f"Best cross-validation score: {grid_search.best_score_:.4f}")

# Step 6: Evaluate the model (GPU accelerated prediction if available)
print("🔄 Performing model evaluation...")

if GPU_AVAILABLE and hasattr(model, 'predict_proba') and 'gpu' in str(type(model)):
    print("🚀 Using GPU for prediction")

y_pred = model.predict(X_test_vec)
y_pred_proba = model.predict_proba(X_test_vec)

print("\n" + "="*50)
print("MODEL EVALUATION RESULTS")
print("="*50)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Additional GPU-specific metrics
if GPU_AVAILABLE:
    print(f"\n🖥️  Training completed using: {'XGBoost GPU' if gpu_info['xgboost_gpu'] else 'CPU fallback'}")
    if gpu_info['device_count'] > 0:
        print(f"🔧 GPU devices used: {gpu_info['device_count']}")

# Step 7: Save model, vectorizer, and evaluation results
models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
os.makedirs(models_dir, exist_ok=True)

# Save model and vectorizer
model_path = os.path.join(models_dir, "phishing_classifier.pkl")
vectorizer_path = os.path.join(models_dir, "tfidf_vectorizer.pkl")

joblib.dump(model, model_path)
joblib.dump(vectorizer, vectorizer_path)

print(f"\nModel saved to: {model_path}")
print(f"Vectorizer saved to: {vectorizer_path}")

# Save evaluation metrics
evaluation_results = {
    "accuracy": float(accuracy_score(y_test, y_pred)),
    "best_params": grid_search.best_params_,
    "best_cv_score": float(grid_search.best_score_),
    "classification_report": classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'], output_dict=True),
    "feature_count": X_train_vec.shape[1],
    "training_samples": len(X_train),
    "test_samples": len(X_test),
    "model_type": "XGBoost" if GPU_AVAILABLE and gpu_info['xgboost_gpu'] else "RandomForest",
    "gpu_info": gpu_info,
    "gpu_accelerated": GPU_AVAILABLE and gpu_info['xgboost_gpu']
}

results_path = os.path.join(models_dir, "evaluation_results.json")
with open(results_path, 'w') as f:
    json.dump(evaluation_results, f, indent=2)

print(f"Evaluation results saved to: {results_path}")

# Step 8: Enhanced prediction function with GPU support
def predict_url(url, return_confidence=False):
    """
    Predict if a URL is phishing or legitimate using GPU acceleration.
    
    Args:
        url (str): URL to analyze
        return_confidence (bool): Whether to return confidence scores
    
    Returns:
        str or tuple: Prediction and optionally confidence scores
    """
    try:
        vec = vectorizer.transform([url])
        
        # Use GPU for prediction if available
        if GPU_AVAILABLE and hasattr(model, 'predict_proba'):
            prediction = model.predict(vec)[0]
        else:
            prediction = model.predict(vec)[0]
        
        if return_confidence:
            confidence = model.predict_proba(vec)[0]
            return ("phishing" if prediction == 1 else "legitimate", 
                   {"legitimate": float(confidence[0]), "phishing": float(confidence[1])})
        else:
            return "phishing" if prediction == 1 else "legitimate"
    except Exception as e:
        print(f"Error predicting URL: {e}")
        return "error"

# Step 9: Test with example URLs
test_urls = [
    "https://google.com",
    "http://bit.ly/malicious",
    "https://secure-banking-login.suspicious-domain.com/update-account",
    "https://github.com/user/repo"
]

print("\n" + "="*50)
print("TESTING PREDICTIONS")
print("="*50)

for url in test_urls:
    prediction, confidence = predict_url(url, return_confidence=True)
    print(f"URL: {url}")
    print(f"Prediction: {prediction.upper()}")
    print(f"Confidence - Legitimate: {confidence['legitimate']:.3f}, Phishing: {confidence['phishing']:.3f}")
    print("-" * 50)

# Step 10: Performance benchmarking
import time

print("\n" + "="*50)
print("PERFORMANCE BENCHMARKING")
print("="*50)

# Benchmark prediction speed with smaller sample for large datasets
benchmark_size = min(1000, len(test_urls) * 50)  # Limit benchmark size
benchmark_urls = (test_urls * (benchmark_size // len(test_urls) + 1))[:benchmark_size]

print(f"Benchmarking with {len(benchmark_urls)} predictions...")
start_time = time.time()

predictions = []
for url in benchmark_urls:
    pred = predict_url(url)
    predictions.append(pred)

end_time = time.time()
total_time = end_time - start_time
urls_per_second = len(benchmark_urls) / total_time

print(f"🚀 Performance Metrics:")
print(f"   Total URLs processed: {len(benchmark_urls)}")
print(f"   Total time: {total_time:.3f} seconds")
print(f"   URLs per second: {urls_per_second:.1f}")
print(f"   Average time per URL: {(total_time/len(benchmark_urls)*1000):.2f} ms")

# Memory cleanup
import gc
del X_train_vec, X_test_vec
if USE_GPU_ARRAYS:
    del X_train_gpu, X_test_gpu, y_train_gpu, y_test_gpu
gc.collect()

print("\n✅ Training completed successfully!")
print(f"🎯 Final model accuracy: {accuracy_score(y_test, y_pred):.4f}")
print(f"📁 Model saved to: {model_path}")
print(f"📁 Vectorizer saved to: {vectorizer_path}")
print(f"📁 Results saved to: {results_path}")
