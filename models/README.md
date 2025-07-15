# Models Directory

This directory will contain trained machine learning models for phishing detection.

## File Structure

- `*.pkl` or `*.joblib` files: Scikit-learn models
- `*.h5` files: Keras/TensorFlow models  
- `model_info.json`: Model metadata and configuration

## Model Types

Planned model types:
- Random Forest Classifier
- Gradient Boosting Classifier
- Support Vector Machine
- Neural Network (optional)

## Usage

Models should be loaded using the `load_model()` function in the main application.
