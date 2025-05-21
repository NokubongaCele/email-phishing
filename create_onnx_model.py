"""
Script to generate a simple ONNX model for phishing detection
"""
import os
import numpy as np
import sklearn
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.datasets import make_classification
import onnxruntime as rt
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

print("Creating ONNX model...")
print(f"sklearn version: {sklearn.__version__}")

# Number of features from email_processor.py
n_features = 15

# Generate a synthetic dataset for the model
# This will be replaced by real training in a production scenario
X, y = make_classification(
    n_samples=1000, 
    n_features=n_features, 
    n_informative=10, 
    n_classes=2, 
    random_state=42
)

# Train a simple model
model = GradientBoostingClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Convert the model to ONNX format
initial_type = [('float_input', FloatTensorType([None, n_features]))]
onnx_model = convert_sklearn(model, initial_types=initial_type)

# Create output directory if it doesn't exist
os.makedirs('static/onnx_model', exist_ok=True)

# Save the model
output_path = 'static/onnx_model/phishing_model.onnx'
with open(output_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"ONNX model saved to {output_path}")

# Test the model
session = rt.InferenceSession(output_path)
input_name = session.get_inputs()[0].name
output_names = [output.name for output in session.get_outputs()]

print(f"Model input name: {input_name}")
print(f"Model output names: {output_names}")

# Test with a single sample
test_sample = np.array([X[0]], dtype=np.float32)
result = session.run(None, {input_name: test_sample})

print("Test prediction successful!")
print(f"Prediction: {result[0]}")
print(f"Probability: {result[1]}")