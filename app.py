import os
import logging
import numpy as np
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
import email_processor
import onnxruntime as ort
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the database
db.init_app(app)

# Load ONNX model
try:
    model_path = os.path.join(app.root_path, 'static', 'onnx_model', 'phishing_model.onnx')
    if os.path.exists(model_path):
        sess_options = ort.SessionOptions()
        sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        onnx_session = ort.InferenceSession(model_path, sess_options=sess_options)
        logger.info("ONNX model loaded successfully")
    else:
        logger.error(f"ONNX model not found at {model_path}")
        onnx_session = None
except Exception as e:
    logger.error(f"Error loading ONNX model: {str(e)}")
    onnx_session = None

with app.app_context():
    import models
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if request.method == 'POST':
        try:
            email_content = None
            email_file = None
            
            if 'email_content' in request.form and request.form['email_content'].strip():
                email_content = request.form['email_content']
                
            if 'email_file' in request.files and request.files['email_file'].filename:
                email_file = request.files['email_file']
                email_content = email_file.read().decode('utf-8', errors='ignore')
            
            if not email_content:
                flash('Please provide email content or upload an email file.', 'danger')
                return redirect(url_for('index'))
            
            # Process the email
            features, important_features = email_processor.extract_features(email_content)
            
            if onnx_session is None:
                flash('ONNX model is not loaded. Cannot perform prediction.', 'danger')
                return redirect(url_for('index'))
            
            # Make prediction using ONNX model
            input_name = onnx_session.get_inputs()[0].name
            features_array = np.array([features], dtype=np.float32)
            
            prediction = onnx_session.run(None, {input_name: features_array})
            
            # Extract prediction results
            prediction_label = int(prediction[0][0])
            confidence_score = float(prediction[1][0][prediction_label])
            
            # Prepare result data
            result = {
                'is_phishing': True if prediction_label == 1 else False,
                'confidence': confidence_score * 100,
                'important_features': important_features,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'features': features
            }
            
            # Store result in session
            session['analysis_result'] = result
            
            # Log the analysis
            analysis = models.Analysis(
                email_content=email_content[:1000],  # Store first 1000 chars
                prediction=prediction_label,
                confidence=confidence_score,
                features=json.dumps(important_features)
            )
            db.session.add(analysis)
            db.session.commit()
            
            return redirect(url_for('results'))
        
        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}")
            flash(f'An error occurred during analysis: {str(e)}', 'danger')
            return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.route('/results')
def results():
    if 'analysis_result' not in session:
        flash('No analysis results available. Please analyze an email first.', 'warning')
        return redirect(url_for('index'))
    
    result = session['analysis_result']
    return render_template('results.html', result=result)

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
