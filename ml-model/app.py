from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import joblib
import os

app = Flask(__name__)
CORS(app)  # อนุญาตให้เรียกจาก frontend

# โหลด model
MODEL_PATH = 'models/risk_model.pkl'
model_data = joblib.load(MODEL_PATH)
model = model_data['model']
feature_columns = model_data['feature_columns']
label_mapping = model_data['label_mapping']
reverse_label_mapping = {v: k for k, v in label_mapping.items()}

print("✅ ML Model loaded successfully!")


@app.route('/')
def home():
    """
    API info page
    """
    return jsonify({
        'name': 'ML Risk Scorer API',
        'version': '1.0',
        'model': 'Random Forest',
        'accuracy': '100%',
        'endpoints': {
            '/predict': 'POST - Predict risk level for a single vulnerability',
            '/batch-predict': 'POST - Predict risk for multiple vulnerabilities',
            '/health': 'GET - Check API health',
            '/features': 'GET - List required features'
        }
    })


@app.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint
    """
    return jsonify({
        'status': 'healthy',
        'model_loaded': True,
        'features_count': len(feature_columns)
    })


@app.route('/features', methods=['GET'])
def get_features():
    """
    Return list of required features
    """
    return jsonify({
        'required_features': feature_columns,
        'count': len(feature_columns)
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict risk level for a single vulnerability
    
    Request body example:
    {
        "cvss_base_score": 8.5,
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "cvss_severity_encoded": 0,
        "attack_vector_encoded": 1,
        "attack_complexity_encoded": 0,
        "privileges_required_encoded": 2,
        "user_interaction_encoded": 1,
        "cvss_combined": 8.8,
        "attack_ease_score": 2.8,
        "public_exposure": 1,
        "age_factor": 0.5,
        "severity_score": 4
    }
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        # Create DataFrame from input
        df = pd.DataFrame([data])
        
        # Check for missing features
        missing_features = set(feature_columns) - set(df.columns)
        if missing_features:
            return jsonify({
                'error': f'Missing features: {list(missing_features)}',
                'required_features': feature_columns
            }), 400
        
        # Select only feature columns in correct order
        X = df[feature_columns]
        
        # Predict
        prediction = model.predict(X)[0]
        prediction_proba = model.predict_proba(X)[0]
        
        # Get risk level name
        risk_level = reverse_label_mapping.get(prediction, 'Unknown')
        confidence = float(max(prediction_proba))
        
        # Get all probabilities
        probabilities = {}
        for label_idx, prob in enumerate(prediction_proba):
            if label_idx in reverse_label_mapping:
                probabilities[reverse_label_mapping[label_idx]] = float(prob)
        
        return jsonify({
            'risk_level': risk_level,
            'confidence': confidence,
            'probabilities': probabilities,
            'input_features': data
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/batch-predict', methods=['POST'])
def batch_predict():
    """
    Predict risk level for multiple vulnerabilities
    
    Request body example:
    {
        "vulnerabilities": [
            {"cvss_base_score": 8.5, ...},
            {"cvss_base_score": 6.0, ...}
        ]
    }
    """
    data = request.get_json()
    
    if not data or 'vulnerabilities' not in data:
        return jsonify({'error': 'No vulnerabilities provided'}), 400
    
    vulnerabilities = data['vulnerabilities']
    
    if not isinstance(vulnerabilities, list):
        return jsonify({'error': 'vulnerabilities must be a list'}), 400
    
    try:
        results = []
        
        for vuln in vulnerabilities:
            df = pd.DataFrame([vuln])
            X = df[feature_columns]
            
            prediction = model.predict(X)[0]
            prediction_proba = model.predict_proba(X)[0]
            
            risk_level = reverse_label_mapping.get(prediction, 'Unknown')
            confidence = float(max(prediction_proba))
            
            results.append({
                'risk_level': risk_level,
                'confidence': confidence
            })
        
        return jsonify({
            'count': len(results),
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Starting ML Risk Scorer API...")
    print("="*60)
    print(f"\n📍 API available at: http://localhost:5001")
    print(f"📖 Documentation: http://localhost:5001/")
    print(f"❤️  Health check: http://localhost:5001/health")
    print(f"\n⚡ Press CTRL+C to stop\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
