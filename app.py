import re
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Allow local UI cross-origin request policies safely

def extract_url_features(url: str) -> dict:
    """
    Parses a URL string down into quantitative values 
    the ML mapping model uses for computing classification bounds.
    """
    # 1. Measure string payload scale
    length = len(url)
    
    # 2. Count standard structural anomalies used in obfuscation chains
    qty_hyphens = url.count('-')
    
    # 3. Use RegEx to search for raw IPv4 layouts bypassing DNS registrations
    ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    has_ip = 1 if re.match(ip_pattern, url) else 0
    
    return {
        "length": length,
        "qty_hyphens": qty_hyphens,
        "has_ip": has_ip
    }

def mock_inference_engine(features: dict) -> float:
    """
    Simulates tree split conditions of an ensemble model (like Random Forest).
    Returns a probability score ranging between 0.0 (Safe) and 1.0 (Phishing).
    """
    score = 0.1 # Base baseline noise
    
    # Structural triggers adding up risk weightings
    if features["length"] > 55:
        score += 0.35
    if features["qty_hyphens"] >= 2:
        score += 0.3
    if features["has_ip"] == 1:
        score += 0.45
        
    return min(score, 1.0) # Bind ceiling threshold constraints

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json() or {}
    target_url = data.get('url', '')
    
    if not target_url:
        return jsonify({"error": "Empty strings cannot be evaluated"}), 400
        
    # Process attributes through feature vectorization functions
    extracted = extract_url_features(target_url)
    risk_score = mock_inference_engine(extracted)
    
    # Binary classification cutoff point set at 50% risk
    verdict = "Phishing" if risk_score >= 0.5 else "Safe"
    
    # Append the calculated score into the feature telemetry output object
    extracted["risk_score"] = risk_score
    
    return jsonify({
        "url": target_url,
        "verdict": verdict,
        "features": extracted
    })

if __name__ == '__main__':
    # Launch on standard port 5000 locally
    app.run(debug=True, port=5000)