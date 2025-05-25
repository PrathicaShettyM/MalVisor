from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os

from analysis.feature_extractor import extract_pe_features
from analysis.model import classify_and_score
from analysis.severity_wrapper import compute_severity
from analysis.reports import save_report, load_report

UPLOAD_DIR = 'server/uploads'

app = Flask(__name__)
CORS(app)

app.config['UPLOAD_FOLDER'] = UPLOAD_DIR

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# 1. Upload Endpoint
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    return jsonify({"message": "File uploaded successfully.", "filename": filename})


# 2. Analyze Endpoint
@app.route('/analyze', methods=['POST'])
def analyze_file():
    filename = request.form.get('filename')
    if not filename:
        return jsonify({"error": "Filename not provided."}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found on server."}), 404

    raw_features = extract_pe_features(file_path)
    if "error" in raw_features:
        return jsonify(raw_features), 400

    result = classify_and_score(raw_features)
    result["raw_features"] = raw_features

    report_id = save_report(result)
    os.remove(file_path)

    return jsonify({
        "message": "Analysis complete.",
        "report_id": report_id,
        "predicted_family": result["predicted_family"],
        "severity": result["severity_score"]
    })


# 3. Report Endpoint 
@app.route('/report/<report_id>', methods=['GET'])
def get_report(report_id):
    data = load_report(report_id)
    if 'error' in data:
        return jsonify(data), 404
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
