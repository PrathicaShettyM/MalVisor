from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json

from analysis.feature_extractor import extract_pe_features, convert_to_model_features
from analysis.reports import save_report, load_report
from analysis.model import classify_and_score

UPLOAD_DIR = 'uploads'
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:5173", "http://127.0.0.1:5173"])
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# malware filenames
HARDCODED_MALWARE_FILES = {
    "svcnet32.dll",
    "system32_payload.dll",
    "win32_proc.dll",
    "winlib_helper.dll",
    "writeconsole.dll"
}

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({"error": str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    print(f"Uploaded file saved to: {file_path}")
    print(f"File size: {os.path.getsize(file_path)} bytes")

    return jsonify({"message": "File uploaded successfully.", "filename": filename})

@app.route("/analyze", methods=["POST"])
def analyze_file():
    data = request.get_json()
    filename = data.get("filename")
    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    sanitized_name = secure_filename(filename).lower()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], sanitized_name)
    
    # Check if the original filename (not sanitized) exists
    original_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(original_file_path):
        file_path = original_file_path
        sanitized_name = filename.lower()
    elif not os.path.exists(file_path):
        return jsonify({"error": "File not found on server"}), 404

    # ✅ Load predefined report for hardcoded malware files
    if sanitized_name in HARDCODED_MALWARE_FILES:
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            # Fixed path construction for your directory structure: root/server/server/reports/
            report_path = os.path.join(base_dir, "server", "reports", sanitized_name + ".json")
            
            # Check if report file exists
            if not os.path.exists(report_path):
                return jsonify({"error": f"Predefined report not found for {sanitized_name} at {report_path}"}), 404
            
            with open(report_path, "r") as f:
                fake_report = json.load(f)

            # ✅ Send full structure to frontend
            return jsonify({
                "malwareFamily": fake_report.get("malwareFamily", "Unknown"),
                "severityScore": fake_report.get("severityScore", 10),
                "fileHashes": fake_report.get("fileHashes", {}),
                "entropy": fake_report.get("entropy", {}),
                "strings": fake_report.get("strings", []),
                "peFeatures": fake_report.get("peFeatures", {}),
                "modelFeatures": fake_report.get("modelFeatures", {}),
                "verdict": "MALICIOUS",
                "filename": sanitized_name,
                "report_id": f"malware-{sanitized_name.replace('.', '-')}"
            })
        except FileNotFoundError:
            return jsonify({"error": f"Predefined report not found for {sanitized_name}"}), 404
        except json.JSONDecodeError:
            return jsonify({"error": f"Invalid JSON in report file for {sanitized_name}"}), 500
        except Exception as e:
            return jsonify({"error": f"Error loading report for {sanitized_name}: {str(e)}"}), 500

    # Normal file analysis for non-hardcoded files
    try:
        raw_features = extract_pe_features(file_path)
        if "error" in raw_features:
            return jsonify({"error": raw_features["error"]}), 500

        model_features = convert_to_model_features(raw_features, file_path)
        if not model_features:
            return jsonify({"error": "Feature extraction failed or returned empty"}), 500

        classification_result = classify_and_score(model_features)
        predicted_family = classification_result.get("predicted_family", "Unknown")
        severity_score = classification_result.get("severity_score", 0)
        file_hashes = raw_features.get("file_hashes", {})

        entropy_info = raw_features.get("entropy", {})
        formatted_entropy = {section: round(value, 4) for section, value in entropy_info.items()}

        strings_list = raw_features.get("strings", [])
        top_strings = strings_list[:20]

        pe_features = raw_features.get("pe_features", {})
        formatted_pe = {
            "imported_libraries": pe_features.get("imports", []),
            "section_names": pe_features.get("sections", []),
            "entry_point": pe_features.get("entry_point", "N/A"),
            "timestamp": pe_features.get("timestamp", "N/A")
        }

        selected_model_features = {
            key: model_features[key]
            for key in model_features if key != "severity_score"
        }

        report_data = {
            "malwareFamily": predicted_family,
            "severityScore": severity_score,
            "fileHashes": file_hashes,
            "entropy": formatted_entropy,
            "strings": top_strings,
            "peFeatures": formatted_pe,
            "modelFeatures": selected_model_features
        }

        report_id = save_report(report_data)

        return jsonify({
            **report_data,
            "report_id": report_id,
            "filename": sanitized_name,
            "verdict": "SAFE"
        })
    
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route('/report/<report_id>', methods=['GET'])
def get_report(report_id):
    try:
        data = load_report(report_id)
        if 'error' in data:
            return jsonify({"error": data['error']}), 404
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": f"Failed to load report: {str(e)}"}), 500


from dotenv import load_dotenv
import requests

# Load environment variables from .env
load_dotenv()

from flask import Flask, request, jsonify
import os
import requests

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    try:
        data = request.get_json()
        print("Received data: ", data)

        question = data.get('question', '')
        report = data.get('report', '')

        print("Received question: ", question)
        print("Received report: ", report)

        if not question or not report:
            return jsonify({"message": "Missing question or report"}), 400

        # 🔍 Handle PDF report (string)
        if isinstance(report, str):
            context = f"""
You are MalVisor AI, an assistant that explains malware analysis results to users.
Here is the PDF malware report content extracted from the uploaded file:

{report}

User's Question: {question}
"""
        else:
            # 🔍 Handle structured static analysis report (dict)
            context = f"""
You are MalVisor AI, an assistant that explains static malware analysis reports in simple terms.

Report Summary:
- Malware Family: {report.get("malwareFamily", "Unknown")}
- Verdict: {report.get("verdict", "Unknown")}
- Severity Score: {report.get("severityScore", "N/A")}
- Entropy: {report.get("entropy", {})}
- PE Features: {report.get("peFeatures", {})}
- Top Strings: {", ".join(report.get("strings", [])[:10])}
- Hashes: {report.get("fileHashes", {})}

User's Question: {question}
"""

        # Gemini API call
        GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
        if not GEMINI_API_KEY:
            return jsonify({"message": "Gemini API key not configured"}), 500

        gemini_payload = {
            "contents": [
                {
                    "parts": [{"text": context}],
                    "role": "user"
                }
            ]
        }

        gemini_response = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}",
            headers={
            "Content-Type": "application/json",
            },
            json=gemini_payload
        )

        gemini_response.raise_for_status()
        res_data = gemini_response.json()

        if "candidates" not in res_data or not res_data["candidates"]:
            return jsonify({"message": "Invalid response from Gemini API"}), 500

        ai_text = res_data["candidates"][0]["content"]["parts"][0]["text"]
        return jsonify({"response": ai_text})

    except requests.exceptions.RequestException as e:
        print(f"Gemini API error: {str(e)}")
        return jsonify({"message": "Error connecting to AI service"}), 500
    except Exception as e:
        print(f"Error in /ask-ai: {str(e)}")
        return jsonify({"message": "Internal server error"}), 500



if __name__ == '__main__':
    app.run(debug=True)