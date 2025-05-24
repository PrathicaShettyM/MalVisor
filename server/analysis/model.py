import joblib
import lightgbm as lgb
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Define the features to be used in training
FEATURE_COLUMNS = [
    "num_imports",
    "entropy_mean",
    "entropy_max",
    "entropy_min",
    "section_count",
    "filesize",
    "string_count",
    "suspicious_string_count",
]

# Supported malware families for classification and scoring
malware_families = [
    "ransomware", "trojan", "worm", "adware", "spyware",
    "backdoor", "keylogger", "dropper", "rootkit", "benign"
]


# Load dataset and train LightGBM model
def train_malware_classifier(csv_path: str, model_output: str = "malware_model.pkl"):
    data = pd.read_csv(csv_path)

    # Drop rows with missing values (basic cleaning)
    data.dropna(subset=FEATURE_COLUMNS + ["label"], inplace=True)

    X = data[FEATURE_COLUMNS]
    y = data["label"]  # Malware family/class

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = lgb.LGBMClassifier(objective="multiclass", num_class=len(set(y)), random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    joblib.dump(model, model_output)
    print(f"Model saved to {model_output}")

# Load and use model for prediction
def classify_sample(features: dict, model_path: str = "malware_model.pkl") -> dict:
    model = joblib.load(model_path)
    input_df = pd.DataFrame([features])[FEATURE_COLUMNS]
    pred_class = model.predict(input_df)[0]
    pred_prob = model.predict_proba(input_df)[0]

    return {
        "predicted_family": pred_class,
        "confidence": max(pred_prob)
    }

# Enhanced severity scoring (can be merged with model prediction output)
def calculate_severity_score(predicted_family: str, features: dict) -> float:
    family_weights = {
    "ransomware": 4.5,
    "trojan": 3.5,
    "worm": 3.0,
    "adware": 1.5,
    "spyware": 3.2,
    "backdoor": 3.8,
    "keylogger": 3.7,
    "dropper": 2.8,
    "rootkit": 4.0,
    "benign": 0.5,
    }

    
    if predicted_family.lower() not in malware_families:
        predicted_family = "unknown"
    
    family_score = family_weights.get(predicted_family.lower(), 1)

    obfuscation_score = features.get("entropy_max", 0) / 8  # normalized entropy
    api_score = features.get("suspicious_string_count", 0) / 10

    severity = min(10.0, family_score + obfuscation_score + api_score)
    return round(severity, 2)

# Full classification + scoring pipeline
def classify_and_score(features: dict, model_path: str = "malware_model.pkl") -> dict:
    classification_result = classify_sample(features, model_path)
    severity = calculate_severity_score(classification_result["predicted_family"], features)

    return {
        **classification_result,
        "severity_score": severity
    }
