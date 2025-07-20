import joblib
import os
import lightgbm as lgb
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_OUTPUT = os.path.join(BASE_DIR, "malware_model.pkl")

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

malware_families = [
    "ransomware", "trojan", "worm", "adware", "spyware",
    "backdoor", "keylogger", "dropper", "rootkit", "benign"
]

def train_malware_classifier(csv_path: str, model_output: str = MODEL_OUTPUT):
    data = pd.read_csv(csv_path)
    data.dropna(subset=FEATURE_COLUMNS + ["label"], inplace=True)

    X = data[FEATURE_COLUMNS]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = lgb.LGBMClassifier(objective="multiclass", num_class=len(set(y)), random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    joblib.dump(model, model_output)
    print(f"Model saved to {model_output}")


def classify_sample(features: dict, model_path: str = MODEL_OUTPUT) -> dict:
    missing = [col for col in FEATURE_COLUMNS if col not in features]
    if missing:
        raise ValueError(f"Missing features: {missing}")

    model = joblib.load(model_path)
    input_df = pd.DataFrame([features])[FEATURE_COLUMNS]
    pred_probs = model.predict_proba(input_df)[0]
    classes = model.classes_

    predicted_index = pred_probs.argmax()
    predicted_class = classes[predicted_index]
    confidence = pred_probs[predicted_index]

    # ✅ Apply override if not benign and confidence is low
    if predicted_class != "benign" and confidence < 0.75:
        predicted_class = "benign"
        confidence = 1 - confidence  # Lower malware confidence implies benign confidence

    return {
        "predicted_family": predicted_class,
        "confidence": round(confidence, 4)
    }


def calculate_severity_score(predicted_family: str, features: dict) -> float:
    family_weights = {
        "ransomware": 4.5, "trojan": 3.5, "worm": 3.0,
        "adware": 1.5, "spyware": 3.2, "backdoor": 3.8,
        "keylogger": 3.7, "dropper": 2.8, "rootkit": 4.0,
        "benign": 0.5
    }

    if predicted_family.lower() not in malware_families:
        predicted_family = "unknown"

    family_score = family_weights.get(predicted_family.lower(), 1)

    adjusted_entropy = max(0, features.get("entropy_max", 0) - 3.0)
    obfuscation_score = adjusted_entropy / 8
    api_score = features.get("suspicious_string_count", 0) / 10

    severity = min(10.0, family_score + obfuscation_score + api_score)
    return round(severity, 2)


def classify_and_score(features: dict, model_path: str = MODEL_OUTPUT) -> dict:
    classification_result = classify_sample(features, model_path)
    severity = calculate_severity_score(classification_result["predicted_family"], features)

    return {
        **classification_result,
        "severity_score": severity
    }

if __name__ == "__main__":
    train_malware_classifier(os.path.join(BASE_DIR, "Malware_DataSet.csv"))
