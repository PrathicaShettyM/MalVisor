from analysis.model import calculate_severity_score
from analysis.feature_extractor import extract_pe_features

def compute_severity(predicted_family, raw_features) -> float:
    entropy_avg = (
        sum(raw_features["entropy"]) / len(raw_features["entropy"])
        if raw_features.get("entropy") else 0
    )
    return calculate_severity_score(predicted_family, entropy_avg, raw_features.get("strings", []))
