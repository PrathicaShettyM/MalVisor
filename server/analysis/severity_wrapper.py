from .model import calculate_severity_score
from .feature_extractor import extract_pe_features

def compute_severity(predicted_family, raw_features) -> float:
    entropy_avg_raw = (
        sum(raw_features["entropy"]) / len(raw_features["entropy"])
        if raw_features.get("entropy") else 0
    )
    entropy_avg_adjusted = max(0, entropy_avg_raw - 3.0)
    
    return calculate_severity_score(
        predicted_family,
        {
            "entropy_max": entropy_avg_adjusted,
            "suspicious_string_count": len([
                s for s in raw_features.get("strings", [])
                if any(api in s for api in ["CreateRemoteThread", "VirtualAlloc", "LoadLibrary"])
            ])
        }
    )
