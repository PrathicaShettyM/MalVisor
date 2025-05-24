import pefile
import math
import os
import string
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# 1. calculate shannon entropy 
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(x.to_bytes(1, 'little')) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

# 2. extract human-readable strings
def extract_strings(file_path: str, min_length: int = 4) -> list:
    result = []
    with open(file_path, "rb") as f:
        content = f.read()
        current = ""
        for byte in content:
            if chr(byte) in string.printable:
                current += chr(byte)
                continue
            if len(current) >= min_length:
                result.append(current)
            current = ""
    return result

# 3. Light code disassembly
def disassemble_code(data: bytes, base_addr=0x1000):
    disassembled = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(data, base_addr):
        disassembled.append(f"{i.mnemonic} {i.op_str}")
    return disassembled

# 4. Extract PE features
def extract_pe_features(file_path: str) -> dict:
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as e:
        return {"error": str(e)}

    features = {
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "sections": [],
        "imports": [],
        "exports": [],
        "entropy": [],
        "strings": extract_strings(file_path),
    }

    for section in pe.sections:
        section_info = {
            "name": section.Name.decode(errors="ignore").strip(),
            "virtual_address": hex(section.VirtualAddress),
            "size_of_raw_data": section.SizeOfRawData,
            "entropy": calculate_entropy(section.get_data())
        }
        features["sections"].append(section_info)
        features["entropy"].append(section_info["entropy"])

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            features["imports"].append({
                "dll": entry.dll.decode(),
                "functions": [imp.name.decode() if imp.name else "ordinal" for imp in entry.imports]
            })

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            features["exports"].append(symbol.name.decode() if symbol.name else "ordinal")

    try:
        code_section = pe.sections[0]
        code = code_section.get_data()[:200]
        features["disassembly"] = disassemble_code(code)
    except Exception as e:
        features["disassembly"] = f"Failed: {str(e)}"

    return features

# 5. Convert raw features into ML model features with severity scoring
def convert_to_model_features(raw_features: dict) -> dict:
    if "error" in raw_features:
        return {}

    num_imports = sum(len(dll["functions"]) for dll in raw_features.get("imports", []))
    entropy_values = raw_features.get("entropy", [])
    strings = raw_features.get("strings", [])
    section_count = len(raw_features.get("sections", []))
    filesize = sum(sec.get("size_of_raw_data", 0) for sec in raw_features.get("sections", []))

    suspicious_apis = ["CreateRemoteThread", "VirtualAlloc", "LoadLibrary"]
    suspicious_string_count = sum(
        any(api in s for api in suspicious_apis)
        for s in strings
    )

    # Severity scoring heuristic
    family_weight = 2.0  # Placeholder: could be mapped from external model/dataset
    entropy_score = max(entropy_values) if entropy_values else 0
    obfuscation_weight = entropy_score / 8  # Normalized to [0, 1]
    api_suspicion_weight = suspicious_string_count / 10  # Arbitrary scale

    severity_score = min(10.0, family_weight + obfuscation_weight + api_suspicion_weight)

    return {
        "num_imports": num_imports,
        "entropy_mean": sum(entropy_values)/len(entropy_values) if entropy_values else 0,
        "entropy_max": entropy_score,
        "entropy_min": min(entropy_values) if entropy_values else 0,
        "section_count": section_count,
        "filesize": filesize,
        "string_count": len(strings),
        "suspicious_string_count": suspicious_string_count,
        "severity_score": round(severity_score, 2),
    }
