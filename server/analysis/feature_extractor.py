import pefile
import math
import os
import string
import hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# ✅ Proper entropy calculation
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(x.to_bytes(1, 'little')) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

# ✅ Extract printable strings from binary
def extract_strings(file_path: str, min_length: int = 4) -> list:
    result = []
    with open(file_path, "rb") as f:
        content = f.read()
        current = ""
        for byte in content:
            char = chr(byte)
            if char in string.printable:
                current += char
            else:
                if len(current) >= min_length:
                    result.append(current)
                current = ""
    return result

# ✅ Disassemble using Capstone (optional but useful)
def disassemble_code(data: bytes, base_addr=0x1000):
    disassembled = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(data, base_addr):
        disassembled.append(f"{i.mnemonic} {i.op_str}")
    return disassembled

# ✅ Hash calculator
def calculate_file_hashes(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        content = f.read()
        return {
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest()
        }

# ✅ PE extractor
def extract_pe_features(file_path: str) -> dict:
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {"error": f"PE parsing failed: {str(e)}"}

    entropy_by_section = {}
    section_names = []
    for section in pe.sections:
        try:
            name = section.Name.decode(errors="ignore").strip()
            entropy = round(calculate_entropy(section.get_data()), 4)
            section_names.append(name)
            entropy_by_section[name] = entropy
        except Exception:
            continue

    imported_libraries = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll:
                try:
                    imported_libraries.append(entry.dll.decode(errors="ignore"))
                except Exception:
                    continue

    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
    except Exception:
        timestamp = "N/A"

    try:
        code_section = pe.sections[0]
        code = code_section.get_data()[:200]
        disassembly = disassemble_code(code)
    except Exception as e:
        disassembly = [f"Disassembly failed: {str(e)}"]

    return {
        "file_hashes": calculate_file_hashes(file_path),
        "entropy": entropy_by_section,
        "strings": extract_strings(file_path),
        "pe_features": {
            "imports": imported_libraries,
            "sections": section_names,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "timestamp": timestamp,
            "disassembly": disassembly
        }
    }

# ✅ Model feature preparation (Fixed logic)
def convert_to_model_features(raw_features: dict, file_path: str) -> dict:
    if "error" in raw_features:
        return {}

    pe_data = raw_features.get("pe_features", {})
    entropy_values = list(raw_features.get("entropy", {}).values())
    strings = raw_features.get("strings", [])

    # ✅ Filter out non-suspicious common strings
    benign_substrings = [
        "This program cannot be run in DOS mode",
        "Rich", ".text", ".data", ".rdata", ".rsrc", ".reloc"
    ]

    suspicious_apis = ["CreateRemoteThread", "VirtualAlloc", "LoadLibrary"]
    suspicious_string_count = 0

    for s in strings:
        if any(api in s for api in suspicious_apis) and not any(b in s for b in benign_substrings):
            suspicious_string_count += 1

    num_imports = len(pe_data.get("imports", []))
    section_count = len(pe_data.get("sections", []))

    # ✅ Use actual file size (corrected)
    try:
        filesize = os.path.getsize(file_path)
    except:
        filesize = 0

    return {
        "num_imports": num_imports,
        "entropy_mean": sum(entropy_values) / len(entropy_values) if entropy_values else 0,
        "entropy_max": max(entropy_values) if entropy_values else 0,
        "entropy_min": min(entropy_values) if entropy_values else 0,
        "section_count": section_count,
        "filesize": filesize,
        "string_count": len(strings),
        "suspicious_string_count": suspicious_string_count
    }
