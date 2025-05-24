import pefile
import math
import os
import string
import subprocess
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# feature extraction for malware analysis and scoring
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
    
    # 4.1 Sections and entropy
    for section in pe.sections:
        section_info = {
            "name": section.Name.decode(errors="ignore").strip(),
            "virtual_address": hex(section.VirtualAddress),
            "size_of_raw_data": section.SizeOfRawData,
            "entropy": calculate_entropy(section.get_data())
        }
        features["sections"].append(section_info)
        features["entropy"].append(section_info["entropy"])

    # 4.2 Imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            features["imports"].append({
                "dll": entry.dll.decode(),
                "functions": [imp.name.decode() if imp.name else "ordinal" for imp in entry.imports]
            })

    # 4.3 Exports
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            features["exports"].append(symbol.name.decode() if symbol.name else "ordinal")

    # 4.4 Disassembly of first 200 bytes of code section
    try:
        code_section = pe.sections[0]
        code = code_section.get_data()[:200]
        features["disassembly"] = disassemble_code(code)
    except Exception as e:
        features["disassembly"] = f"Failed: {str(e)}"

    return features

