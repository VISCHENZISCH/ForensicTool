"""Extraction de Strings (ASCII/Unicode) et catégorisation (IOCs)."""

import re
import base64

def extract_strings_with_offsets(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    """Extrait les chaînes ASCII et UTF-16 LE/BE avec leurs offsets."""
    strings = []
    
    # ASCII
    ascii_pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    for match in re.finditer(ascii_pattern, data):
        strings.append((match.start(), match.group().decode('ascii')))
        
    # UTF-16 LE
    utf16le_pattern = rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}"
    for match in re.finditer(utf16le_pattern, data):
        try:
            strings.append((match.start(), match.group().decode('utf-16-le')))
        except: pass

    # UTF-16 BE
    utf16be_pattern = rb"(?:\x00[\x20-\x7E]){" + str(min_length).encode() + rb",}"
    for match in re.finditer(utf16be_pattern, data):
        try:
            strings.append((match.start(), match.group().decode('utf-16-be')))
        except: pass

    # Sort by offset
    strings.sort(key=lambda x: x[0])
    return strings

def categorize_strings(strings_with_offsets: list[tuple[int, str]]) -> dict[str, list[dict]]:
    """Catégorise les chaînes de caractères extraites."""
    categories = {
        "urls": [],
        "ips": [],
        "emails": [],
        "paths": [],
        "registry": [],
        "crypto": [],
        "base64": [],
        "shell": []
    }
    
    url_pat = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    ip_pat = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    email_pat = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    path_win_pat = re.compile(r'[a-zA-Z]:\\[^:\*\?"<>\|]+')
    path_lin_pat = re.compile(r'(?:/[a-zA-Z0-9_.-]+)+')
    reg_pat = re.compile(r'(?i)(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_.\\]+')
    btc_pat = re.compile(r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b')
    b64_pat = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    shell_pat = re.compile(r'(?i)(?:powershell|cmd\.exe|/bin/sh|/bin/bash|wget\s|curl\s|nc\s+-e|Invoke-Expression|IEX)')

    for offset, s in strings_with_offsets:
        item = {"offset": hex(offset), "value": s}
        
        if url_pat.search(s): categories["urls"].append(item)
        if ip_pat.search(s): categories["ips"].append(item)
        if email_pat.search(s): categories["emails"].append(item)
        if path_win_pat.search(s) or path_lin_pat.search(s): categories["paths"].append(item)
        if reg_pat.search(s): categories["registry"].append(item)
        if btc_pat.search(s): categories["crypto"].append(item)
        if shell_pat.search(s): categories["shell"].append(item)
        
        # Base64 decoding attempt
        for b64 in b64_pat.findall(s):
            try:
                decoded = base64.b64decode(b64).decode('utf-8', 'ignore')
                if len(decoded) > 5 and re.match(r'^[\x20-\x7E\r\n\t]+$', decoded):
                    categories["base64"].append({"offset": hex(offset), "value": b64, "decoded": decoded})
            except: pass

    # Remove duplicates within categories
    for cat in categories:
        seen = set()
        unique = []
        for d in categories[cat]:
            if d["value"] not in seen:
                seen.add(d["value"])
                unique.append(d)
        categories[cat] = unique

    return categories
