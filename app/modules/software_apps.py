import subprocess
import re

def procesar_http_headers(raw_output: str) -> dict:
    resultado = {}
    current_port = None
    headers = {}

    lines = raw_output.splitlines()

    for line in lines:
        # Detectar puerto abierto
        puerto_match = re.match(r"(\d+)/tcp\s+open", line)
        if puerto_match:
            if current_port and headers:
                resultado[current_port] = headers
            current_port = puerto_match.group(1)
            headers = {}
            continue

        # Detectar líneas de header
        header_match = re.match(r"\|\s+([^:]+):\s*(.*)", line)
        if header_match and current_port:
            key = header_match.group(1).strip()
            value = header_match.group(2).strip()
            # Si valor está vacío, intentar tomar las siguientes líneas con indentación
            if value == "":
                value_lines = []
                idx = lines.index(line) + 1
                while idx < len(lines) and lines[idx].startswith("|   "):
                    value_lines.append(lines[idx][4:].strip())
                    idx += 1
                value = " ".join(value_lines).strip()
            headers[key] = value

    if current_port and headers:
        resultado[current_port] = headers

    return resultado

def procesar_http_enum(raw_output: str) -> dict:
    resultado = {}
    lines = raw_output.splitlines()

    rutas = []
    for line in lines:
        m = re.match(r"\|\s+(/[\w\-./]*)\s+(\[.*\])?", line)
        if m:
            ruta = m.group(1)
            rutas.append(ruta)

    resultado["rutas_detectadas"] = rutas
    return resultado

def evaluate(ip_o_dominio: str) -> dict:
    resultado = {}

    # Escaneo http-headers
    try:
        raw_headers = subprocess.check_output([
            "nmap", "-p", "80,443,8080", "--script", "http-headers", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["http_headers_raw"] = raw_headers
        resultado["http_headers"] = procesar_http_headers(raw_headers)
    except Exception as e:
        resultado["http_headers_error"] = str(e)

    # Escaneo http-enum
    try:
        raw_enum = subprocess.check_output([
            "nmap", "-p", "80,443,8080", "--script", "http-enum", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["http_enum_raw"] = raw_enum
        resultado["http_enum"] = procesar_http_enum(raw_enum)
    except Exception as e:
        resultado["http_enum_error"] = str(e)

    # Escaneo http-cookie-flags
    try:
        raw_cookies = subprocess.check_output([
            "nmap", "-p", "80,443", "--script", "http-cookie-flags", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["cookies_seguras_raw"] = raw_cookies
    except Exception as e:
        resultado["cookies_seguras_error"] = str(e)

    return resultado
