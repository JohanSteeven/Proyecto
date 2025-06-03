import subprocess
import re

def procesar_http_headers(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para extraer encabezados HTTP por puerto.

    Args:
        raw_output (str): Salida de nmap del script http-headers.

    Returns:
        dict: Diccionario con puertos como claves y encabezados HTTP como subdiccionarios.
    """
    resultado = {}
    current_port = None
    headers = {}

    lines = raw_output.splitlines()

    for line in lines:
        puerto_match = re.match(r"(\d+)/tcp\s+open", line)
        if puerto_match:
            if current_port and headers:
                resultado[current_port] = headers
            current_port = puerto_match.group(1)
            headers = {}
            continue

        header_match = re.match(r"\|\s+([^:]+):\s*(.*?)$", line)
        if header_match and current_port:
            key = header_match.group(1).strip()
            value = header_match.group(2).strip()
            if value:
                headers[key] = value


    if current_port and headers:
        resultado[current_port] = headers

    return resultado

def procesar_http_enum(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para extraer rutas HTTP detectadas.

    Args:
        raw_output (str): Salida de nmap del script http-enum.

    Returns:
        dict: Diccionario con la lista de rutas detectadas.
    """
    rutas = []
    for line in raw_output.splitlines():
        m = re.match(r"\|\s+(/[\w\-./]*)", line)
        if m:
            ruta = m.group(1)
            if ruta not in rutas:
                rutas.append(ruta)
    return {"rutas_detectadas": rutas}

def procesar_cookies(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para identificar cookies inseguras (sin Secure o HttpOnly).

    Args:
        raw_output (str): Salida de nmap del script http-cookie-flags.

    Returns:
        dict: Diccionario con la lista de cookies inseguras detectadas.
    """
    cookies_inseguros = []
    for line in raw_output.splitlines():
        if "Set-Cookie" in line:
            # Detecta si faltan flags secure o httponly (simplificado)
            lower_line = line.lower()
            if "secure" not in lower_line or "httponly" not in lower_line:
                cookies_inseguros.append(line.strip())
    return {"cookies_inseguros": cookies_inseguros}

def evaluate(ip_o_dominio: str) -> dict:
    """
    Evalúa la configuración de aplicaciones web y encabezados HTTP de un host remoto usando Nmap.

    Realiza las siguientes comprobaciones:
    - Encabezados HTTP expuestos en puertos comunes.
    - Rutas HTTP accesibles detectadas.
    - Cookies inseguras (sin Secure o HttpOnly).

    Args:
        ip_o_dominio (str): IP o dominio a evaluar.

    Returns:
        dict: Resultados de la evaluación de aplicaciones web y encabezados HTTP.
    """
    resultado = {}

    try:
        raw_headers = subprocess.check_output([
            "nmap", "-p", "80,443,8080", "--script", "http-headers", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["http_headers"] = procesar_http_headers(raw_headers)
    except Exception as e:
        resultado["http_headers_error"] = str(e)

    try:
        raw_enum = subprocess.check_output([
            "nmap", "-p", "80,443,8080", "--script", "http-enum", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["http_enum"] = procesar_http_enum(raw_enum)
    except Exception as e:
        resultado["http_enum_error"] = str(e)

    try:
        raw_cookies = subprocess.check_output([
            "nmap", "-p", "80,443", "--script", "http-cookie-flags", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["cookies_seguras"] = procesar_cookies(raw_cookies)
    except Exception as e:
        resultado["cookies_seguras_error"] = str(e)

    return resultado
