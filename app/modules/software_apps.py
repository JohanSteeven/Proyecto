# software_apps.py
import subprocess
import re

def ejecutar_nmap_script(ip, puertos, script_name, timeout=120): # Helper to reduce repetition
    """
    Ejecuta un script de nmap específico y retorna su salida.
    """
    cmd = ["nmap", "-p", puertos, "--script", script_name, ip]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return {"estado": "ok", "output": output}
    except subprocess.CalledProcessError as e:
        return {"estado": "error", "output": e.output}
    except Exception as e:
        return {"estado": "error", "output": str(e)}

def procesar_http_headers(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para extraer encabezados HTTP por puerto y analiza su seguridad.
    """
    resultado = {}
    current_port = None
    headers = {}
    security_header_issues = []

    lines = raw_output.splitlines()

    for line in lines:
        puerto_match = re.match(r"(\d+)/tcp\s+open", line)
        if puerto_match:
            if current_port and headers:
                resultado[current_port] = {"headers": headers, "security_issues": security_header_issues}
            current_port = puerto_match.group(1)
            headers = {}
            security_header_issues = []
            continue

        header_match = re.match(r"\|\s+([^:]+):\s*(.*?)$", line)
        if header_match and current_port:
            key = header_match.group(1).strip()
            value = header_match.group(2).strip()
            if value:
                headers[key] = value.format() # Capture header for general info

                # Analyze specific security headers
                lower_key = key.lower()
                if lower_key == "server":
                    if "iis" in value.lower() or "apache" in value.lower() or "nginx" in value.lower():
                        security_header_issues.append(f"Encabezado 'Server' expone información de la versión del servidor: {value}")
                if lower_key == "x-powered-by":
                    security_header_issues.append(f"Encabezado 'X-Powered-By' expone tecnología backend: {value}")
                if lower_key == "x-frame-options":
                    if "deny" not in value.lower() and "sameorigin" not in value.lower():
                        security_header_issues.append(f"Encabezado 'X-Frame-Options' no configurado para prevenir Clickjacking: {value}")
                if lower_key == "x-content-type-options":
                    if "nosniff" not in value.lower():
                        security_header_issues.append(f"Encabezado 'X-Content-Type-Options' no configurado con 'nosniff'")
                if lower_key == "content-security-policy":
                    if not value.strip():
                        security_header_issues.append("Encabezado 'Content-Security-Policy' vacío o débil")
                if lower_key == "strict-transport-security":
                    if "max-age=0" in value.lower() or not value.strip():
                        security_header_issues.append("Encabezado 'Strict-Transport-Security' (HSTS) ausente o con 'max-age=0'")
                if lower_key == "set-cookie":
                    lower_value = value.lower()
                    if "secure" not in lower_value:
                        security_header_issues.append(f"Cookie sin flag 'Secure': {value}")
                    if "httponly" not in lower_value:
                        security_header_issues.append(f"Cookie sin flag 'HttpOnly': {value}")
                    if "samesite" not in lower_value:
                        security_header_issues.append(f"Cookie sin flag 'SameSite': {value}")


    if current_port and headers:
        resultado[current_port] = {"headers": headers, "security_issues": security_header_issues}

    return resultado

def procesar_http_enum(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para extraer rutas HTTP detectadas y sus estados.
    """
    rutas = []
    # Regex to capture path and potentially status code if available from script
    for line in raw_output.splitlines():
        # Match lines like "| /admin/            (Status: 200)" or "| /robots.txt"
        m = re.match(r"\|\s+(/[\w\-. /]*(?:\s+\(Status:\s*\d+\))?)", line)
        if m:
            ruta_info = m.group(1).strip()
            rutas.append(ruta_info)
    return {"rutas_detectadas": rutas}

def procesar_cookies(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para identificar cookies inseguras (sin Secure, HttpOnly, o SameSite).
    """
    cookies_inseguros = []
    for line in raw_output.splitlines():
        if "Set-Cookie" in line:
            lower_line = line.lower()
            issues = []
            if "secure" not in lower_line:
                issues.append("Secure")
            if "httponly" not in lower_line:
                issues.append("HttpOnly")
            if "samesite" not in lower_line: # Check for SameSite flag
                issues.append("SameSite")

            if issues:
                cookies_inseguros.append(f"{line.strip()} (Faltan flags: {', '.join(issues)})")
    return {"cookies_inseguros": cookies_inseguros}

def procesar_http_methods(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para identificar métodos HTTP potencialmente inseguros.
    """
    methods_info = {}
    current_port = None
    for line in raw_output.splitlines():
        port_match = re.match(r"(\d+)/tcp\s+open", line)
        if port_match:
            current_port = port_match.group(1)
            methods_info[current_port] = []
            continue

        method_match = re.search(r"\|\s+Methods:\s+([A-Z,\s]+)", line)
        if method_match and current_port:
            methods = [m.strip() for m in method_match.group(1).split(',')]
            insecure_methods = [m for m in methods if m in ["PUT", "DELETE", "TRACE", "CONNECT"]] # Common insecure methods
            if insecure_methods:
                methods_info[current_port].append(f"Métodos HTTP potencialmente inseguros detectados: {', '.join(insecure_methods)}")
            else:
                methods_info[current_port].append("No se detectaron métodos HTTP notablemente inseguros")
    return methods_info

def procesar_http_title(raw_output: str) -> dict:
    """
    Procesa la salida de nmap para extraer títulos de páginas web.
    """
    titles = {}
    for line in raw_output.splitlines():
        match = re.match(r"(\d+)/tcp\s+open\s+http\s+.*?\|--title:\s+(.*)", line)
        if match:
            port = match.group(1)
            title = match.group(2).strip()
            titles[port] = title
    return titles

def evaluate(ip_o_dominio: str) -> dict:
    """
    Evalúa la configuración de aplicaciones web y encabezados HTTP de un host remoto usando Nmap.
    """
    resultado = {}
    ports_to_scan = "80,443,8080,8443" # Expanded common web ports

    # http-headers
    r_headers = ejecutar_nmap_script(ip_o_dominio, ports_to_scan, "http-headers")
    if r_headers["estado"] == "ok":
        resultado["http_headers_analysis"] = procesar_http_headers(r_headers["output"])
    else:
        resultado["http_headers_error"] = r_headers["output"]

    # http-enum
    r_enum = ejecutar_nmap_script(ip_o_dominio, ports_to_scan, "http-enum")
    if r_enum["estado"] == "ok":
        resultado["http_enum"] = procesar_http_enum(r_enum["output"])
    else:
        resultado["http_enum_error"] = r_enum["output"]

    # http-cookie-flags (focused on insecure cookies)
    r_cookies = ejecutar_nmap_script(ip_o_dominio, ports_to_scan, "http-cookie-flags")
    if r_cookies["estado"] == "ok":
        resultado["cookies_seguras_analysis"] = procesar_cookies(r_cookies["output"])
    else:
        resultado["cookies_seguras_error"] = r_cookies["output"]

    # http-methods
    r_methods = ejecutar_nmap_script(ip_o_dominio, ports_to_scan, "http-methods")
    if r_methods["estado"] == "ok":
        resultado["http_methods_analysis"] = procesar_http_methods(r_methods["output"])
    else:
        resultado["http_methods_error"] = r_methods["output"]

    # http-title
    r_title = ejecutar_nmap_script(ip_o_dominio, ports_to_scan, "http-title")
    if r_title["estado"] == "ok":
        resultado["http_titles"] = procesar_http_title(r_title["output"])
    else:
        resultado["http_titles_error"] = r_title["output"]

    # Placeholder for other advanced checks
    # e.g., http-waf-detect, http-domino-enum-users, http-trace, http-put
    # These would require dedicated parsing functions similar to the ones above.
    # r_waf = ejecutar_nmap_script(ip_o_dominio, ports_to_scan, "http-waf-detect")
    # if r_waf["estado"] == "ok":
    #     resultado["waf_detection"] = r_waf["output"] # Simple inclusion for now

    return resultado