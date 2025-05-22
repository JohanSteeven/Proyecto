import subprocess
import re

def ejecutar_nmap(ip, puertos, scripts, timeout=60):
    """
    Ejecuta un comando nmap con los puertos y scripts especificados sobre la IP/dominio dado.

    Args:
        ip (str): IP o dominio a escanear.
        puertos (str): Puertos a escanear, separados por coma.
        scripts (list): Lista de scripts nmap a ejecutar.
        timeout (int): Tiempo máximo de espera en segundos.

    Returns:
        dict: Diccionario con estado ('ok' o 'error') y la salida del comando.
    """
    cmd = ["nmap", "-p", puertos, "--script", ",".join(scripts), ip]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return {"estado": "ok", "output": output}
    except subprocess.CalledProcessError as e:
        return {"estado": "error", "output": e.output}
    except Exception as e:
        return {"estado": "error", "output": str(e)}

def parse_ssh_auth(raw_output: str) -> dict:
    """
    Extrae métodos de autenticación soportados en SSH y aceptación de claves públicas desde la salida de nmap.

    Args:
        raw_output (str): Salida de nmap.

    Returns:
        dict: Métodos de autenticación SSH y aceptación de claves públicas.
    """
    result = {}
    # Buscar métodos de autenticación SSH
    match = re.search(r"ssh-auth-methods:\n((\s*\|\s+.*\n)+)", raw_output, re.MULTILINE)
    if match:
        methods_block = match.group(1)
        methods = re.findall(r"\|\s+(.*)", methods_block)
        methods = [m.strip(" -") for m in methods]
        result["ssh_auth_methods"] = methods
    else:
        result["ssh_auth_methods"] = []

    # Buscar aceptación de claves públicas
    pubkey_match = re.search(r"ssh-publickey-acceptance:\n((\s*\|\s+.*\n)+)", raw_output, re.MULTILINE)
    if pubkey_match:
        pubkey_block = pubkey_match.group(1)
        accepted = re.findall(r"\|\s+(.*)", pubkey_block)
        result["ssh_publickey_acceptance"] = [a.strip() for a in accepted]
    else:
        result["ssh_publickey_acceptance"] = []

    return result

def parse_http_auth(raw_output: str) -> dict:
    """
    Detecta tipos de autenticación HTTP básicos presentes en la salida de nmap.

    Args:
        raw_output (str): Salida de nmap.

    Returns:
        dict: Tipos de autenticación HTTP detectados.
    """
    result = {}
    auth_types = []
    for line in raw_output.splitlines():
        if re.search(r"HTTP Authentication", line, re.I):
            auth_types.append(line.strip())
    result["http_authentication"] = auth_types if auth_types else ["No se detectó autenticación HTTP"]
    return result

def parse_login_insecure(raw_output: str) -> dict:
    """
    Extrae puertos abiertos para servicios de login inseguros (FTP anónimo, Telnet) de la salida de nmap.

    Args:
        raw_output (str): Salida de nmap.

    Returns:
        dict: Lista de puertos inseguros detectados.
    """
    puertos_abiertos = []
    for line in raw_output.splitlines():
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            puertos_abiertos.append({"puerto": m.group(1), "servicio": m.group(2)})
    return {"puertos_abiertos": puertos_abiertos}

def evaluate(ip_o_dominio: str) -> dict:
    """
    Evalúa servicios de autenticación y login inseguros en una IP o dominio remoto usando nmap.

    Args:
        ip_o_dominio (str): IP o dominio a evaluar.

    Returns:
        dict: Resultados de la evaluación de autenticación y login.
    """
    resultado = {}

    # Evaluación de servicios de autenticación comunes
    r = ejecutar_nmap(ip_o_dominio, "21,22,23,80,110,143,389,636,3306,5432", ["auth"], timeout=90)
    if r["estado"] == "ok":
        parsed_ssh = parse_ssh_auth(r["output"])
        parsed_http = parse_http_auth(r["output"])
        resultado["servicios_autenticacion"] = {
            "ssh": parsed_ssh,
            "http": parsed_http
        }
    else:
        resultado["servicios_autenticacion_error"] = r["output"]

    # Evaluación de login no cifrado (FTP anónimo, Telnet)
    r = ejecutar_nmap(ip_o_dominio, "21,23", ["ftp-anon", "telnet-encryption"], timeout=90)
    if r["estado"] == "ok":
        resultado["servicios_login_inseguros"] = parse_login_insecure(r["output"])
    else:
        resultado["servicios_login_inseguros_error"] = r["output"]

    # Evaluación de autenticación HTTP básica y por formulario
    r = ejecutar_nmap(ip_o_dominio, "80,443", ["http-auth", "http-form-auth"], timeout=90)
    if r["estado"] == "ok":
        # Se puede parsear más, pero se retorna el texto completo
        resultado["http_autenticacion"] = r["output"]
    else:
        if "did not match a category" in r["output"]:
            resultado["http_autenticacion_error"] = "Script Nmap no encontrado o no soportado en esta versión."
        else:
            resultado["http_autenticacion_error"] = r["output"]

    return resultado
