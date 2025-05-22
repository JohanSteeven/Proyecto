import subprocess
import re

def ejecutar_nmap(ip, puertos, scripts, timeout=90):
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
    cmd = ["nmap", "-Pn", "--defeat-rst-ratelimit", "-p", puertos, "--script", ",".join(scripts), ip]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return {"estado": "ok", "output": output}
    except subprocess.CalledProcessError as e:
        return {"estado": "error", "output": e.output}
    except Exception as e:
        return {"estado": "error", "output": str(e)}

def parse_nmap_ports(raw_output):
    """
    Extrae el estado de puertos (open, filtered, closed) y servicios desde la salida de Nmap.

    Args:
        raw_output (str): Salida de nmap.

    Returns:
        dict: Diccionario con puertos como claves y su estado y servicio como valores.
    """
    puertos = {}
    lines = raw_output.splitlines()
    for line in lines:
        m = re.match(r"(\d+)/tcp\s+(\w+)\s+(\S+)", line)
        if m:
            puerto, estado, servicio = m.groups()
            puertos[puerto] = {"estado": estado, "servicio": servicio}
    return puertos

def parse_ssh_auth_methods(raw_output):
    """
    Extrae métodos de autenticación SSH de la salida Nmap.

    Args:
        raw_output (str): Salida de nmap.

    Returns:
        list: Lista de métodos de autenticación SSH detectados.
    """
    methods = []
    match = re.search(r"ssh-auth-methods:\n((\s*\|\s+.*\n)+)", raw_output, re.MULTILINE)
    if match:
        block = match.group(1)
        methods = re.findall(r"\|\s+(.*)", block)
        methods = [m.strip() for m in methods]
    return methods

def evaluate(ip_o_dominio: str) -> dict:
    """
    Evalúa servicios de autenticación y login inseguros en una IP o dominio remoto usando nmap.

    Realiza las siguientes comprobaciones:
    - Escaneo de puertos comunes para servicios de autenticación.
    - Detección de métodos de autenticación SSH si el puerto 22 está abierto.

    Args:
        ip_o_dominio (str): IP o dominio a evaluar.

    Returns:
        dict: Resultados de la evaluación de autenticación y login.
    """
    resultado = {}

    r = ejecutar_nmap(ip_o_dominio, "21,22,23,80,110,143,389,636,3306,5432", ["auth"], timeout=90)
    if r["estado"] == "ok":
        puertos = parse_nmap_ports(r["output"])
        ssh_methods = parse_ssh_auth_methods(r["output"]) if "22" in puertos and puertos["22"]["estado"] == "open" else []
        resultado["puertos"] = puertos
        if ssh_methods:
            resultado["ssh_auth_methods"] = ssh_methods
    else:
        resultado["error"] = r["output"]

    # Otros escaneos (login inseguros, http auth) pueden tener parseo similar

    return resultado
