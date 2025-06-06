# auth.py
import subprocess
import re
# Removed httpx as buscar_vulnerabilidades_nvd is no longer used

def ejecutar_nmap(ip, puertos, scripts, timeout=180): # Increased timeout for broader scans
    """
    Ejecuta un comando nmap con los puertos y scripts especificados sobre la IP/dominio dado.
    """
    # Added -sV for service version detection, crucial for some auth scripts
    cmd = ["nmap", "-Pn", "--defeat-rst-ratelimit", "-sV", "-p", puertos, "--script", ",".join(scripts), ip]
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
    """
    puertos = {}
    lines = raw_output.splitlines()
    # Se intentará extraer producto y versión si se encuentran (simplificado)
    for line in lines:
        # Improved regex to capture more details for product and version
        m = re.match(r"(\d+)/tcp\s+(\w+)\s+([^\s]+)(?:\s+([\w\s\.\-]+))?(?:\s+([\w\s\.\-]+))?", line)
        if m:
            puerto, estado, servicio = m.group(1), m.group(2), m.group(3).lower()
            producto = m.group(4).strip().lower() if m.group(4) else ""
            version = m.group(5).strip().lower() if m.group(5) else ""
            puertos[puerto] = {
                "estado": estado,
                "servicio": servicio,
                "producto": producto,
                "version": version
            }
    return puertos

def parse_ssh_auth_methods(raw_output):
    """
    Extrae métodos de autenticación SSH de la salida Nmap, with more detail.
    """
    methods = []
    # More specific regex to capture method and status if available
    match = re.search(r"ssh-auth-methods:\n((\s*\|\s+Authentication methods:\s+.*?\n)+)", raw_output, re.MULTILINE | re.DOTALL)
    if match:
        block = match.group(1)
        # Regex to capture individual methods and their status/description
        found_methods = re.findall(r"\|\s+Authentication methods:\s+(.*?)\s+\((.*?)\)", block)
        if not found_methods: # Fallback for simpler output
             found_methods = re.findall(r"\|\s+(.*)", block)

        for m in found_methods:
            if isinstance(m, tuple):
                methods.append(f"{m[0].strip()} ({m[1].strip()})")
            else:
                methods.append(m.strip())
    return methods

def evaluate(ip_o_dominio: str) -> dict:
    """
    Evalúa servicios de autenticación y login inseguros en una IP o dominio remoto usando nmap.
    """
    resultado = {}

    # Expanded ports and scripts for more comprehensive auth detection
    # Added ftp-anon, smtp-enum-users, ldap-rootdse, telnet-ntlm-info
    r = ejecutar_nmap(ip_o_dominio,
                      "21,22,23,80,110,143,389,636,3306,5432,5985,5986",
                      ["auth", "ftp-anon", "smtp-enum-users", "ldap-rootdse", "telnet-ntlm-info"],
                      timeout=180)
    if r["estado"] == "ok":
        puertos = parse_nmap_ports(r["output"])
        ssh_methods = parse_ssh_auth_methods(r["output"]) if "22" in puertos and puertos["22"]["estado"] == "open" else []
        resultado["puertos"] = puertos
        if ssh_methods:
            resultado["ssh_auth_methods"] = ssh_methods

        # Placeholder for default credentials or weak config checks
        # This would require more advanced logic or specific Nmap script outputs.
        # For now, relying on 'auth' script output and parsed service info.
        insecure_auth_findings = []
        if "21" in puertos and puertos["21"]["estado"] == "open":
            if "anonymous" in r["output"].lower():
                insecure_auth_findings.append("FTP permite login anónimo")
        if "23" in puertos and puertos["23"]["estado"] == "open":
            insecure_auth_findings.append("Telnet (sin cifrado) detectado, puede exponer credenciales")
        if "389" in puertos and puertos["389"]["estado"] == "open":
            if "ldap-rootdse" in r["output"]: # Basic check for ldap-rootdse script output
                insecure_auth_findings.append("LDAP abierto, puede exponer información de directorio")
        if "smtp-enum-users" in r["output"].lower():
            insecure_auth_findings.append("SMTP permite enumeración de usuarios")

        if insecure_auth_findings:
            resultado["insecure_authentication_findings"] = insecure_auth_findings

    else:
        resultado["error"] = r["output"]

    return resultado