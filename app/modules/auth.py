import subprocess
import re
import httpx

def ejecutar_nmap(ip, puertos, scripts, timeout=90):
    """
    Ejecuta un comando nmap con los puertos y scripts especificados sobre la IP/dominio dado.
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
    """
    puertos = {}
    lines = raw_output.splitlines()
    # Se intentará extraer producto y versión si se encuentran (simplificado)
    for line in lines:
        m = re.match(r"(\d+)/tcp\s+(\w+)\s+(\S+)(?:\s+([\w\.\-]+))?(?:\s+([\w\.\-]+))?", line)
        if m:
            puerto, estado, servicio = m.group(1), m.group(2), m.group(3).lower()
            producto = m.group(4).lower() if m.group(4) else ""
            version = m.group(5).lower() if m.group(5) else ""
            puertos[puerto] = {
                "estado": estado,
                "servicio": servicio,
                "producto": producto,
                "version": version
            }
    return puertos

def buscar_vulnerabilidades_nvd(producto, version, max_results=3):
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    query = f"{producto} {version}".strip()
    if not query:
        return []
    params = {
        "keyword": query,
        "resultsPerPage": max_results
    }
    try:
        response = httpx.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("result", {}).get("CVE_Items", [])
    except Exception as e:
        return {"error": str(e)}

def parse_ssh_auth_methods(raw_output):
    """
    Extrae métodos de autenticación SSH de la salida Nmap.
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
    Además busca vulnerabilidades CVE asociadas a los productos y versiones detectados.
    """
    resultado = {}

    r = ejecutar_nmap(ip_o_dominio, "21,22,23,80,110,143,389,636,3306,5432", ["auth"], timeout=90)
    if r["estado"] == "ok":
        puertos = parse_nmap_ports(r["output"])
        ssh_methods = parse_ssh_auth_methods(r["output"]) if "22" in puertos and puertos["22"]["estado"] == "open" else []
        resultado["puertos"] = puertos
        if ssh_methods:
            resultado["ssh_auth_methods"] = ssh_methods

        # Buscar CVEs para cada servicio detectado que tenga producto y versión
        vulnerabilidades = []
        for puerto, info in puertos.items():
            producto = info.get("producto", "")
            version = info.get("version", "")
            if producto and version:
                cves = buscar_vulnerabilidades_nvd(producto, version)
                if isinstance(cves, list) and cves:
                    vulnerabilidades.append({
                        "puerto": puerto,
                        "servicio": info.get("servicio", ""),
                        "producto": producto,
                        "version": version,
                        "vulnerabilidades": [{
                            "id": cve["cve"]["CVE_data_meta"]["ID"],
                            "descripcion": cve["cve"]["description"]["description_data"][0]["value"]
                        } for cve in cves]
                    })

        resultado["vulnerabilidades_detectadas"] = vulnerabilidades

    else:
        resultado["error"] = r["output"]

    return resultado
