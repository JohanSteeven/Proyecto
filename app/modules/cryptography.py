import subprocess
import re

def ejecutar_nmap(ip, puertos, scripts, timeout=90):
    cmd = ["nmap", "-p", puertos, "--script", ",".join(scripts), ip]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return {"estado": "ok", "output": output}
    except subprocess.CalledProcessError as e:
        return {"estado": "error", "output": e.output}
    except Exception as e:
        return {"estado": "error", "output": str(e)}

def extraer_protocolos_inseguros(lines):
    protocolos = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
    encontrados = [p for p in protocolos if any(p in line for line in lines)]
    return encontrados if encontrados else ["Ninguno detectado"]

def extraer_algoritmos_inseguros(lines):
    algoritmos = ["RC4", "MD5", "SHA1", "CBC", "3DES", "RC2", "DES"]
    encontrados = sorted({algo for algo in algoritmos for line in lines if algo in line})
    return encontrados



def extraer_suites_claves_bajas(lines, umbral=256):
    suites = []
    for line in lines:
        match = re.search(r"(\d{1,10}) bits", line)
        if match and int(match.group(1)) < umbral:
            suites.append(line.strip())
    return suites if suites else ["Ninguna detectada"]


def extraer_algoritmos_robustos(lines):
    patrones = ("AES-256", "AES-128", "RSA", "ECDHE", "ECDSA", "CHACHA20-POLY1305", "Ed25519")
    encontrados = sorted({pat for pat in patrones for line in lines if pat.lower() in line.lower()})
    return encontrados


def extraer_algoritmos_ssh(raw_output):
    lines = raw_output.splitlines()
    inseguros = [l.strip() for l in lines if re.search(r"(diffie-hellman-group1-sha1|ssh-rsa)", l, re.I)]
    fuertes = [l.strip() for l in lines if re.search(r"(ecdh-sha2-nistp|chacha20-poly1305@openssh.com|aes256-ctr)", l, re.I)]
    return inseguros, fuertes

def extraer_info_certificado(texto):
    patrones = {
        'Subject': r"Subject:\s*(.+)",
        'Issuer': r"Issuer:\s*(.+)",
        'Valid from': r"Not valid before:\s*(.+)",
        'Valid to': r"Not valid after:\s{2}(.+)",
        'Key size (bits)': r"Public Key bits:\s*(\d+)",
        'Signature Algorithm': r"Signature Algorithm:\s*(.+)"
    }
    info = {}
    for clave, patron in patrones.items():
        match = re.search(patron, texto)
        if match:
            valor = match.group(1).strip()
            if clave == 'Key size (bits)':
                valor = int(valor)
            info[clave] = valor
    return info

def evaluate(ip_o_dominio: str) -> dict:
    resultado = {}

    # Evaluación SSL/TLS
    r_ssl = ejecutar_nmap(ip_o_dominio, "443,465,993,995,8443", ["ssl-enum-ciphers"])
    if r_ssl["estado"] == "ok":
        lines = r_ssl["output"].splitlines()
        resultado["protocolos_inseguros"] = extraer_protocolos_inseguros(lines)
        resultado["algoritmos_inseguros"] = extraer_algoritmos_inseguros(lines)
        resultado["suites_claves_menor_256"] = extraer_suites_claves_bajas(lines)
        resultado["algoritmos_robustos"] = extraer_algoritmos_robustos(lines)
    else:
        resultado["error_ssl_ciphers"] = r_ssl["output"]

    # Evaluación SSH
    r_ssh = ejecutar_nmap(ip_o_dominio, "22", ["ssh2-enum-algos"])
    if r_ssh["estado"] == "ok":
        inseguros, fuertes = extraer_algoritmos_ssh(r_ssh["output"])
        resultado["ssh_algoritmos_inseguros"] = inseguros
        resultado["ssh_algoritmos_fuertes"] = fuertes
    else:
        resultado["error_ssh_algos"] = r_ssh["output"]

    # Evaluación Certificado SSL
    r_cert = ejecutar_nmap(ip_o_dominio, "443", ["ssl-cert"])
    if r_cert["estado"] == "ok":
        cert_info = extraer_info_certificado(r_cert["output"])
        resultado["ssl_cert"] = cert_info if cert_info else "Información no disponible"
    else:
        resultado["error_ssl_cert"] = r_cert["output"]

    return resultado
