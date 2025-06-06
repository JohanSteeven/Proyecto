# cryptography.py
import subprocess
import re

def ejecutar_nmap(ip, puertos, scripts, timeout=180): # Increased timeout
    cmd = ["nmap", "-sV", "-p", puertos, "--script", ",".join(scripts), ip] # Added -sV
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return {"estado": "ok", "output": output}
    except subprocess.CalledProcessError as e:
        return {"estado": "error", "output": e.output}
    except Exception as e:
        return {"estado": "error", "output": str(e)}

def extraer_protocolos_inseguros(lines):
    protocolos_inseguros = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"] # Explicitly added TLSv1.0, TLSv1.1 as insecure
    encontrados = []
    for p in protocolos_inseguros:
        # Look for explicit mention of insecure protocols being enabled
        if any(f"{p} enabled" in line or f"{p} supported" in line for line in lines):
            encontrados.append(p)
    return encontrados if encontrados else ["Ninguno detectado"]

def extraer_algoritmos_inseguros(lines):
    # Expanded list of known weak algorithms
    algoritmos = ["RC4", "MD5", "SHA1", "CBC", "3DES", "DES", "RC2", "EXPORT", "NULL", "ADH"]
    encontrados = sorted({algo for algo in algoritmos for line in lines if algo.lower() in line.lower() and "cipher" in line.lower()})
    return encontrados

def extraer_suites_claves_bajas(lines, umbral=256):
    suites = []
    for line in lines:
        # Improved regex to specifically look for "bits" in cipher suite descriptions
        match = re.search(r"(\d+)\s+bits", line) # Changed from '(\d{1,10}) bits'
        if match and int(match.group(1)) < umbral and "cipher" in line.lower():
            suites.append(line.strip())
    return suites if suites else ["Ninguna detectada"]

def extraer_algoritmos_robustos(lines):
    # Expanded patterns for robust algorithms
    patrones = ("AES-256", "AES-128", "RSA 2048", "RSA 4096", "ECDHE", "ECDSA", "CHACHA20-POLY1305", "Ed25519", "SHA256", "SHA384", "SHA512", "GCM")
    encontrados = sorted({pat for pat in patrones for line in lines if pat.lower() in line.lower()})
    return encontrados

def extraer_algoritmos_ssh(raw_output):
    lines = raw_output.splitlines()
    # More specific patterns for insecure SSH algorithms
    inseguros = [l.strip() for l in lines if re.search(r"(diffie-hellman-group1-sha1|ssh-rsa\s+\(weak\)|cbc\s+mode|hmac-md5|arcfour)", l, re.I)]
    # More specific patterns for strong SSH algorithms
    fuertes = [l.strip() for l in lines if re.search(r"(ecdh-sha2-nistp|chacha20-poly1305@openssh.com|aes256-gcm|aes128-gcm|aes256-ctr|aes192-ctr|aes128-ctr|hmac-sha2-256|hmac-sha2-512|eddsa-sha2-519)", l, re.I)]
    return inseguros, fuertes

def extraer_info_certificado(texto):
    patrones = {
        'Subject': r"Subject:\s*(.+)",
        'Issuer': r"Issuer:\s*(.+)",
        'Valid from': r"Not valid before:\s*(.+)",
        'Valid to': r"Not valid after:\s{2}(.+)",
        'Key size (bits)': r"Public Key bits:\s*(\d+)",
        'Signature Algorithm': r"Signature Algorithm:\s*(.+)",
        'DNS Names': r"DNS Name:\s*(.+)" # Extracting SANs
    }
    info = {}
    for clave, patron in patrones.items():
        # Use findall for DNS Names as there can be multiple
        if clave == 'DNS Names':
            matches = re.findall(patron, texto)
            if matches:
                info[clave] = [m.strip() for m in matches]
        else:
            match = re.search(patron, texto)
            if match:
                valor = match.group(1).strip()
                if clave == 'Key size (bits)':
                    valor = int(valor)
                info[clave] = valor

    # Check for self-signed certificates
    if info.get('Subject') and info.get('Issuer') and info['Subject'] == info['Issuer']:
        info['Self-Signed'] = True
    else:
        info['Self-Signed'] = False

    # Check for expiration (simple example, more robust date parsing needed for production)
    if 'Valid to' in info:
        try:
            from datetime import datetime
            valid_to_str = info['Valid to'].split("T")[0] # Assuming format like '2025-06-05T12:34:56'
            valid_to_date = datetime.strptime(valid_to_str, '%Y-%m-%d')
            if datetime.now() > valid_to_date:
                info['Expired'] = True
            else:
                info['Expired'] = False
        except Exception:
            info['Expiration Check Error'] = "Could not parse 'Valid to' date."

    return info

def evaluate(ip_o_dominio: str) -> dict:
    resultado = {}

    # Evaluation SSL/TLS - Added more relevant scripts
    r_ssl = ejecutar_nmap(ip_o_dominio, "443,465,993,995,8443",
                          ["ssl-enum-ciphers", "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection", "tls-alpn", "tls-nextprotoneg", "sslv2-drown"])
    if r_ssl["estado"] == "ok":
        lines = r_ssl["output"].splitlines()
        resultado["protocolos_inseguros"] = extraer_protocolos_inseguros(lines)
        resultado["algoritmos_inseguros"] = extraer_algoritmos_inseguros(lines)
        resultado["suites_claves_menor_256"] = extraer_suites_claves_bajas(lines)
        resultado["algoritmos_robustos"] = extraer_algoritmos_robustos(lines)

        # Check for specific SSL/TLS vulnerabilities from script output
        ssl_vulns = []
        if "Heartbleed" in r_ssl["output"] and "VULNERABLE" in r_ssl["output"]:
            ssl_vulns.append("Vulnerabilidad Heartbleed detectada")
        if "POODLE" in r_ssl["output"] and "VULNERABLE" in r_ssl["output"]:
            ssl_vulns.append("Vulnerabilidad POODLE detectada")
        if "CCS Injection" in r_ssl["output"] and "VULNERABLE" in r_ssl["output"]:
            ssl_vulns.append("Vulnerabilidad CCS Injection detectada")
        if "DROWN" in r_ssl["output"] and "VULNERABLE" in r_ssl["output"]:
            ssl_vulns.append("Vulnerabilidad DROWN detectada")

        if ssl_vulns:
            resultado["ssl_tls_vulnerabilities"] = ssl_vulns
    else:
        resultado["error_ssl_ciphers"] = r_ssl["output"]

    # Evaluation SSH
    r_ssh = ejecutar_nmap(ip_o_dominio, "22", ["ssh2-enum-algos", "ssh-hostkey"]) # Added ssh-hostkey
    if r_ssh["estado"] == "ok":
        inseguros, fuertes = extraer_algoritmos_ssh(r_ssh["output"])
        resultado["ssh_algoritmos_inseguros"] = inseguros
        resultado["ssh_algoritmos_fuertes"] = fuertes

        # Check for weak SSH host keys (e.g., RSA < 2048 bits)
        if "ssh-hostkey" in r_ssh["output"]:
            key_match = re.search(r"(\d+)\s+bit\s+RSA\s+key", r_ssh["output"])
            if key_match and int(key_match.group(1)) < 2048:
                resultado["ssh_weak_host_key"] = f"SSH Host Key con tamaño débil detectado: {key_match.group(1)} bits RSA"
    else:
        resultado["error_ssh_algos"] = r_ssh["output"]

    # Evaluation SSL Certificate
    r_cert = ejecutar_nmap(ip_o_dominio, "443", ["ssl-cert"])
    if r_cert["estado"] == "ok":
        cert_info = extraer_info_certificado(r_cert["output"])
        resultado["ssl_cert"] = cert_info if cert_info else "Información no disponible"
    else:
        resultado["error_ssl_cert"] = r_cert["output"]

    return resultado