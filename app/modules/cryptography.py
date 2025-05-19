import subprocess
import re

def evaluate(ip_o_dominio: str) -> dict:
    resultado = {}

    try:
        # 1. Escanear cifrados SSL/TLS en puertos comunes usando nmap ssl-enum-ciphers
        ssl_ciphers = subprocess.check_output([
            "nmap", "-p", "443,465,993,995,8443",
            "--script", "ssl-enum-ciphers", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=90)
        resultado["ssl_ciphers_raw"] = ssl_ciphers

        lines = ssl_ciphers.splitlines()

        # Detectar protocolos inseguros SSLv2, SSLv3
        protocolos_inseguros = [p for p in ("SSLv2", "SSLv3") if any(p in l for l in lines)]
        resultado["protocolos_inseguros"] = protocolos_inseguros

        # Detectar algoritmos inseguros RC4, MD5, SHA1, CBC
        algoritmos_inseguros = sorted({algo for algo in ("RC4", "MD5", "SHA1", "CBC") for l in lines if algo in l})
        resultado["algoritmos_inseguros"] = algoritmos_inseguros

        # Suites con claves menores a 256 bits
        suites_bajas = []
        for l in lines:
            m = re.search(r"(\d+)\s*bits", l)
            if m and int(m.group(1)) < 256:
                suites_bajas.append(l.strip())
        resultado["suites_claves_menor_256"] = suites_bajas

        # Detectar algoritmos robustos (AES-256, RSA >=2048, ECC, ECDSA)
        patrones_fuertes = ("AES-256", "RSA", "ECDHE", "ECDSA", "CHACHA20-POLY1305")
        algoritmos_robustos = sorted({pat for pat in patrones_fuertes for l in lines if pat.lower() in l.lower()})
        resultado["algoritmos_robustos"] = algoritmos_robustos

    except Exception as e:
        resultado["error_ssl_ciphers"] = str(e)

    try:
        # 2. Escanear cifrados SSH y algoritmos con ssh2-enum-algos script
        ssh_algos = subprocess.check_output([
            "nmap", "-p", "22",
            "--script", "ssh2-enum-algos", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["ssh_algos_raw"] = ssh_algos

        ssh_lines = ssh_algos.splitlines()

        # Buscar algoritmos inseguros SSH (ej: diffie-hellman-group1-sha1)
        ssh_inseguros = []
        for l in ssh_lines:
            if re.search(r"(diffie-hellman-group1-sha1|ssh-rsa)", l, re.I):
                ssh_inseguros.append(l.strip())
        resultado["ssh_algoritmos_inseguros"] = ssh_inseguros

        # Buscar algoritmos fuertes SSH (ej: ecdh-sha2-nistp256, chacha20-poly1305@openssh.com)
        ssh_fuertes = []
        for l in ssh_lines:
            if re.search(r"(ecdh-sha2-nistp|chacha20-poly1305@openssh.com|aes256-ctr)", l, re.I):
                ssh_fuertes.append(l.strip())
        resultado["ssh_algoritmos_fuertes"] = ssh_fuertes

    except Exception as e:
        resultado["error_ssh_algos"] = str(e)

    try:
        # 3. Validar certificados X.509 con ssl-cert script
        ssl_cert = subprocess.check_output([
            "nmap", "-p", "443",
            "--script", "ssl-cert", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["ssl_cert"] = ssl_cert
    except Exception as e:
        resultado["error_ssl_cert"] = str(e)

    return resultado
