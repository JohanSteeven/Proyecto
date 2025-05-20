import subprocess
import re

def evaluate(ip_o_dominio: str) -> dict:
    resultado = {}

    try:
        ssl_ciphers_raw = subprocess.check_output([
            "nmap", "-p", "443,465,993,995,8443",
            "--script", "ssl-enum-ciphers", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=90)

        lines = ssl_ciphers_raw.splitlines()

        # Detectar protocolos inseguros
        protocolos_inseguros = [p for p in ("SSLv2", "SSLv3") if any(p in l for l in lines)]

        # Detectar algoritmos inseguros
        algoritmos_inseguros = sorted({algo for algo in ("RC4", "MD5", "SHA1", "CBC") for l in lines if algo in l})

        # Suites con claves menores a 256 bits
        suites_bajas = []
        for l in lines:
            m = re.search(r"(\d+)\s*bits", l)
            if m and int(m.group(1)) < 256:
                suites_bajas.append(l.strip())

        # Algoritmos robustos
        patrones_fuertes = ("AES-256", "RSA", "ECDHE", "ECDSA", "CHACHA20-POLY1305")
        algoritmos_robustos = sorted({pat for pat in patrones_fuertes for l in lines if pat.lower() in l.lower()})

        resultado.update({
            "protocolos_inseguros": protocolos_inseguros or ["Ninguno detectado"],
            "algoritmos_inseguros": algoritmos_inseguros,
            "suites_claves_menor_256": suites_bajas or ["Ninguna detectada"],
            "algoritmos_robustos": algoritmos_robustos,
        })

    except Exception as e:
        resultado["error_ssl_ciphers"] = str(e)

    try:
        ssh_algos_raw = subprocess.check_output([
            "nmap", "-p", "22",
            "--script", "ssh2-enum-algos", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)

        ssh_lines = ssh_algos_raw.splitlines()
        ssh_inseguros = [l.strip() for l in ssh_lines if re.search(r"(diffie-hellman-group1-sha1|ssh-rsa)", l, re.I)]
        ssh_fuertes = [l.strip() for l in ssh_lines if re.search(r"(ecdh-sha2-nistp|chacha20-poly1305@openssh.com|aes256-ctr)", l, re.I)]

        resultado.update({
            "ssh_algoritmos_inseguros": ssh_inseguros,
            "ssh_algoritmos_fuertes": ssh_fuertes,
        })

    except Exception as e:
        resultado["error_ssh_algos"] = str(e)

    try:
        ssl_cert_raw = subprocess.check_output([
            "nmap", "-p", "443",
            "--script", "ssl-cert", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)

        cert_info = {}

        subject_match = re.search(r"Subject: (.+)", ssl_cert_raw)
        issuer_match = re.search(r"Issuer: (.+)", ssl_cert_raw)
        valid_from_match = re.search(r"Not valid before: (.+)", ssl_cert_raw)
        valid_to_match = re.search(r"Not valid after:  (.+)", ssl_cert_raw)
        key_bits_match = re.search(r"Public Key bits: (\d+)", ssl_cert_raw)
        sig_algo_match = re.search(r"Signature Algorithm: (.+)", ssl_cert_raw)

        if subject_match:
            cert_info['Subject'] = subject_match.group(1).strip()
        if issuer_match:
            cert_info['Issuer'] = issuer_match.group(1).strip()
        if valid_from_match:
            cert_info['Valid from'] = valid_from_match.group(1).strip()
        if valid_to_match:
            cert_info['Valid to'] = valid_to_match.group(1).strip()
        if key_bits_match:
            cert_info['Key size (bits)'] = int(key_bits_match.group(1))
        if sig_algo_match:
            cert_info['Signature Algorithm'] = sig_algo_match.group(1).strip()

        resultado["ssl_cert"] = cert_info if cert_info else "Información no disponible"

    except Exception as e:
        resultado["error_ssl_cert"] = str(e)

    return resultado
