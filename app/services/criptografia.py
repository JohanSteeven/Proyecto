import subprocess
import re

def evaluar(ip_o_dominio: str) -> dict:
    resultado = {}
    # 1. Evaluar cifrados SSL/TLS disponibles y su fortaleza
    try:
        ssl_ciphers = subprocess.check_output([
            "nmap", "-p", "443,465,993,995,8443",
            "--script", "ssl-enum-ciphers", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["ssl_ciphers_raw"] = ssl_ciphers

        lines = ssl_ciphers.splitlines()

        # 2. Detección de protocolos inseguros (SSLv2, SSLv3)
        protocolos_inseguros = [
            p for p in ("SSLv2", "SSLv3")
            if any(p in l for l in lines)
        ]
        resultado["protocolos_inseguros"] = protocolos_inseguros

        # 3. Detección de algoritmos inseguros (RC4, MD5, SHA1, CBC)
        algoritmos_inseguros = sorted({
            algo for algo in ("RC4", "MD5", "SHA1", "CBC")
            for l in lines if algo in l
        })
        resultado["algoritmos_inseguros"] = algoritmos_inseguros

        # 4. Suites con claves menores a 256 bits
        suites_bajas = []
        for l in lines:
            m = re.search(r"(\d+)\s*bits", l)
            if m and int(m.group(1)) < 256:
                suites_bajas.append(l.strip())
        resultado["suites_claves_menor_256"] = suites_bajas

        # 5. Validación de algoritmos robustos (AES-256, RSA≥2048, ECC≥224)
        patrones_fuertes = ("AES-256", "RSA", "ECDHE", "ECDSA")
        algoritmos_robustos = sorted({
            pat for pat in patrones_fuertes
            for l in lines if pat.lower() in l.lower()
        })
        resultado["algoritmos_robustos"] = algoritmos_robustos

    except Exception as e:
        resultado["error_ssl_ciphers"] = str(e)

    # 6. Presencia y detalles del certificado X.509
    try:
        ssl_cert = subprocess.check_output([
            "nmap", "-p", "443",
            "--script", "ssl-cert", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["ssl_cert"] = ssl_cert
    except Exception as e:
        resultado["error_ssl_cert"] = str(e)

    return resultado
