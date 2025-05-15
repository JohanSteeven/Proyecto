import subprocess

def evaluar():
    resultado = {}

    # 1. Verificar soporte de TLS 1.2 o superior y ausencia de SSL (usando openssl client contra localhost)
    try:
        scan = subprocess.check_output(["openssl", "ciphers", "-v"], text=True)
        resultado["tls_1_2_o_superior"] = any("TLSv1.2" in line or "TLSv1.3" in line for line in scan.splitlines())
        resultado["uso_ssl"] = any("SSL" in line for line in scan.splitlines())
    except Exception as e:
        resultado["tls_1_2_o_superior"] = str(e)
        resultado["uso_ssl"] = str(e)

    # 2. Verificar eliminación de algoritmos inseguros (RC4, MD5, SHA1)
    try:
        inseguro = ["RC4", "MD5", "SHA1"]
        resultado["algoritmos_inseguros"] = any(alg in scan for alg in inseguro)
    except Exception as e:
        resultado["algoritmos_inseguros"] = str(e)

    # 3. Verificar presencia de certificados SSL válidos en el sistema (por ejemplo en nginx o apache2)
    try:
        cert_check = subprocess.check_output(["sudo", "find", "/etc/ssl", "-name", "*.crt"], text=True)
        resultado["certificados_ssl_detectados"] = cert_check.strip().splitlines()
    except Exception as e:
        resultado["certificados_ssl_detectados"] = str(e)

    return resultado
