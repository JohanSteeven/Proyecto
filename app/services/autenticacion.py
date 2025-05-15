import subprocess

def evaluar(ip_o_dominio: str):
    resultado = {}

    # 1. Detectar servicios de autenticación comunes y protocolos de login inseguros
    try:
        output = subprocess.check_output([
            "nmap", "-p", "21,22,23,80,110,143,389,636,3306,5432", "--script", "auth", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["servicios_autenticacion"] = output
    except subprocess.CalledProcessError as e:
        resultado["servicios_autenticacion"] = e.output
    except Exception as e:
        resultado["servicios_autenticacion"] = str(e)

    # 2. Verificar si existen puertos con login no cifrado (ej: telnet, ftp)
    try:
        inseguro = subprocess.check_output([
            "nmap", "-p", "21,23", "--script", "ftp-anon,telnet-encryption", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["servicios_login_inseguros"] = inseguro
    except subprocess.CalledProcessError as e:
        resultado["servicios_login_inseguros"] = e.output
    except Exception as e:
        resultado["servicios_login_inseguros"] = str(e)

    # 3. Validar mecanismos de autenticación básicos si están expuestos (ej: HTTP Basic Auth)
    try:
        http_auth = subprocess.check_output([
            "nmap", "-p", "80,443", "--script", "http-auth,http-form-auth", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["http_autenticacion"] = http_auth
    except subprocess.CalledProcessError as e:
        resultado["http_autenticacion"] = e.output
    except Exception as e:
        resultado["http_autenticacion"] = str(e)

    return resultado