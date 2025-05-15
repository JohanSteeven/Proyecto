import subprocess

def evaluar(ip_o_dominio: str):
    resultado = {}

    # 1. Detectar servicio NTP activo
    try:
        ntp = subprocess.check_output([
            "nmap", "-sU", "-p", "123", "--script", "ntp-info", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["ntp"] = ntp
    except subprocess.CalledProcessError as e:
        resultado["ntp"] = e.output
    except Exception as e:
        resultado["ntp"] = str(e)

    # 2. Detectar syslog o servicios similares (UDP 514)
    try:
        syslog = subprocess.check_output([
            "nmap", "-sU", "-p", "514", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["syslog"] = syslog
    except subprocess.CalledProcessError as e:
        resultado["syslog"] = e.output
    except Exception as e:
        resultado["syslog"] = str(e)

    # 3. Inspección de headers HTTP por pistas de logging
    try:
        headers = subprocess.check_output([
            "nmap", "-p", "80,443", "--script", "http-headers", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["http_headers"] = headers
    except subprocess.CalledProcessError as e:
        resultado["http_headers"] = e.output
    except Exception as e:
        resultado["http_headers"] = str(e)

    return resultado
