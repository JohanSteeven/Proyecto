import subprocess

def evaluar(ip_o_dominio: str):
    resultado = {}

    # 1. Servicios de acceso remoto comunes (SSH, RDP, VPN, VNC)
    try:
        acceso_remoto = subprocess.check_output([
            "nmap", "-p", "22,23,3389,1194,5900", "--script",
            "ssh2-enum-algos,rdp-enum-encryption,vnc-info,telnet-encryption", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["servicios_acceso_logico"] = acceso_remoto
    except subprocess.CalledProcessError as e:
        resultado["servicios_acceso_logico"] = e.output
    except Exception as e:
        resultado["servicios_acceso_logico"] = str(e)

    # 2. Firewall y detección de filtrado
    try:
        firewall = subprocess.check_output([
            "nmap", "-Pn", "--reason", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["deteccion_firewall"] = firewall
    except subprocess.CalledProcessError as e:
        resultado["deteccion_firewall"] = e.output
    except Exception as e:
        resultado["deteccion_firewall"] = str(e)

    # 3. Verificar puertos y servicios comunes habilitados (baseline)
    try:
        puertos = subprocess.check_output([
            "nmap", "-sS", "-p", "1-1024", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["puertos_basicos_abiertos"] = puertos
    except subprocess.CalledProcessError as e:
        resultado["puertos_basicos_abiertos"] = e.output
    except Exception as e:
        resultado["puertos_basicos_abiertos"] = str(e)

    # 4. Revisar servicios inseguros conocidos (nmap default scripts)
    try:
        inseguros = subprocess.check_output([
            "nmap", "--script", "default", ip_o_dominio
        ], stderr=subprocess.STDOUT, text=True, timeout=60)
        resultado["servicios_inseguros"] = inseguros
    except subprocess.CalledProcessError as e:
        resultado["servicios_inseguros"] = e.output
    except Exception as e:
        resultado["servicios_inseguros"] = str(e)

    return resultado
