import subprocess
import os

def evaluar():
    resultado = {}

    # 1. Accesos prohibidos por defecto (firewall DROP por defecto)
    try:
        rules = subprocess.check_output(["sudo", "iptables", "-L", "INPUT", "-n"], text=True)
        resultado["acceso_por_defecto"] = "policy DROP" in rules or "DROP" in rules
    except Exception as e:
        resultado["acceso_por_defecto"] = str(e)

    # 2. Verificar que Telnet y FTP estén deshabilitados
    try:
        ports = subprocess.check_output(["ss", "-tuln"], text=True)
        resultado["telnet_habilitado"] = ":23" in ports
        resultado["ftp_habilitado"] = ":21" in ports
    except Exception as e:
        resultado["telnet_ftp_verificacion"] = str(e)

    # 3. SSH versión 2 habilitado
    try:
        ssh_config = open("/etc/ssh/sshd_config").read()
        resultado["ssh_version"] = "Protocol 2" in ssh_config
    except Exception as e:
        resultado["ssh_version"] = str(e)

    # 4. Verificar uso de VPN (chequeo de tun0 activo)
    try:
        interfaces = subprocess.check_output(["ip", "addr"], text=True)
        resultado["vpn_activa"] = "tun0" in interfaces
    except Exception as e:
        resultado["vpn_activa"] = str(e)

    # 5. Verificar uso de algoritmos robustos en SSH (ej: AES-256)
    try:
        strong_ciphers = ["aes256", "chacha20"]
        resultado["algoritmos_robustos_ssh"] = any(cipher in ssh_config.lower() for cipher in strong_ciphers)
    except Exception as e:
        resultado["algoritmos_robustos_ssh"] = str(e)

    # 6. Verificar políticas de firewall definidas
    try:
        firewalld_active = subprocess.check_output(["sudo", "ufw", "status"], text=True)
        resultado["firewall_activo"] = "Status: active" in firewalld_active
    except Exception as e:
        resultado["firewall_activo"] = str(e)

    # 7. Verificar segmentación de red (subredes y bridges definidos)
    try:
        ip_link = subprocess.check_output(["ip", "link"], text=True)
        resultado["segmentacion_red"] = any(x in ip_link for x in ["br-", "vlan", "eth0", "eth1"])
    except Exception as e:
        resultado["segmentacion_red"] = str(e)

    # 8. Verificar acceso limitado a hosts del dominio (resolución interna DNS/local)
    try:
        hosts = open("/etc/hosts").read()
        resultado["hosts_dominio_local"] = any(".local" in line for line in hosts.splitlines())
    except Exception as e:
        resultado["hosts_dominio_local"] = str(e)

    # 9. Verificar monitoreo de dispositivos fuera del dominio (ej: logs de dhcpd)
    try:
        dhcp_log = "/var/log/syslog"
        if os.path.exists(dhcp_log):
            with open(dhcp_log, "r") as f:
                contenido = f.read()
                resultado["dispositivos_fuera_dominio"] = "DHCPACK" in contenido
        else:
            resultado["dispositivos_fuera_dominio"] = "no log dhcp"
    except Exception as e:
        resultado["dispositivos_fuera_dominio"] = str(e)

    return resultado
