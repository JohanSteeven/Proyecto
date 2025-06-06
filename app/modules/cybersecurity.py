# cybersecurity.py
import nmap 
import re
import httpx # Still needed for potential future use or if other functions were added.

INSEGURIDAD_SERVICIOS = {
    'ftp': "FTP no cifrado (puerto 21)",
    'telnet': "Telnet inseguro sin cifrado (puerto 23)",
    'smb': "SMB (Server Message Block) detectado. Evaluar versión y configuración (ej. SMBv1 es vulnerable)", # Generic SMB, specific versions checked in scripts
    'rlogin': "Rlogin inseguro (puerto 513)",
    'rexec': "Rexec inseguro (puerto 512)",
    'pop3': "POP3 sin cifrado (puerto 110)",
    'imap': "IMAP sin cifrado (puerto 143)",
    'http': "HTTP sin cifrado (puerto 80)",
    'snmp': "SNMP detectado. Evaluar versión (v1/v2c pueden tener autenticación débil) y comunidad.",
    'mssql': "Microsoft SQL Server sin cifrado (puerto 1433)",
    'ms-sql-s': "Microsoft SQL Server sin cifrado (puerto 1433)",
    'rdp': "Escritorio remoto (RDP) detectado. Evaluar autorización y configuración de seguridad.", # Generic RDP
    'ssh': "SSH detectado. Evaluar versiones inseguras y algoritmos débiles (puerto 22).", # Generic SSH
    'smtp': "SMTP sin cifrado o autenticación (puerto 25)",
    'netbios-ssn': "NetBIOS/SMB directo (puerto 139) - Posible exposición de información",
    'cifs': "CIFS (Common Internet File System) detectado - Posible exposición de recursos compartidos",
    'nfs': "NFS (Network File System) detectado - Posible exposición de recursos compartidos",
    'vnc': "VNC (Virtual Network Computing) detectado - Posible acceso remoto sin cifrado robusto",
    'mysql': "MySQL sin cifrado (puerto 3306)",
    'postgresql': "PostgreSQL sin cifrado (puerto 5432)",
    'rpcbind': "RPCBind/Portmapper (puerto 111) - Puede revelar información sobre servicios RPC"
}

# Expanded weak ciphers and protocols
DEBIL_CIPHERS = ['rc4', 'md5', 'md4', 'des', '3des', 'cbc', 'null', 'export', 'anon', 'sslv2', 'sslv3', 'tls1.0', 'tls1.1']

_cache_cves = {} # This cache is no longer directly used for NVD search in this module as the NVD search is removed.

def escanear_host(ip):
    scanner = nmap.PortScanner()
    # Added more scripts for broader detection
    # Added -sC for default scripts, -sV for service version detection
    scanner.scan(ip, arguments='-sS -sV -sC --script ssl-cert,ssl-enum-ciphers,ftp-anon,smb-security-mode,ssh2-enum-algos,http-security-headers,snmp-info')
    return scanner

def extraer_puertos_abiertos(scanner):
    puertos_abiertos = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, servicio_info in scanner[host][proto].items():
                puertos_abiertos.append({
                    "puerto": port,
                    "protocolo": proto,
                    "estado": servicio_info.get('state', 'unknown'), # Added state
                    "servicio": servicio_info['name'].lower(),
                    "producto": servicio_info.get('product', '').lower(),
                    "version": servicio_info.get('version', '').lower(),
                    "info_adicional": servicio_info.get('extrainfo', '').lower()
                })
    return puertos_abiertos

# Removed buscar_vulnerabilidades_nvd function as requested

def detectar_servicios_inseguros(scanner):
    servicios_inseguros = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, servicio_info in scanner[host][proto].items():
                service_name = servicio_info['name'].lower()
                scripts_output = servicio_info.get('script', {}) # Nmap library stores script output in 'script' key

                # Check for general insecure services based on port/service name
                if service_name in INSEGURIDAD_SERVICIOS:
                    servicios_inseguros.append({
                        "puerto": port,
                        "servicio": service_name,
                        "mensaje": INSEGURIDAD_SERVICIOS[service_name]
                    })

                # Detailed SSL/TLS cipher and protocol checking
                if 'ssl-enum-ciphers' in scripts_output:
                    cipher_info = scripts_output['ssl-enum-ciphers'].lower()
                    for weak_cipher in DEBIL_CIPHERS:
                        if weak_cipher in cipher_info:
                            servicios_inseguros.append({
                                "puerto": port,
                                "servicio": service_name,
                                "mensaje": f"Cifrado débil o protocolo inseguro detectado en SSL/TLS: {weak_cipher.upper()}"
                            })
                            # Break to avoid duplicate messages for the same weak cipher type
                            break
                    # Specific checks for SSL/TLS protocol versions
                    if "sslv2" in cipher_info:
                        servicios_inseguros.append({"puerto": port, "servicio": service_name, "mensaje": "Protocolo SSLv2 habilitado (inseguro)"})
                    if "sslv3" in cipher_info:
                        servicios_inseguros.append({"puerto": port, "servicio": service_name, "mensaje": "Protocolo SSLv3 habilitado (inseguro, POODLE)"})
                    if "tls1.0" in cipher_info:
                        servicios_inseguros.append({"puerto": port, "servicio": service_name, "mensaje": "Protocolo TLSv1.0 habilitado (considerado obsoleto/inseguro)"})
                    if "tls1.1" in cipher_info:
                        servicios_inseguros.append({"puerto": port, "servicio": service_name, "mensaje": "Protocolo TLSv1.1 habilitado (considerado obsoleto/inseguro)"})


                # Specific script-based detections
                if 'ftp-anon' in scripts_output:
                    if "Anonymous FTP login allowed" in scripts_output['ftp-anon']:
                        servicios_inseguros.append({
                            "puerto": port,
                            "servicio": service_name,
                            "mensaje": "Servidor FTP permite login anónimo"
                        })
                if 'smb-security-mode' in scripts_output:
                    smb_output = scripts_output['smb-security-mode'].lower()
                    if "message signing disabled" in smb_output:
                        servicios_inseguros.append({
                            "puerto": port,
                            "servicio": service_name,
                            "mensaje": "SMB Signing deshabilitado (riesgo de ataque Man-in-the-Middle)"
                        })
                    if "smbv1 enabled" in smb_output: # Check for explicit SMBv1 enabled
                         servicios_inseguros.append({
                            "puerto": port,
                            "servicio": service_name,
                            "mensaje": "SMBv1 habilitado (vulnerable a WannaCry, NotPetya)"
                        })
                if 'ssh2-enum-algos' in scripts_output:
                    ssh_output = scripts_output['ssh2-enum-algos'].lower()
                    if re.search(r"(diffie-hellman-group1-sha1|arcfour)", ssh_output):
                        servicios_inseguros.append({
                            "puerto": port,
                            "servicio": service_name,
                            "mensaje": "Algoritmos SSH débiles/obsoletos detectados"
                        })
                if 'http-security-headers' in scripts_output:
                    headers_output = scripts_output['http-security-headers'].lower()
                    # Basic check for missing security headers
                    if "x-frame-options" not in headers_output:
                        servicios_inseguros.append({"puerto": port, "servicio": service_name, "mensaje": "Encabezado X-Frame-Options ausente (riesgo de Clickjacking)"})
                    if "x-content-type-options" not in headers_output:
                        servicios_inseguros.append({"puerto": port, "servicio": service_name, "mensaje": "Encabezado X-Content-Type-Options ausente (riesgo de MIME-sniffing)"})
                    if "strict-transport-security" not in headers_output:
                        servicios_inseguros.append({"puerto": port, "servicio": service_name, "mensaje": "Encabezado Strict-Transport-Security (HSTS) ausente"})

                if 'snmp-info' in scripts_output:
                    snmp_output = scripts_output['snmp-info'].lower()
                    if "public" in snmp_output or "private" in snmp_output: # Common default communities
                        servicios_inseguros.append({
                            "puerto": port,
                            "servicio": service_name,
                            "mensaje": "Comunidad SNMP predeterminada/débil detectada (public/private)"
                        })

    return servicios_inseguros, [] # No longer processing specific CVE vulnerabilities here.

def evaluate(ip):
    scanner = escanear_host(ip)
    puertos_abiertos = extraer_puertos_abiertos(scanner)
    servicios_inseguros, _ = detectar_servicios_inseguros(scanner) # _ to ignore the empty vulnerabilities list

    return {
        "puertos_abiertos": puertos_abiertos,
        "servicios_inseguros": servicios_inseguros,
        "vulnerabilidades_detectadas": [] # Explicitly empty as per request
    }