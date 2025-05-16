import nmap

# Listado ampliado de servicios y protocolos inseguros
INSEGURIDAD_SERVICIOS = {
    'ftp': "FTP no cifrado",
    'telnet': "Telnet inseguro sin cifrado",
    'smbv1': "SMB versión 1 vulnerable",
    'rlogin': "Rlogin inseguro",
    'rexec': "Rexec inseguro",
    'pop3': "POP3 sin cifrado",
    'imap': "IMAP sin cifrado",
    'http': "HTTP sin cifrado",
    'snmp': "SNMP sin autenticación segura",
    'mssql': "Microsoft SQL Server sin cifrado",
    'ms-sql-s': "Microsoft SQL Server sin cifrado",
    'rdp': "Escritorio remoto (RDP) sin autorización",
    'ssh': "SSH versión insegura",
    'smtp': "SMTP sin cifrado o autenticación",
    
}

# Algoritmos y protocolos de cifrado débiles que queremos detectar
DEBIL_CIPHERS = ['rc4', 'md5', 'md4', 'sha1', 'des', '3des', 'cbc', 'sha']

def nmap_scan(ip):
    scanner = nmap.PortScanner()
    # Escaneo con detección de versiones y scripts ssl-cert para info cifrado
    scanner.scan(ip, arguments='-sV --script ssl-cert,ssl-enum-ciphers')

    resultados = {
        "puertos_abiertos": [],
        "servicios_inseguros": []
    }

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                service_name = scanner[host][proto][port]['name'].lower()
                product = scanner[host][proto][port].get('product', '').lower()
                version = scanner[host][proto][port].get('version', '').lower()
                extra_info = scanner[host][proto][port].get('extrainfo', '').lower()

                resultados["puertos_abiertos"].append({
                    "puerto": port,
                    "protocolo": proto,
                    "servicio": service_name,
                    "producto": product,
                    "version": version,
                    "info_adicional": extra_info
                })

                # Detectar servicios inseguros por nombre
                if service_name in INSEGURIDAD_SERVICIOS:
                    resultados["servicios_inseguros"].append({
                        "puerto": port,
                        "servicio": service_name,
                        "mensaje": f"Protocolo inseguro detectado: {INSEGURIDAD_SERVICIOS[service_name]}"
                    })


                # Detectar cifrados débiles a través de scripts ssl-enum-ciphers (extra info)
                # nmap guarda esto en 'script' dentro de cada puerto, si lo tienes activado
                scripts = scanner[host][proto][port].get('scripts', {})
                if 'ssl-enum-ciphers' in scripts:
                    cipher_info = scripts['ssl-enum-ciphers']
                    # chequea si aparece alguno de los cifrados débiles en el texto del script
                    for weak_cipher in DEBIL_CIPHERS:
                        if weak_cipher in cipher_info.lower():
                            resultados["servicios_inseguros"].append({
                                "puerto": port,
                                "servicio": service_name,
                                "mensaje": f"Cifrado débil detectado en protocolo SSL/TLS: {weak_cipher.upper()}"
                            })
                            break

                

    return resultados
