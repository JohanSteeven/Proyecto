import nmap
import httpx

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

DEBIL_CIPHERS = ['rc4', 'md5', 'md4', 'sha1', 'des', '3des', 'cbc', 'sha']

_cache_cves = {}

def escanear_host(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV --script ssl-cert,ssl-enum-ciphers')
    return scanner

def extraer_puertos_abiertos(scanner):
    puertos_abiertos = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, servicio_info in scanner[host][proto].items():
                puertos_abiertos.append({
                    "puerto": port,
                    "protocolo": proto,
                    "servicio": servicio_info['name'].lower(),
                    "producto": servicio_info.get('product', '').lower(),
                    "version": servicio_info.get('version', '').lower(),
                    "info_adicional": servicio_info.get('extrainfo', '').lower()
                })
    return puertos_abiertos

def buscar_vulnerabilidades_nvd(producto, version, max_results=3):
    key = f"{producto}:{version}"
    if key in _cache_cves:
        return _cache_cves[key]

    producto = producto.strip().lower()
    version = version.strip().lower()
    if not producto or producto in ['unknown', '']:
        return []
    query = f"{producto} {version}".strip()
    if len(query) < 3:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        "keyword": query,
        "resultsPerPage": max_results
    }
    try:
        response = httpx.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        cves = data.get("result", {}).get("CVE_Items", [])
        resultado_cves = []
        for cve in cves:
            cve_id = cve["cve"]["CVE_data_meta"]["ID"]
            descripcion = cve["cve"]["description"]["description_data"][0]["value"]
            cvss = cve.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
            score = cvss.get("baseScore", "N/A")
            severity = cvss.get("baseSeverity", "N/A")
            url_cve = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            resultado_cves.append({
                "id": cve_id,
                "descripcion": descripcion,
                "cvss_score": score,
                "severity": severity,
                "url": url_cve
            })

        _cache_cves[key] = resultado_cves
        return resultado_cves

    except Exception as e:
        # Aquí podrías loggear el error si tienes logger configurado
        # print(f"Error consultando NVD para {query}: {e}")
        _cache_cves[key] = []
        return []

def detectar_servicios_inseguros(scanner):
    servicios_inseguros = []
    vulnerabilidades = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, servicio_info in scanner[host][proto].items():
                service_name = servicio_info['name'].lower()
                scripts = servicio_info.get('scripts', {})

                if service_name in INSEGURIDAD_SERVICIOS:
                    servicios_inseguros.append({
                        "puerto": port,
                        "servicio": service_name,
                        "mensaje": f"Protocolo inseguro detectado: {INSEGURIDAD_SERVICIOS[service_name]}"
                    })

                if 'ssl-enum-ciphers' in scripts:
                    cipher_info = scripts['ssl-enum-ciphers'].lower()
                    for weak_cipher in DEBIL_CIPHERS:
                        if weak_cipher in cipher_info:
                            servicios_inseguros.append({
                                "puerto": port,
                                "servicio": service_name,
                                "mensaje": f"Cifrado débil detectado en protocolo SSL/TLS: {weak_cipher.upper()}"
                            })
                            break

                producto = servicio_info.get('product', '').strip()
                version = servicio_info.get('version', '').strip()
                if producto and version:
                    cves = buscar_vulnerabilidades_nvd(producto, version)
                    if cves:
                        vulnerabilidades.append({
                            "puerto": port,
                            "servicio": service_name,
                            "producto": producto,
                            "version": version,
                            "vulnerabilidades": cves
                        })

    return servicios_inseguros, vulnerabilidades

def evaluate(ip):
    scanner = escanear_host(ip)
    puertos_abiertos = extraer_puertos_abiertos(scanner)
    servicios_inseguros, vulnerabilidades = detectar_servicios_inseguros(scanner)

    return {
        "puertos_abiertos": puertos_abiertos,
        "servicios_inseguros": servicios_inseguros,
        "vulnerabilidades_detectadas": vulnerabilidades
    }
