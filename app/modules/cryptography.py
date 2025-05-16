import nmap
from datetime import datetime

# Listado de cifrados débiles que queremos detectar
WEAK_CIPHERS = ['rc4', 'md5', 'sha1', 'des', '3des', 'cbc', 'md4']

def evaluate(ip):
    scanner = nmap.PortScanner()

    # Escaneo con scripts para certificado y cifrados SSL/TLS
    scanner.scan(ip, arguments='-p 443 --script ssl-cert,ssl-enum-ciphers')

    resultados = {
        "certificado": {},
        "cifrados_debiles": [],
        "tls_versiones": [],
        "alertas": []
    }

    for host in scanner.all_hosts():
        # Revisar puerto 443 o cualquier puerto con ssl-enum-ciphers
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                scripts = scanner[host][proto][port].get('scripts', {})

                # Info del certificado
                if 'ssl-cert' in scripts:
                    cert_info = scripts['ssl-cert']

                    resultados['certificado']['issuer'] = cert_info.get('issuer', 'desconocido')
                    resultados['certificado']['subject'] = cert_info.get('subject', 'desconocido')
                    resultados['certificado']['valid_from'] = cert_info.get('notbefore', 'desconocido')
                    resultados['certificado']['valid_until'] = cert_info.get('notafter', 'desconocido')

                    # Validar fechas del certificado
                    try:
                        not_after = datetime.strptime(cert_info.get('notafter'), '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.now():
                            resultados['alertas'].append('Certificado TLS expirado')
                    except Exception:
                        resultados['alertas'].append('No se pudo verificar vigencia del certificado')

                # Info de cifrados
                if 'ssl-enum-ciphers' in scripts:
                    cipher_report = scripts['ssl-enum-ciphers']

                    # Extraemos las versiones TLS detectadas
                    tls_versions = []
                    weak_ciphers_found = []
                    lines = cipher_report.split('\n')
                    for line in lines:
                        line_lower = line.lower()
                        # Buscar versiones TLS
                        if 'tls' in line_lower or 'ssl' in line_lower:
                            # Ejemplo: TLSv1.2, TLSv1.3 etc.
                            tls_versions.append(line.strip())
                        # Buscar cifrados débiles
                        for weak in WEAK_CIPHERS:
                            if weak in line_lower:
                                weak_ciphers_found.append(line.strip())

                    resultados['tls_versiones'] = list(set(tls_versions))
                    resultados['cifrados_debiles'] = list(set(weak_ciphers_found))
                    if weak_ciphers_found:
                        resultados['alertas'].append('Se detectaron cifrados débiles en TLS/SSL')

    if not resultados['certificado']:
        resultados['alertas'].append('No se detectó certificado TLS en el puerto 443')
    if not resultados['tls_versiones']:
        resultados['alertas'].append('No se detectaron versiones TLS/SSL')

    return resultados
