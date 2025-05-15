import subprocess
from datetime import datetime, timedelta
import os

def evaluar():
    resultado = {}

    # 1. Verificar existencia y contenido reciente en logs como /var/log/auth.log
    try:
        path = "/var/log/auth.log"
        if os.path.exists(path):
            with open(path, "r") as f:
                lines = f.readlines()
                resultado["log_auth_existente"] = True
                resultado["eventos_recientes"] = len(lines[-50:])
        else:
            resultado["log_auth_existente"] = False
    except Exception as e:
        resultado["log_auth_existente"] = str(e)

    # 2. Verificar sincronización de hora (NTP activo)
    try:
        ntp_status = subprocess.check_output(["timedatectl"], text=True)
        resultado["ntp_sincronizado"] = "synchronized: yes" in ntp_status.lower()
    except Exception as e:
        resultado["ntp_sincronizado"] = str(e)

    # 3. Verificar existencia de logs de auditoría (auditd)
    try:
        auditd_status = subprocess.check_output(["sudo", "auditctl", "-s"], text=True)
        resultado["auditd_activo"] = "enabled 1" in auditd_status.lower()
    except Exception as e:
        resultado["auditd_activo"] = str(e)

    # 4. Verificar logs con información de qué, quién, cuándo y dónde
    try:
        fields_detected = all(
            any(field in line.lower() for field in ["user", "tty", "date", "session"]) for line in lines[-100:]
        ) if lines else False
        resultado["formato_logs_valido"] = fields_detected
    except Exception as e:
        resultado["formato_logs_valido"] = str(e)
    return resultado