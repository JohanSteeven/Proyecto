import subprocess
import os

def evaluar():
    resultado = {}

    try:
        users = subprocess.check_output(["cut", "-d:", "-f1", "/etc/passwd"], text=True).splitlines()
    except:
        users = []

    # 1. Verificar existencia de usuarios admin y operador
    try:
        with open("/etc/passwd", "r") as f:
            passwd_lines = f.read()
            resultado["perfiles_existentes"] = {
                "admin": "admin" in passwd_lines,
                "operador": "operador" in passwd_lines
            }
    except Exception as e:
        resultado["perfiles_existentes"] = str(e)

    # 2. Usuarios inactivos más de 90 días (usando lastlog)
    try:
        lastlog = subprocess.check_output(["lastlog"], text=True)
        inactivos = [line for line in lastlog.splitlines()[1:] if "Never" in line or "202" in line and "[" not in line]
        resultado["usuarios_inactivos_mas_90_dias"] = len(inactivos)
    except Exception as e:
        resultado["usuarios_inactivos_mas_90_dias"] = str(e)

    # 3. Verificar si existe la opción de deshabilitar usuarios (shadow password field *)
    try:
        shadow = subprocess.check_output(["sudo", "cat", "/etc/shadow"], text=True)
        deshabilitados = [line for line in shadow.splitlines() if line.split(":")[1].startswith("*")]
        resultado["usuarios_deshabilitados"] = len(deshabilitados)
    except Exception as e:
        resultado["usuarios_deshabilitados"] = str(e)

    # 4. Verificar unicidad de usuarios (no duplicados)
    try:
        resultado["usuarios_duplicados"] = len(users) != len(set(users))
    except Exception as e:
        resultado["usuarios_duplicados"] = str(e)

    # 5. Verificar usuarios por defecto (ej: root, daemon) renombrados o deshabilitados
    try:
        default_users = ["root", "daemon", "bin"]
        encontrados = [u for u in default_users if u in users]
        resultado["usuarios_por_defecto"] = encontrados
    except Exception as e:
        resultado["usuarios_por_defecto"] = str(e)

    # 6. Verificar cambio de contraseña obligatorio al primer inicio (con chage)
    try:
        chage_output = subprocess.check_output(["chage", "-l", "root"], text=True)
        resultado["cambio_contraseña_primer_inicio"] = "must change" in chage_output.lower()
    except Exception as e:
        resultado["cambio_contraseña_primer_inicio"] = str(e)

    # 7. Verificar bloqueo automático de sesión por inactividad (TMOUT)
    try:
        with open("/etc/bash.bashrc", "r") as f:
            contenido = f.read()
            resultado["bloqueo_por_inactividad"] = "TMOUT" in contenido
    except Exception as e:
        resultado["bloqueo_por_inactividad"] = str(e)

    # 8. Verificar usuarios del sistema no usados por humanos (UID < 1000)
    try:
        system_users = [line.split(":")[0] for line in open("/etc/passwd") if int(line.split(":")[2]) < 1000]
        resultado["usuarios_sistema_identificados"] = system_users
    except Exception as e:
        resultado["usuarios_sistema_identificados"] = str(e)

    # 9. Verificar separación entre usuarios normales y de sistema
    try:
        all_users = subprocess.check_output(["getent", "passwd"], text=True).splitlines()
        separados = all("/home/" in u or int(u.split(":")[2]) >= 1000 for u in all_users if "nologin" not in u)
        resultado["usuarios_separados_de_sistema"] = separados
    except Exception as e:
        resultado["usuarios_separados_de_sistema"] = str(e)

    # 10. Verificar si hay contraseñas cifradas (campo de /etc/shadow no vacío y no en texto plano)
    try:
        hashes = [line.split(":")[1] for line in shadow.splitlines() if line.split(":")[1] not in ["", "*", "!!"]]
        resultado["contraseñas_cifradas"] = all(h.startswith("$") for h in hashes)
    except Exception as e:
        resultado["contraseñas_cifradas"] = str(e)

    return resultado
