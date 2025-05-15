import os
import subprocess

def evaluar():
    resultado = {}

    # 1. Verificar que no se exponga versión del software (en Apache/Nginx headers)
    try:
        apache_conf = "/etc/apache2/conf-enabled/security.conf"
        if os.path.exists(apache_conf):
            with open(apache_conf, "r") as f:
                contenido = f.read()
                resultado["ocultar_version_apache"] = "ServerTokens Prod" in contenido and "ServerSignature Off" in contenido
        else:
            resultado["ocultar_version_apache"] = "archivo no encontrado"
    except Exception as e:
        resultado["ocultar_version_apache"] = str(e)

    # 2. Verificar si hay páginas de ejemplo, respaldo o por defecto en /var/www/html
    try:
        archivos = os.listdir("/var/www/html")
        archivos_sospechosos = [f for f in archivos if any(w in f.lower() for w in ["example", "backup", "test"])]
        resultado["paginas_inseguras"] = archivos_sospechosos
    except Exception as e:
        resultado["paginas_inseguras"] = str(e)

    # 3. Buscar código fuente con posibles contraseñas hardcodeadas
    try:
        grep_output = subprocess.check_output(["grep", "-r", "password", "/var/www/html"], text=True)
        resultado["passwords_hardcodeadas"] = grep_output.strip().splitlines()[:5]
    except subprocess.CalledProcessError:
        resultado["passwords_hardcodeadas"] = []  # grep no encontró resultados
    except Exception as e:
        resultado["passwords_hardcodeadas"] = str(e)

    return resultado
