import platform
import socket

def obtener_info_sistema():
    return {
        "sistema_operativo": platform.system(),
        "version": platform.version(),
        "arquitectura": platform.machine(),
        "hostname": socket.gethostname(),
        "direccion_ip": socket.gethostbyname(socket.gethostname())
    }


def es_linux():
    return platform.system().lower() == "linux"


def es_windows():
    return platform.system().lower() == "windows"