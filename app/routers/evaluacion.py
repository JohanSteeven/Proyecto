from fastapi import APIRouter, HTTPException, Query
from app.modules import cybersecurity, cryptography, software_apps, auth
import socket

router = APIRouter(prefix="/evaluacion", tags=["evaluacion"])

def validar_ip(ip_o_dominio: str) -> bool:
    """
    Valida que el parámetro recibido sea una IP o dominio resoluble.

    Args:
        ip_o_dominio (str): IP o dominio a validar.

    Raises:
        HTTPException: Si el dominio o IP no es válido o no se puede resolver.
    """
    try:
        socket.gethostbyname(ip_o_dominio)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Dominio o IP no válido o no resoluble: {ip_o_dominio}")


@router.post("/")
def evaluar(ip_o_dominio: str = Query(..., description="IP o dominio a evaluar")):
    """
    Endpoint principal para evaluar la seguridad de una IP o dominio remoto.

    Realiza las siguientes evaluaciones:
    - Ciberseguridad general (puertos, servicios inseguros, cifrados débiles)
    - Criptografía (protocolos inseguros, algoritmos robustos, certificados)
    - Aplicaciones y encabezados HTTP (headers, rutas, cookies inseguras)
    - Autenticación y login (servicios de autenticación, login inseguro, HTTP auth)

    Args:
        ip_o_dominio (str): IP o dominio a evaluar.

    Returns:
        dict: Resultados de todas las evaluaciones de seguridad.

    Raises:
        HTTPException: Si ocurre un error durante la evaluación.
    """
    validar_ip(ip_o_dominio)
    try:
        resultado = {
            "ciberseguridad": cybersecurity.evaluate(ip_o_dominio),
            "criptografia": cryptography.evaluate(ip_o_dominio),
            "aplicaciones": software_apps.evaluate(ip_o_dominio),
            "autenticacion": auth.evaluate(ip_o_dominio)
        }
        return resultado
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
