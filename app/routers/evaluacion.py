from fastapi import APIRouter, HTTPException, Query
from app.services import (
    evaluador_ip,
    autenticacion,
    acceso_logico,
    seguridad_logs,
    criptografia,
    apps_seguras,
)

router = APIRouter(prefix="/evaluacion", tags=["evaluacion"])

@router.post("/")
def evaluar(ip_o_dominio: str = Query(..., description="IP o dominio a evaluar")):
    try:
        resultado = {
            "ip_o_dominio": ip_o_dominio,
            "evaluacion": {
                "escaneo_red": evaluador_ip.evaluar(ip_o_dominio),
                "autenticacion": autenticacion.evaluar(ip_o_dominio),
                "acceso_logico": acceso_logico.evaluar(ip_o_dominio),
                "logs": seguridad_logs.evaluar(ip_o_dominio),
                "criptografia": criptografia.evaluar(ip_o_dominio),
                "aplicaciones": apps_seguras.evaluar(ip_o_dominio),
            }
        }
        return resultado
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
