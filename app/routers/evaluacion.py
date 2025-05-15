from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services import (
    evaluador_ip,
    autenticacion,
    acceso_logico,
    seguridad_logs,
    criptografia,
    apps_seguras,
)

router = APIRouter(prefix="/evaluacion", tags=["evaluacion"])

class EvaluacionInput(BaseModel):
    ip_o_dominio: str

@router.post("/")
def evaluar(input_data: EvaluacionInput):
    try:
        resultado = {
            "ip_o_dominio": input_data.ip_o_dominio,
            "evaluacion": {
                "escaneo_red": evaluador_ip.evaluar(input_data.ip_o_dominio),
                "autenticacion": autenticacion.evaluar(),
                "acceso_logico": acceso_logico.evaluar(),
                "logs": seguridad_logs.evaluar(),
                "criptografia": criptografia.evaluar(),
                "aplicaciones": apps_seguras.evaluar(),
            }
        }
        return resultado
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))