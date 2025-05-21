from fastapi import APIRouter, HTTPException, Query
from app.modules import cybersecurity, cryptography, software_apps

router = APIRouter(prefix="/evaluacion", tags=["evaluacion"])

@router.post("/")
def evaluar(ip_o_dominio: str = Query(..., description="IP o dominio a evaluar")):
    try:
        resultado = {
            "ciberseguridad": cybersecurity.evaluate(ip_o_dominio),
            "criptografia": cryptography.evaluate(ip_o_dominio),
            "aplicaciones": software_apps.evaluate(ip_o_dominio)
          
        }
        return resultado
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
