from pydantic import BaseModel
from typing import Dict, Any

class EvaluacionResponse(BaseModel):
    ip_o_dominio: str
    evaluacion: Dict[str, Any]
