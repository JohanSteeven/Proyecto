from pydantic import BaseModel

class EvaluacionRequest(BaseModel):
    ip_o_dominio: str
