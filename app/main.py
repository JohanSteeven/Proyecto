from fastapi import FastAPI
from app.routers import evaluacion

app = FastAPI(
    title="API Evaluación Automática de Seguridad",
    description="Sistema que evalúa parámetros de ciberseguridad sobre una IP o dominio.",
    version="1.0.0"
)

app.include_router(evaluacion.router)

@app.get("/")
def root():
    return {"mensaje": "API de Evaluación de Seguridad Operativa"}
