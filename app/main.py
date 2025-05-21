from fastapi import FastAPI
from app.routers import evaluacion

app = FastAPI(
    title="API Evaluación Automática de Seguridad",
    description="Evalúa parámetros de ciberseguridad sobre una IP o dominio remoto.",
    version="1.0.0"
)

app.include_router(evaluacion.router)
