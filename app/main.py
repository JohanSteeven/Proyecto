from fastapi import FastAPI
from app.routers import evaluacion
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
templates = Jinja2Templates(directory="app/templates")

app.include_router(evaluacion.router)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})