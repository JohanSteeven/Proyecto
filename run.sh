#!/bin/bash

# Activa el entorno virtual si existe
source venv/bin/activate 2>/dev/null

# Lanza el servidor
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
