

# API de Evaluación de Seguridad

Esta API permite evaluar automáticamente diferentes parámetros de seguridad relacionados con una IP o dominio, mediante módulos especializados que analizan aspectos de ciberseguridad y criptografía.

---

## Módulos disponibles y parámetros evaluados

### 1. Módulo: Evaluación de Ciberseguridad (`cybersecurity.py`)

Este módulo realiza un escaneo externo para detectar vulnerabilidades comunes y configuraciones inseguras.

**Parámetros evaluados:**

- Puertos abiertos y servicios activos.
- Protocolos inseguros (FTP, Telnet, SMBv1, etc.).
- Versiones vulnerables de servicios (ej. SSH v1).
- Cifrados débiles detectados en protocolos.
- Servicios predeterminados o inseguros habilitados.
- Alertas críticas sobre configuraciones inseguras.

---

### 2. Módulo: Evaluación de Criptografía (`cryptography.py`)

Analiza mecanismos criptográficos en comunicación TLS/SSL del objetivo.

**Parámetros evaluados:**

- Transmisión cifrada con TLS 1.2 o superior.
- Certificados digitales válidos y vigentes.
- Uso de algoritmos criptográficos fuertes (AES-256, RSA-2048, ECC).
- Eliminación de cifrados y hashes débiles (RC4, CBC, MD5, SHA1, etc.).
- Versiones TLS activas y ausencia de SSL obsoleto.
- Cifrado adecuado de datos sensibles en tránsito.
- Alertas sobre configuraciones criptográficas inseguras.

**Parámetros no evaluables automáticamente:**

- Registro de actividades criptográficas internas.
- Gestión segura de claves criptográficas.
- Cifrado de datos en reposo y medios de respaldo externos.

---

## Requisitos e instalación

1. Clona este repositorio.

2. Crea y activa un entorno virtual:

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
````

3. Instala dependencias:

```bash
pip install -r requirements.txt
```

4. Asegúrate de tener instalado `nmap` con scripts `ssl-cert` y `ssl-enum-ciphers`.

---

## Ejecución

Inicia el servidor Flask:

```bash
python app.py
```

La API estará disponible en: `http://127.0.0.1:5000/evaluate`

---

## Uso

Realiza una petición POST con JSON que contenga la IP o dominio a evaluar.

Ejemplo con `curl`:

```bash
curl -X POST http://127.0.0.1:5000/evaluate \
  -H "Content-Type: application/json" \
  -d '{"ip": "scanme.nmap.org"}'
```

Ejemplo de cuerpo JSON:

```json
{
  "ip": "scanme.nmap.org"
}
```

---

## Respuesta

La API devolverá un JSON con los resultados de los módulos ejecutados, incluyendo el estado de cumplimiento y descripción detallada de cada parámetro evaluado.

---




