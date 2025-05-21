# API de Evaluación Automática de Seguridad — Parámetros Implementados

Este documento detalla los parámetros de seguridad que cada módulo implementado en la API evalúa sobre la IP o dominio remoto.

---

## 1. Módulo `cybersecurity.py`

- Puertos abiertos y servicios detectados.
- Detección de servicios inseguros:
  - FTP sin cifrado.
  - Telnet habilitado.
  - SMBv1 vulnerable.
  - RDP sin autenticación.
  - SMTP sin cifrado.
- Algoritmos débiles en TLS/SSL (RC4, MD5, SHA1, CBC).

---

## 2. Módulo `cryptography.py`

- Protocolos TLS/SSL inseguros detectados (SSLv2, SSLv3).
- Algoritmos criptográficos inseguros (RC4, MD5, SHA1, CBC).
- Algoritmos criptográficos robustos (AES-256, RSA 2048+, ECDHE, ECDSA, ChaCha20).
- Certificados digitales válidos con detalle de emisor, validez, tamaño clave y algoritmo de firma.
- Algoritmos SSH inseguros y robustos.

---

## 3. Módulo `software_apps.py`

- Encabezados HTTP expuestos (puertos 80, 443, 8080).
- Detección de páginas de ejemplo, respaldo o test accesibles.
- Verificación de flags de seguridad en cookies HTTP (`Secure`, `HttpOnly`).

---

