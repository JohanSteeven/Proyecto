from services.scanner import nmap_scan

def evaluate(ip):
    try:
        resultados = nmap_scan(ip)
        return {
            "status": "success",
            "data": resultados
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
