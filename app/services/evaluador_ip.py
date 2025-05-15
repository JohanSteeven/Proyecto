import subprocess

def evaluar(ip_o_dominio: str) -> dict:
    try:
        resultado = subprocess.check_output(["nmap", "-F", ip_o_dominio], stderr=subprocess.STDOUT, text=True, timeout=15)
        return {"estado": "ok", "resultado": resultado}
    except subprocess.CalledProcessError as e:
        return {"estado": "error", "mensaje": e.output}
    except Exception as e:
        return {"estado": "error", "mensaje": str(e)}