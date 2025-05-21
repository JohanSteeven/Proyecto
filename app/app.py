from flask import Flask, request, jsonify
from modules import cybersecurity, cryptography, software_apps

app = Flask(__name__)

@app.route('/evaluate', methods=['POST'])
def evaluate():
    data = request.get_data(as_text=True)
    print("Raw data received:", data)  # Esto muestra lo que llegó
    try:
        json_data = request.get_json(force=True)
    except Exception as e:
        return {"error": "JSON mal formado: " + str(e)}, 400

    ip = json_data.get('ip')
    if not ip:
        return {"error": "IP address is required"}, 400

    resultados ={ 
                 "Ciberseguridad":cybersecurity.evaluate(ip),
                 "Criptografia":cryptography.evaluate(ip),
                 "Software":software_apps.evaluate(ip)
                 }
    
    return jsonify(resultados)

if __name__ == '__main__':
    app.run(debug=True)
