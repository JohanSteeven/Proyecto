from flask import Flask, request, jsonify
from modules import cybersecurity

app = Flask(__name__)

@app.route('/evaluate', methods=['POST'])
def evaluate():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    # Solo ejecutamos el módulo cybersecurity por ahora
    resultado = cybersecurity.evaluate(ip)
    return jsonify(resultado)

if __name__ == '__main__':
    app.run(debug=True)
