from flask import Flask, request, jsonify
import requests
import os

# Flask uygulaması oluşturuluyor. Vercel bunu otomatik olarak çalıştıracak.
app = Flask(__name__)

@app.route('/', methods=['POST', 'GET'])
def handler():
    # CORS (Cross-Origin Resource Sharing) başlıkları. 
    # Farklı bir domainden (senin uygulaman) istek geleceği için bu gerekli.
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    }

    # Tarayıcıların gönderdiği OPTIONS isteğine yanıt vermek için.
    if request.method == 'OPTIONS':
        return ('', 204, headers)

    # Sadece POST isteklerini kabul et
    if request.method != 'POST':
        return jsonify({"error": "Only POST requests are accepted"}), 405, headers

    # Vercel'de ayarladığımız ortam değişkenlerinden (environment variables) gizli bilgileri al.
    # Bu bilgiler asla kodun içinde yer almaz.
    CLIENT_ID = os.environ.get('KICK_CLIENT_ID')
    CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET')

    if not CLIENT_ID or not CLIENT_SECRET:
        return jsonify({"error": "Server configuration error: Client ID or Secret not set"}), 500, headers

    # Masaüstü uygulamasından gelen JSON verisini al.
    data = request.get_json()
    if not data or 'code' not in data or 'redirect_uri' not in data:
        return jsonify({"error": "Missing 'code' or 'redirect_uri' in request"}), 400, headers
    
    auth_code = data['code']
    redirect_uri = data['redirect_uri']
    code_verifier = data.get('code_verifier') # PKCE için bu da gerekli

    # Kick'in token endpoint'ine gönderilecek payload'ı oluştur.
    payload = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': redirect_uri,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier
    }

    try:
        # Kick API'sine token isteğini gönder.
        response = requests.post('https://id.kick.com/oauth/token', data=payload)
        response.raise_for_status()  # HTTP hatası varsa exception fırlat.
        
        # Kick'ten gelen yanıtı doğrudan masaüstü uygulamasına geri döndür.
        return (response.text, response.status_code, headers)

    except requests.exceptions.RequestException as e:
        # Bir hata olursa, hatayı JSON formatında döndür.
        error_message = str(e.response.text) if e.response else str(e)
        return jsonify({"error": "Failed to communicate with Kick API", "details": error_message}), 502, headers