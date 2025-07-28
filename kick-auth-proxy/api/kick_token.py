from http.server import BaseHTTPRequestHandler
import json
import os
import requests
import logging

# Vercel logları için basit bir logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        CLIENT_ID = os.environ.get('KICK_CLIENT_ID')
        CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET')

        if not CLIENT_ID or not CLIENT_SECRET:
            logger.error("CLIENT_ID or CLIENT_SECRET environment variables are not set.")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Server configuration error"}).encode())
            return

        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data)
            logger.info(f"Received POST request body: {body}") # Gelen body'yi logla
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Invalid JSON in request body: {e}")
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid JSON in request body"}).encode())
            return
        except Exception as e:
            logger.error(f"Error reading request body: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Internal server error reading request body"}).encode())
            return

        grant_type = body.get('grant_type')

        if grant_type == 'authorization_code':
            # Yetkilendirme Kodu Akışı
            if 'code' not in body or 'redirect_uri' not in body or 'code_verifier' not in body:
                logger.warning("Missing parameters for authorization_code grant type.")
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing required parameters for authorization_code flow"}).encode())
                return

            payload = {
                'grant_type': 'authorization_code',
                'code': body['code'],
                'redirect_uri': body['redirect_uri'],
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'code_verifier': body['code_verifier']
            }
            logger.info(f"Processing authorization_code flow with payload: {payload}")

        elif grant_type == 'refresh_token':
            # Yenileme Belirteci Akışı
            if 'refresh_token' not in body:
                logger.warning("Missing refresh_token for refresh_token grant type.")
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing refresh_token parameter for refresh_token flow"}).encode())
                return

            payload = {
                'grant_type': 'refresh_token',
                'refresh_token': body['refresh_token'],
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET
            }
            logger.info(f"Processing refresh_token flow with payload: {payload}")

        else:
            logger.warning(f"Unsupported grant_type received: {grant_type}")
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unsupported grant_type"}).encode())
            return

        # Kick API'ye istek gönderme
        try:
            response = requests.post('https://id.kick.com/oauth/token', data=payload)
            response.raise_for_status() # HTTP 4xx/5xx hatalarını yakala

            logger.info(f"Successfully received response from Kick API. Status: {response.status_code}")
            self.send_response(response.status_code)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response.text.encode())

        except requests.exceptions.RequestException as e:
            logger.error(f"Error communicating with Kick API: {e}")
            if e.response is not None:
                error_details = e.response.text
                logger.error(f"Kick API response error details: {error_details}")
            else:
                error_details = str(e)

            self.send_response(502) # Bad Gateway
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Failed to communicate with Kick API", "details": error_details}).encode())
        except Exception as e:
            logger.critical(f"An unexpected error occurred: {e}", exc_info=True) # Diğer tüm hataları yakala
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "An unexpected server error occurred"}).encode())
        return

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        return
