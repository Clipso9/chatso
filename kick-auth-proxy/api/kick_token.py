from http.server import BaseHTTPRequestHandler
import json
import os
import requests

class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        CLIENT_ID = os.environ.get('KICK_CLIENT_ID')
        CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET')

        if not CLIENT_ID or not CLIENT_SECRET:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Server configuration error"}).encode())
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        body = json.loads(post_data)

        if 'code' not in body or 'redirect_uri' not in body or 'code_verifier' not in body:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Missing required parameters"}).encode())
            return
            
        payload = {
            'grant_type': 'authorization_code',
            'code': body['code'],
            'redirect_uri': body['redirect_uri'],
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code_verifier': body['code_verifier']
        }

        try:
            response = requests.post('https://id.kick.com/oauth/token', data=payload)
            response.raise_for_status()
            
            self.send_response(response.status_code)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response.text.encode())

        except requests.exceptions.RequestException as e:
            self.send_response(502)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            error_details = str(e.response.text) if e.response else str(e)
            self.wfile.write(json.dumps({"error": "Failed to communicate with Kick API", "details": error_details}).encode())
        return

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        return
