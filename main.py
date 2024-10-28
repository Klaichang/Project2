from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
from datetime import datetime, timezone, timedelta
import sqlite3

# Server configuration
hostName = "localhost"
serverPort = 8080

# Initialize SQLite database
conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
cursor = conn.cursor()

# Create table for storing keys if it doesn’t exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()

# Helper functions
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def save_key_to_db(key, expiration_time):
    """Save a serialized private key to the database with an expiration time"""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiration_time))
    conn.commit()

# Generate one valid and one expired key for testing
signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = int(datetime.now(timezone.utc).timestamp())
one_hour_later = now + 3600
expired_time = now - 3600
save_key_to_db(signing_key, one_hour_later)
save_key_to_db(signing_key, expired_time)

def get_private_key(expired=False):
    """Retrieve the private key from the database based on expiration"""
    now = int(datetime.now(timezone.utc).timestamp())
    if expired:
        cursor.execute("SELECT kid, key FROM keys WHERE exp < ?", (now,))
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    
    row = cursor.fetchone()
    if row:
        kid, key_pem = row[0], row[1]
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
        )
        return private_key, key_pem, kid  # Return key object, PEM format, and kid
    return None, None, None

# HTTP request handler class
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Retrieve the correct private key based on the 'expired' parameter
            private_key, key_pem, kid = get_private_key(expired='expired' in params)

            if private_key:
                headers = {"kid": str(kid)}  # Set kid from database in header
                token_payload = {
                    "user": "username",
                    "exp": datetime.now(timezone.utc) + timedelta(hours=1) if 'expired' not in params else datetime.now(timezone.utc) - timedelta(hours=1)
                }
                # Sign the JWT using the private key in PEM format
                encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)
                
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found.")
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            now = int(datetime.now(timezone.utc).timestamp())
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
            keys = []
            for row in cursor.fetchall():
                kid, key_pem = row[0], row[1]
                public_key = serialization.load_pem_private_key(
                    key_pem,
                    password=None,
                ).public_key()

                keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_key.public_numbers().n),
                    "e": int_to_base64(public_key.public_numbers().e),
                })
            jwks = {"keys": keys}
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Server started at http://{hostName}:{serverPort}")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    conn.close()
    print("Server stopped.")
