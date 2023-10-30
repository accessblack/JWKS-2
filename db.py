import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

# SQLite Setup
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
''')


def save_key_to_db(pem_key, expiration_time):
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_key, expiration_time))
    conn.commit()


def fetch_key(expired=False):
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ?", (datetime.datetime.utcnow().timestamp(),))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp >= ?", (datetime.datetime.utcnow().timestamp(),))
    return cursor.fetchone()


# JWKS Server Setup
hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption())

# Save initial keys to DB
save_key_to_db(pem, datetime.datetime.utcnow().timestamp() + 3600)  # Expires in 1 hour
save_key_to_db(pem, datetime.datetime.utcnow().timestamp() - 3600)  # Expired 1 hour ago


class MyServer(BaseHTTPRequestHandler):

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            if 'expired' in params:
                pem_key = fetch_key(True)
            else:
                pem_key = fetch_key()

            # Add your logic for processing the POST request
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("POST request received", "utf-8"))

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            cursor.execute("SELECT kid, key FROM keys WHERE exp >= ?", (datetime.datetime.utcnow().timestamp(),))
            valid_keys = cursor.fetchall()

            # Replace this with your logic to create and send JWKS response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("GET request received", "utf-8"))


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")

