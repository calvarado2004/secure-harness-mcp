from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
# A wildcard WITHOUT credentials is a public API, not a defect.
CORS(app, origins="*")
# Credentials WITH a named origin is the correct pairing.
CORS(app, origins=["https://app.example.com"], supports_credentials=True)
