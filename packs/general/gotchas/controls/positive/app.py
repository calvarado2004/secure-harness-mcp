from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = False
CORS(app, origins="*", supports_credentials=True)
