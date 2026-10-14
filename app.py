"""
CyberThreatMiner: Web Application Entry Point.
Course: 23PCIT503 - Machine Learning Mini Project
Cyberattack Technique Association Mining Using the Apriori Algorithm.
"""
import os
import sys
from flask import Flask, send_from_directory
from flask_cors import CORS
from backend.api.routes import api_bp

app = Flask(__name__, static_folder="static", static_url_path="")

# Restrict CORS strictly to localhost
CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                r"^https?://127\.0\.0\.1(:\d+)?$",
                r"^https?://localhost(:\d+)?$"
            ]
        }
    }
)

# Register API Blueprint under /api
app.register_blueprint(api_bp, url_prefix="/api")


@app.get("/")
def index():
    """Serves the primary Single Page Application dashboard."""
    return send_from_directory("static", "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "app": "CyberThreatMiner", "version": "3.0.0"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    # Default to debug=False and host=127.0.0.1; enable debug only via an explicit DEBUG=1 env var
    debug = os.environ.get("DEBUG", "0") == "1"
    host = "127.0.0.1"
    print(f"Starting CyberThreatMiner on http://{host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug)
