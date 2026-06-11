"""
app.py - PhishGuard Flask API
Main application entry point with authentication and MongoDB storage.
"""
 
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from analyzer import analyze_url
from auth import auth_bp, require_auth
from database import get_scans_collection
import logging
 
load_dotenv()
 
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
 
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
 
app.register_blueprint(auth_bp)
 
 
@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "running", "service": "PhishGuard API", "version": "2.0.0"})
 
 
@app.route("/analyze", methods=["POST"])
@require_auth
def analyze():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400
 
    logger.info(f"User '{request.username}' analyzing: {url}")
    result = analyze_url(url)
 
    scans = get_scans_collection()
    scans.insert_one({**result, "user_id": request.user_id, "username": request.username})
 
    return jsonify(result), 200
 
 
@app.route("/history", methods=["GET"])
@require_auth
def history():
    limit = request.args.get("limit", default=50, type=int)
    scans = get_scans_collection()
    records = list(
        scans.find({"user_id": request.user_id}, {"_id": 0})
        .sort("timestamp", -1)
        .limit(limit)
    )
    return jsonify(records), 200
 
 
@app.route("/history", methods=["DELETE"])
@require_auth
def clear_history():
    scans = get_scans_collection()
    result = scans.delete_many({"user_id": request.user_id})
    return jsonify({"message": f"Deleted {result.deleted_count} records"}), 200
 
 
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
