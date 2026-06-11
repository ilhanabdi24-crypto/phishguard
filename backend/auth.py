"""
auth.py - Authentication routes
Handles user signup, login, and JWT token verification.
"""

import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify
from database import get_users_collection
from dotenv import load_dotenv

load_dotenv()

auth_bp = Blueprint("auth", __name__)

JWT_SECRET = os.getenv("JWT_SECRET", "fallback-secret-change-this")
JWT_EXPIRY_HOURS = 24


# ─── Helper: generate JWT token ────────────────────────────────────────────

def generate_token(user_id: str, username: str) -> str:
    payload = {
        "user_id": str(user_id),
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


# ─── Helper: require auth decorator ────────────────────────────────────────

def require_auth(f):
    """Decorator that protects routes — requires a valid JWT token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Token can be in Authorization header: "Bearer <token>"
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_id = payload["user_id"]
            request.username = payload["username"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated


# ─── Route: Sign Up ─────────────────────────────────────────────────────────

@auth_bp.route("/signup", methods=["POST"])
def signup():
    """
    Register a new user.
    Body: { "username": "...", "email": "...", "password": "..." }
    """
    data = request.get_json()

    # Validate fields
    required = ["username", "email", "password"]
    for field in required:
        if not data or not data.get(field, "").strip():
            return jsonify({"error": f"'{field}' is required"}), 400

    username = data["username"].strip().lower()
    email    = data["email"].strip().lower()
    password = data["password"]

    # Password strength check
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    users = get_users_collection()

    # Check for existing user
    if users.find_one({"$or": [{"username": username}, {"email": email}]}):
        return jsonify({"error": "Username or email already exists"}), 409

    # Hash password with bcrypt
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Insert new user
    result = users.insert_one({
        "username": username,
        "email": email,
        "password": hashed,
        "created_at": datetime.utcnow().isoformat() + "Z"
    })

    token = generate_token(result.inserted_id, username)

    return jsonify({
        "message": "Account created successfully",
        "token": token,
        "username": username
    }), 201


# ─── Route: Log In ──────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate an existing user.
    Body: { "username": "...", "password": "..." }
    """
    data = request.get_json()

    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Username and password are required"}), 400

    username = data["username"].strip().lower()
    password = data["password"]

    users = get_users_collection()
    user = users.find_one({"username": username})

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"error": "Invalid username or password"}), 401

    token = generate_token(user["_id"], username)

    return jsonify({
        "message": "Login successful",
        "token": token,
        "username": username
    }), 200


# ─── Route: Verify Token ────────────────────────────────────────────────────

@auth_bp.route("/verify", methods=["GET"])
@require_auth
def verify():
    """Check if current token is still valid."""
    return jsonify({
        "valid": True,
        "username": request.username
    }), 200