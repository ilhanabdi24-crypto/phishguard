"""
database.py - MongoDB Atlas connection
Handles the single shared database client for the entire app.
"""

import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
import logging

load_dotenv()

logger = logging.getLogger(__name__)

_client = None
_db = None


def get_db():
    """
    Returns the MongoDB database instance.
    Creates a single connection (singleton) and reuses it.
    """
    global _client, _db

    if _db is not None:
        return _db

    mongo_uri = os.getenv("MONGO_URI")

    if not mongo_uri:
        raise ValueError(
            "MONGO_URI not set. Please create a .env file in the backend folder "
            "and add your MongoDB Atlas connection string."
        )

    try:
        _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        # Test the connection
        _client.admin.command("ping")
        _db = _client["phishguard"]
        logger.info("Connected to MongoDB Atlas successfully.")
        return _db

    except ConnectionFailure as e:
        logger.error(f"MongoDB connection failed: {e}")
        raise


def get_users_collection():
    """Returns the users collection."""
    return get_db()["users"]


def get_scans_collection():
    """Returns the scans collection."""
    return get_db()["scans"]