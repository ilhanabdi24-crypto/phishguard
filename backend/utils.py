"""
utils.py - Utility functions for data persistence
Handles reading/writing analysis history to data.json
"""

import json
import os
import logging

logger = logging.getLogger(__name__)

# Path to the history data file (relative to this file's location)
DATA_FILE = os.path.join(os.path.dirname(__file__), "data.json")


def load_history() -> list:
    """
    Load all stored analysis records from data.json.
    Returns an empty list if the file doesn't exist or is corrupted.
    """
    if not os.path.exists(DATA_FILE):
        return []

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Could not load history: {e}")

    return []


def save_to_history(result: dict) -> bool:
    """
    Append a new analysis result to data.json.
    Creates the file if it doesn't exist.

    Args:
        result: The analysis result dict to store

    Returns:
        True on success, False on failure
    """
    history = load_history()
    history.append(result)

    # Keep last 500 records to prevent unbounded growth
    if len(history) > 500:
        history = history[-500:]

    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        return True
    except IOError as e:
        logger.error(f"Failed to save history: {e}")
        return False


def get_stats() -> dict:
    """
    Calculate aggregate statistics from analysis history.
    """
    history = load_history()
    total = len(history)

    if total == 0:
        return {"total": 0, "safe": 0, "suspicious": 0, "high_risk": 0}

    safe = sum(1 for r in history if r.get("status") == "Safe")
    suspicious = sum(1 for r in history if r.get("status") == "Suspicious")
    high_risk = sum(1 for r in history if r.get("status") == "High Risk")

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "high_risk": high_risk
    }
