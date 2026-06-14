# ⬡ PhishGuard — Phishing URL Detection & Analysis Dashboard

> A cybersecurity portfolio project that analyzes URLs for phishing indicators, scores them across 8 threat vectors, and visualizes results in a real-time dark-mode dashboard.

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-F7DF1E?style=flat-square&logo=javascript&logoColor=black)


---

##  Table of Contents

- [Overview](#overview)
- [How Phishing Works](#how-phishing-works)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Example Output](#example-output)
- [Test URLs](#test-urls)
- [Future Improvements](#future-improvements)

---

## Overview

Phishing is one of the most prevalent cyber threats today — attackers craft malicious URLs that impersonate legitimate websites to steal credentials and financial data. PhishGuard is a rule-based URL analysis tool that applies 8 heuristic checks to detect common phishing patterns and classify URLs into **Safe**, **Suspicious**, or **High Risk** categories.

This project demonstrates:
- Backend API design with Python/Flask
- Rule-based threat detection logic
- RESTful API design patterns
- Modern frontend dashboard development
- Data persistence and history tracking

---

## How Phishing Works

Phishing URLs often exhibit predictable patterns:

| Pattern | Example | Why It's Suspicious |
|---------|---------|---------------------|
| IP address as host | `http://192.168.1.1/login` | Avoids domain reputation checks |
| Hyphens in domain | `secure-login-bank.com` | Mimics trusted brands |
| Excessive subdomains | `login.verify.secure.evil.com` | Obscures real domain |
| `@` symbol | `user@evil.com@bank.com` | Browser ignores pre-@ content |
| Suspicious keywords | `/verify`, `/secure`, `/bank` | Targets credential pages |
| Long URLs | 100+ character URLs | Hides true destination |
| HTTP (not HTTPS) | `http://` | No transport encryption |

---

## Features

- **URL Analysis** — Submits any URL for instant rule-based analysis
- **8 Threat Vector Checks** — URL length, IP host, hyphens, subdomains, keywords, @ symbol, HTTP usage, double-slash injection
- **Risk Scoring** — Numeric score from 0–8 with visual bar chart
- **3-Tier Classification** — Safe / Suspicious / High Risk
- **Scan History** — All results stored in `data.json` and displayed in a history table
- **Statistics Dashboard** — Live counters for total scans by classification
- **One-click test URLs** — Built-in sample URLs to demo the tool
- **Dark Mode UI** — Industrial cybersecurity aesthetic with terminal typography

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.9+, Flask 3.0, Flask-CORS |
| Frontend | HTML5, CSS3 (custom properties, CSS Grid), Vanilla JS (ES6+) |
| Data Storage | JSON file (`data.json`) |
| Fonts | Space Mono (monospace), DM Sans (UI) via Google Fonts |

---

## Project Structure

```
phishing-detector/
│
├── backend/
│   ├── app.py          # Flask app — API routes
│   ├── analyzer.py     # URL analysis engine — all detection logic
│   ├── utils.py        # History persistence helpers
│   └── data.json       # Analysis history store
│
├── frontend/
│   ├── index.html      # Dashboard markup
│   ├── styles.css      # Dark theme styles
│   └── script.js       # API calls & dynamic rendering
│
├── README.md
└── requirements.txt
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- A modern web browser

### Step 1 — Clone the Repository

```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
```

### Step 2 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Start the Flask Server

```bash
cd backend
python app.py
```

You should see:
```
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

### Step 4 — Open the Frontend

In a new terminal or file explorer, open:

```
frontend/index.html
```

Or serve it with Python's built-in HTTP server:

```bash
cd frontend
python -m http.server 8080
```

Then navigate to `http://localhost:8080` in your browser.

>  **Important:** The Flask server must be running on port 5000 for the frontend to work.

---

## Usage

1. **Enter a URL** in the input field (with or without `https://`)
2. **Click ANALYZE** or press Enter
3. **View the result card** showing:
   - Risk classification (Safe / Suspicious / High Risk)
   - Numeric score out of 8
   - List of triggered threat indicators
4. **Check the history table** to review previous scans
5. **Use quick test buttons** to demo with sample URLs

---

## API Reference

### `POST /analyze`

Analyze a URL for phishing indicators.

**Request Body:**
```json
{
  "url": "http://secure-login-bank.com/verify"
}
```

**Response:**
```json
{
  "url": "http://secure-login-bank.com/verify",
  "score": 4,
  "status": "High Risk",
  "reasons": [
    "Contains suspicious keywords: login, secure, verify, bank",
    "Uses HTTP instead of HTTPS (unencrypted connection)",
    "Domain contains 2 hyphens — common phishing pattern"
  ],
  "details": {
    "url_length": false,
    "at_symbol": false,
    "hyphen_in_domain": true,
    "subdomain_depth": false,
    "ip_address": false,
    "suspicious_keywords": true,
    "https": true,
    "double_slash": false
  },
  "timestamp": "2024-01-15T14:32:11Z"
}
```

### `GET /history?limit=N`

Returns the last N analysis records (default: 50).

### `DELETE /history`

Clears all stored history.

### `GET /`

Health check — returns server status.

---

## Example Output

### High Risk URL

```
Input:  http://secure-login-bank.com/verify?account=update
Score:  5/8
Status: 🔴 High Risk

Triggers:
  • URL is unusually long (62 characters)
  • Contains suspicious keywords: login, secure, verify, bank, update
  • Uses HTTP instead of HTTPS
  • Domain contains 2 hyphens
  • Contains '@' symbol
```

### Safe URL

```
Input:  https://google.com
Score:  0/8
Status: 🟢 Safe

Triggers:
  ✓ No phishing indicators detected
```

---

## Test URLs

| URL | Expected |
|-----|----------|
| `http://secure-login-bank.com/verify?update=true&account=123` | 🔴 High Risk |
| `http://192.168.0.1/login` | 🔴 High Risk |
| `http://paypal-login.secure-verify.com` | 🟡 Suspicious |
| `http://amazon.com.login.phish.net/secure` | 🔴 High Risk |
| `https://microsoft.com` | 🟢 Safe |
| `https://google.com` | 🟢 Safe |

---

## Scoring Logic

```
Score  0–1  →  🟢 Safe
Score  2–3  →  🟡 Suspicious
Score  4+   →  🔴 High Risk
```

Each of the 8 checks adds +1 to the score:
1. URL length > 75 characters
2. `@` symbol present
3. 2+ hyphens in domain
4. More than 3 dots in domain (subdomain depth)
5. IP address used as host
6. Suspicious keywords (login, verify, secure, update, bank, etc.)
7. Uses HTTP instead of HTTPS
8. Double-slash injection in path

---

## Future Improvements

| Feature | Description |
|---------|-------------|
|  ML Detection | Train a classifier on the [ISCX URL Dataset](https://www.unb.ca/cic/datasets/url-2016.html) for higher accuracy |
|  WHOIS Lookup | Check domain age — newly registered domains are higher risk |
|  SSL Verification | Verify the SSL certificate's validity and issuer |
|  Threat Intelligence | Integrate VirusTotal or PhishTank APIs for real-time blacklist checks |
|  Docker | Containerize the full stack with `docker-compose` |
|  Auth | Add API key authentication for the backend |
|  Analytics | Charts for threat trends over time |
|  Alerts | Email/Slack notifications when High Risk URLs are detected |

---



*PhishGuard does not provide 100% accurate phishing detection. It is an educational tool demonstrating rule-based heuristic analysis. For production use, integrate with threat intelligence APIs.*
