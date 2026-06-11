"""
analyzer.py - Core URL analysis engine
Applies rule-based checks AND live connectivity checks on any URL.
"""

import re
import socket
import ssl
import urllib.request
import urllib.error
from datetime import datetime


# ─── Suspicious keywords commonly found in phishing URLs ───────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "bank",
    "account", "password", "confirm", "signin", "wallet",
    "paypal", "ebay", "amazon", "apple", "microsoft"
]

# ─── Risk classification thresholds ────────────────────────────────────────
def classify(score: int) -> str:
    if score <= 1:
        return "Safe"
    elif score <= 3:
        return "Suspicious"
    else:
        return "High Risk"


# ─── Individual check functions ────────────────────────────────────────────

def check_url_length(url: str) -> tuple[bool, str]:
    """URLs longer than 75 characters are often obfuscated."""
    if len(url) > 75:
        return True, f"URL is unusually long ({len(url)} characters)"
    return False, ""


def check_at_symbol(url: str) -> tuple[bool, str]:
    """The '@' symbol in a URL causes browsers to ignore everything before it."""
    if "@" in url:
        return True, "Contains '@' symbol — browser ignores everything before it"
    return False, ""


def check_hyphen_in_domain(url: str) -> tuple[bool, str]:
    """
    Excessive hyphens in the domain are a classic phishing trick
    e.g. secure-login-bank.com
    """
    # Extract domain portion only (between // and first /)
    try:
        domain_part = re.split(r"//", url, 1)[1].split("/")[0]
        hyphen_count = domain_part.count("-")
        if hyphen_count >= 2:
            return True, f"Domain contains {hyphen_count} hyphens — common phishing pattern"
    except IndexError:
        pass
    return False, ""


def check_subdomain_depth(url: str) -> tuple[bool, str]:
    """
    Too many subdomains (more than 3 dots in the domain) suggest obfuscation.
    e.g. login.verify.secure.evil.com
    """
    try:
        domain_part = re.split(r"//", url, 1)[1].split("/")[0]
        dot_count = domain_part.count(".")
        if dot_count > 3:
            return True, f"Excessive subdomains detected ({dot_count} dots in domain)"
    except IndexError:
        pass
    return False, ""


def check_ip_address(url: str) -> tuple[bool, str]:
    """
    Legitimate sites use domain names, not raw IP addresses.
    e.g. http://192.168.1.1/login
    """
    ip_pattern = re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}"
    )
    if ip_pattern.match(url):
        return True, "Uses IP address instead of a domain name"
    return False, ""


def check_suspicious_keywords(url: str) -> tuple[bool, str]:
    """Check for phishing-related keywords in the URL."""
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found:
        return True, f"Contains suspicious keywords: {', '.join(found)}"
    return False, ""


def check_https(url: str) -> tuple[bool, str]:
    """HTTP (not HTTPS) is less trustworthy, especially for sensitive pages."""
    if url.startswith("http://"):
        return True, "Uses HTTP instead of HTTPS (unencrypted connection)"
    return False, ""


def check_double_slash(url: str) -> tuple[bool, str]:
    """Double slashes in the path are used to redirect to malicious sites."""
    path = url.split("//", 1)[-1]  # skip protocol slashes
    if "//" in path:
        return True, "Contains suspicious double-slash redirection in path"
    return False, ""


def check_domain_resolves(url: str) -> tuple[bool, str]:
    """Check if the domain actually resolves via DNS — fake sites often don't."""
    try:
        domain = re.split(r"//", url, 1)[1].split("/")[0].split(":")[0]
        socket.gethostbyname(domain)
        return False, ""  # resolves fine — not suspicious
    except socket.gaierror:
        return True, "Domain does not resolve — may be fake or offline"
    except Exception:
        return False, ""


def check_ssl_valid(url: str) -> tuple[bool, str]:
    """Check if HTTPS URLs have a valid SSL certificate."""
    if not url.startswith("https://"):
        return False, ""  # skip — HTTP already flagged separately
    try:
        domain = re.split(r"//", url, 1)[1].split("/")[0].split(":")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
        return False, ""  # valid SSL
    except ssl.SSLCertVerificationError:
        return True, "SSL certificate is invalid or untrusted"
    except Exception:
        return False, ""  # can't check — don't penalise


def check_redirects(url: str) -> tuple[bool, str]:
    """Follow redirects and flag if the final destination domain differs."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            final_url = resp.geturl()
        # Extract original and final domains
        orig_domain = re.split(r"//", url, 1)[1].split("/")[0]
        final_domain = re.split(r"//", final_url, 1)[1].split("/")[0]
        if orig_domain != final_domain:
            return True, f"URL redirects to a different domain: {final_domain}"
    except Exception:
        pass  # timeout or connection error — skip silently
    return False, ""


# ─── Main analysis function ─────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Run all checks on a URL and return a structured result dict.

    Returns:
        {
            "url": str,
            "score": int,
            "status": str,
            "reasons": list[str],
            "details": dict,
            "timestamp": str
        }
    """
    checks = [
        check_url_length,
        check_at_symbol,
        check_hyphen_in_domain,
        check_subdomain_depth,
        check_ip_address,
        check_suspicious_keywords,
        check_https,
        check_double_slash,
        check_domain_resolves,
        check_ssl_valid,
        check_redirects,
    ]

    reasons = []
    details = {}

    for check_fn in checks:
        triggered, reason = check_fn(url)
        check_name = check_fn.__name__.replace("check_", "")
        details[check_name] = triggered
        if triggered:
            reasons.append(reason)

    score = len(reasons)
    status = classify(score)

    return {
        "url": url,
        "score": score,
        "status": status,
        "reasons": reasons,
        "details": details,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
