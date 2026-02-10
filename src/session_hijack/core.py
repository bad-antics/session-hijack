"""Session Hijack Core"""
import hashlib, base64, json, time, os, re

class SessionExtractor:
    COOKIE_PATTERNS = [
        re.compile(r"Cookie:\s*(.+?)(?:\r\n|$)", re.I),
        re.compile(r"Set-Cookie:\s*(.+?)(?:\r\n|$)", re.I),
        re.compile(r"Authorization:\s*Bearer\s+([\w\-._~+/]+=*)", re.I),
    ]
    
    def extract_from_header(self, http_data):
        sessions = []
        for pattern in self.COOKIE_PATTERNS:
            matches = pattern.findall(http_data)
            for m in matches:
                sessions.append({"type": "cookie" if "Cookie" in pattern.pattern else "token", "value": m,
                                "timestamp": time.time()})
        return sessions
    
    def parse_jwt(self, token):
        try:
            parts = token.split(".")
            if len(parts) != 3: return None
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            return {"header": header, "payload": payload, "signature": parts[2],
                    "expired": payload.get("exp", float("inf")) < time.time()}
        except: return None

class SessionAnalyzer:
    def analyze_cookie(self, cookie_str):
        """Analyze cookie security properties"""
        flags = {"httponly": "httponly" in cookie_str.lower(),
                "secure": "secure" in cookie_str.lower(),
                "samesite": "samesite" in cookie_str.lower(),
                "path": "/" in cookie_str}
        vulnerabilities = []
        if not flags["httponly"]: vulnerabilities.append("Missing HttpOnly flag - XSS risk")
        if not flags["secure"]: vulnerabilities.append("Missing Secure flag - transmission risk")
        if not flags["samesite"]: vulnerabilities.append("Missing SameSite - CSRF risk")
        return {"flags": flags, "vulnerabilities": vulnerabilities, "risk": "HIGH" if len(vulnerabilities) >= 2 else "MEDIUM"}
    
    def detect_fixation(self, sessions):
        """Check for session fixation"""
        seen = {}
        fixation = []
        for s in sessions:
            val = s["value"]
            if val in seen:
                if s.get("source_ip") != seen[val].get("source_ip"):
                    fixation.append({"session": val, "ips": [seen[val].get("source_ip"), s.get("source_ip")]})
            else: seen[val] = s
        return fixation
