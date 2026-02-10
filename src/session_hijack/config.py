"""Session Hijack Config"""
SESSION_COOKIE_NAMES = ["PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "session_id", "sid", "connect.sid"]
TOKEN_PATTERNS = ["Bearer", "JWT", "OAuth"]
SNIFF_INTERFACE = "eth0"
LOG_FILE = "sessions.json"
SAFE_MODE = True
