"""Session security hardening"""
import hashlib, secrets, time, json

class SessionHardener:
    def generate_secure_token(self, length=32):
        return secrets.token_urlsafe(length)
    
    def bind_session(self, session_id, client_ip, user_agent):
        fingerprint = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()
        return {"session_id": session_id, "fingerprint": fingerprint, "created": time.time()}
    
    def validate_session(self, session_data, client_ip, user_agent):
        expected = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()
        return session_data.get("fingerprint") == expected
    
    def generate_csrf_token(self):
        return secrets.token_hex(32)
    
    def recommended_headers(self):
        return {"Set-Cookie": "session_id=TOKEN; HttpOnly; Secure; SameSite=Strict; Path=/",
                "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "max-age=31536000"}
