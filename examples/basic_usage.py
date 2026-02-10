from session_hijack.defender import SessionHardener
h = SessionHardener()
print("Secure token:", h.generate_secure_token())
print("CSRF token:", h.generate_csrf_token())
print("Headers:", json.dumps(h.recommended_headers(), indent=2))
import json
