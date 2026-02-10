import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from session_hijack.core import SessionExtractor, SessionAnalyzer
from session_hijack.defender import SessionHardener

class TestExtractor(unittest.TestCase):
    def test_jwt(self):
        e = SessionExtractor()
        # Invalid JWT returns None
        self.assertIsNone(e.parse_jwt("not.a.jwt.token"))

class TestHardener(unittest.TestCase):
    def test_token(self):
        h = SessionHardener()
        t = h.generate_secure_token()
        self.assertGreater(len(t), 20)
    def test_csrf(self):
        h = SessionHardener()
        t = h.generate_csrf_token()
        self.assertEqual(len(t), 64)

if __name__ == "__main__": unittest.main()
