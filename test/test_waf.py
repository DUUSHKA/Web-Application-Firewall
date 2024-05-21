import unittest
from flask import Flask, request
from waf import waf

class TestWAF(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.client = self.app.test_client()
        self.waf = waf.WAF()

        @self.app.route('/test', methods=['GET', 'POST'])
        def test():
            if self.waf.inspect(request):
                return "Blocked", 403
            return "OK", 200

    def test_sql_injection(self):
        response = self.client.get('/test?id=1\' OR \'1\'=\'1')
        self.assertEqual(response.status_code, 403)

    def test_xss(self):
        response = self.client.get('/test?q=<script>alert(\'XSS\')</script>')
        self.assertEqual(response.status_code, 403)

    def test_command_injection(self):
        response = self.client.post('/test', data={'data': 'echo test'})
        self.assertEqual(response.status_code, 403)

    def test_directory_traversal(self):
        response = self.client.get('/test?file=../../etc/passwd')
        self.assertEqual(response.status_code, 403)

    def test_valid_request(self):
        response = self.client.get('/test?id=1')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
