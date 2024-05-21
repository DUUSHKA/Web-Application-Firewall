import re

class Rule:
    def __init__(self, name, pattern):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)

    def check(self, request):
        # Check URL parameters
        for key, value in request.args.items():
            if self.pattern.search(value):
                return True
        # Check form data
        for key, value in request.form.items():
            if self.pattern.search(value):
                return True
        # Check JSON payload
        if request.is_json:
            data = request.get_json()
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and self.pattern.search(value):
                        return True
        return False

def get_rules():
    return [
        Rule("SQL Injection", r"('|\"|;|--|\b(AND|OR|SELECT|INSERT|DELETE|UPDATE|DROP|UNION|JOIN)\b)"),
        Rule("XSS", r"(<|>|\"|\'|\%3C|\%3E|script|alert|onload|onerror)"),
        Rule("Command Injection", r"(\||&|;|`|>|<|\$|\b(cat|ls|dir|rm|touch|echo)\b)"),
        Rule("Directory Traversal", r"(\.\./|\.\.\\|/etc/passwd|/windows|/system32)")
    ]
