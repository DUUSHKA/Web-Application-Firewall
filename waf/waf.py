from . import rules
import logging

class WAF:
    def __init__(self):
        self.rules = rules.get_rules()
        logging.basicConfig(filename='waf.log', level=logging.INFO)

    def inspect(self, request):
        for rule in self.rules:
            if rule.check(request):
                logging.info(f"Blocked by rule: {rule.name}, Request: {request.url}")
                print(f"Blocked by rule: {rule.name}")
                return True
        return False
