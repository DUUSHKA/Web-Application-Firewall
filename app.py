from flask import Flask, request, abort
from waf import waf

app = Flask(__name__)
waf_rules = waf.WAF()

@app.before_request
def before_request_func():
    if waf_rules.inspect(request):
        abort(403)

@app.route('/')
def index():
    return "Welcome to the Web Application protected by WAF!"

@app.route('/search')
def search():
    query = request.args.get('q')
    return f"Search results for: {query}"

@app.route('/submit', methods=['POST'])
def submit():
    data = request.form.get('data')
    return f"Data received: {data}"

if __name__ == '__main__':
    app.run(debug=True)