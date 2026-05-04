# BENCHMARK: vulnerable - ssrf
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    resp = requests.get(url)
    return resp.text
