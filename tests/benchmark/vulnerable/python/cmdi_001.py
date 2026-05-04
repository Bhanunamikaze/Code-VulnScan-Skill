# BENCHMARK: vulnerable - cmdi
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True)
    return result.stdout
