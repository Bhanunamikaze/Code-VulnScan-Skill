# BENCHMARK: vulnerable - path_traversal
from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    filename = request.args.get("file")
    with open(filename, "rb") as f:
        data = f.read()
    return data
