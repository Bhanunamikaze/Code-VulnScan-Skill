# BENCHMARK: vulnerable - cmdi
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/convert")
def convert():
    filename = request.args.get("filename", "")
    os.system("convert " + filename + " output.png")
    return "done"
