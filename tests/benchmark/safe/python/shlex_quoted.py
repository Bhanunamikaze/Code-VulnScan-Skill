# BENCHMARK: safe - shlex_quote_sanitization
import os
import shlex
from flask import Flask, request

app = Flask(__name__)


@app.route("/convert")
def convert():
    raw_filename = request.args.get("filename", "")
    # Safe: shlex.quote escapes the argument, preventing shell injection
    safe_filename = shlex.quote(raw_filename)
    os.system(f"convert {safe_filename} output.png")
    return "done"
