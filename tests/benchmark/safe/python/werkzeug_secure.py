# BENCHMARK: safe - werkzeug_secure_filename
import os
from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_DIR = "/var/app/uploads"


@app.route("/download")
def download():
    raw_name = request.args.get("file", "")
    # Safe: secure_filename strips path separators and dangerous chars
    safe_name = secure_filename(raw_name)
    return send_from_directory(UPLOAD_DIR, safe_name)
