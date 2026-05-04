# BENCHMARK: safe - path_realpath_check
import os
from flask import Flask, request, abort

app = Flask(__name__)
SAFE_DIR = os.path.realpath("/var/app/files")


@app.route("/download")
def download():
    raw_path = request.args.get("file", "")
    # Safe: realpath resolves .. traversals, startswith ensures within safe dir
    full_path = os.path.realpath(os.path.join(SAFE_DIR, raw_path))
    if not full_path.startswith(SAFE_DIR + os.sep):
        abort(403)
    with open(full_path, "rb") as f:
        return f.read()
