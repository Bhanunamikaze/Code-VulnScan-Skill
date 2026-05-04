# BENCHMARK: safe - subprocess_list_no_shell
import subprocess
from flask import Flask, request

app = Flask(__name__)
ALLOWED_DIRS = ["/var/data/uploads", "/tmp/safe"]


@app.route("/list")
def list_files():
    safe_path = "/var/data/uploads"
    # Safe: list form, shell=False prevents shell injection
    result = subprocess.run(["ls", safe_path], shell=False, capture_output=True, text=True)
    return result.stdout
