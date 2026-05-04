# Intentionally vulnerable Python — used for test fixtures ONLY
# Do NOT deploy this code
import os, pickle, subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    # SQLi via f-string
    q = request.args.get("q")
    conn.execute(f"SELECT * FROM items WHERE name='{q}'")

@app.route("/run")
def run():
    # CMDi via shell=True
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)

@app.route("/file")
def read_file():
    # Path traversal
    name = request.args.get("name")
    with open(name) as f:
        return f.read()

@app.route("/load")
def load():
    # Unsafe deserialization
    data = request.data
    return str(pickle.loads(data))

SECRET_KEY = "hardcoded-secret-1234abcd"
API_TOKEN = "sk-abcdef1234567890abcdef1234567890"
