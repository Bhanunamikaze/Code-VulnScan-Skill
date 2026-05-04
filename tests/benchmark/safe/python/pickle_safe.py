# BENCHMARK: safe - json_instead_of_pickle
import json
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load_session():
    raw = request.data.decode("utf-8")
    # Safe: json.loads does not execute arbitrary code
    session = json.loads(raw)
    return str(session.get("user_id", ""))
