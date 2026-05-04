# BENCHMARK: vulnerable - deserialization
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load_session():
    data = request.data
    session = pickle.loads(data)
    return str(session)
