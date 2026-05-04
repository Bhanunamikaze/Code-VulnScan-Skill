# BENCHMARK: safe - yaml_safe_load
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def load_config():
    raw = request.data.decode("utf-8")
    # Safe: yaml.safe_load disallows arbitrary Python object instantiation
    config = yaml.safe_load(raw)
    return str(config.get("key", ""))
