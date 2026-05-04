# BENCHMARK: vulnerable - xss
from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/comment")
def show_comment():
    comment = request.args.get("comment", "")
    safe_comment = Markup(comment)
    return f"<div>{safe_comment}</div>"
