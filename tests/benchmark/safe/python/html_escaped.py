# BENCHMARK: safe - html_escape_before_render
import html
from flask import Flask, request

app = Flask(__name__)


@app.route("/comment")
def show_comment():
    raw_comment = request.args.get("comment", "")
    # Safe: html.escape prevents XSS
    escaped = html.escape(raw_comment)
    return f"<div>{escaped}</div>"
