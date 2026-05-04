# BENCHMARK: safe - bleach_sanitization
import bleach
from flask import Flask, request

app = Flask(__name__)
ALLOWED_TAGS = ["b", "i", "em", "strong", "p"]


@app.route("/post")
def show_post():
    raw_content = request.args.get("content", "")
    # Safe: bleach.clean strips disallowed HTML tags
    clean_content = bleach.clean(raw_content, tags=ALLOWED_TAGS)
    return f"<article>{clean_content}</article>"
