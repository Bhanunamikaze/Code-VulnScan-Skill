# BENCHMARK: vulnerable - sqli
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={uid}")
    row = cursor.fetchone()
    conn.close()
    return str(row)
