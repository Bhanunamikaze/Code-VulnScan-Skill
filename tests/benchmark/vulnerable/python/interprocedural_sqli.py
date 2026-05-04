# BENCHMARK: vulnerable - sqli (interprocedural)
import sqlite3
from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect(":memory:", check_same_thread=False)


def run_query(query_str):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username='{query_str}'")
    return cursor.fetchall()


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = run_query(q)
    return str(results)
