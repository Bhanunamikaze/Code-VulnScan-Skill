# BENCHMARK: safe - sqlalchemy_parameterized
from flask import Flask, request
from sqlalchemy import text, create_engine
from sqlalchemy.orm import Session

app = Flask(__name__)
engine = create_engine("sqlite:///app.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    with Session(engine) as session:
        result = session.execute(
            text("SELECT * FROM users WHERE id=:id"),
            {"id": user_id}
        )
        row = result.fetchone()
    return str(row)
