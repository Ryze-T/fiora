import json
import sqlite3

from flask import Flask, request, send_file

app = Flask(__name__)
DB = sqlite3.connect("app.db")


@app.get("/admin/export")
def export():
    cur = DB.execute("SELECT * FROM orders")
    return json.dumps([dict(zip([c[0] for c in cur.description], row)) for row in cur.fetchall()])


@app.get("/files")
def files():
    name = request.args.get("name")
    return send_file(open(name, "rb").read())
