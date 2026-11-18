from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/run")
def run():
    target = request.args.get("target")
    os.system("nslookup " + target)
    return "ok"
