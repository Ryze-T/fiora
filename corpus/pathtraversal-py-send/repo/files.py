from flask import Flask, request, send_file
app = Flask(__name__)

@app.route("/get")
def get():
    name = request.args.get("name")
    return send_file("/srv/files/" + name)
