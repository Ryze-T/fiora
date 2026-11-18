import pickle
from flask import Flask, request
app = Flask(__name__)

@app.route("/import", methods=["POST"])
def import_state():
    data = request.get_data()
    obj = pickle.loads(data)
    return {"ok": True}
