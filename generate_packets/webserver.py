#! env python

from flask import Flask, make_response
import uuid
app = Flask(__name__)

MAGIC_COOKIE = "DEADBEEF-CAFE-FADE-FEED-DEADBEEF" # roughly uuid size

@app.route("/")
def index():
    resp = make_response("Cookie set to " + MAGIC_COOKIE)
    resp.set_cookie("session", MAGIC_COOKIE)
    return resp;

@app.route("/random")
def random():
    return str(uuid.uuid4())

