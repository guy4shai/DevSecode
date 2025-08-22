import yaml
import requests
import subprocess
import os
import hashlib
import pickle
import jwt
import tempfile
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/eval", methods=["POST"])
def unsafe_eval():
    data = request.form.get("code")
    # ⚠️ Arbitrary code execution
    result = eval(data)
    return str(result)

@app.route("/run", methods=["POST"])
def run_command():
    cmd = request.form.get("cmd")
    # ⚠️ Shell injection risk
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()

@app.route("/pickle", methods=["POST"])
def unsafe_pickle():
    data = request.data
    # ⚠️ Arbitrary deserialization vulnerability
    obj = pickle.loads(data)
    return str(obj)

@app.route("/jwt", methods=["GET"])
def insecure_jwt():
    payload = {"user": "admin"}
    # ⚠️ JWT חתום במפתח חלש מאוד
    token = jwt.encode(payload, "123", algorithm="HS256")
    return token

@app.route("/tmpfile")
def insecure_tempfile():
    # ⚠️ Temporary file without secure flags
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(b"Sensitive data")
    tmp.close()
    return f"Temp file at {tmp.name}"

@app.route("/set-cookie")
def insecure_cookie():
    # ⚠️ Cookie without secure or httponly flags
    resp = make_response("Setting insecure cookie")
    resp.set_cookie("session", "abc123")
    return resp

@app.route("/")
def index():
    r = requests.get("http://example.com")
    return r.text

# 🔐 סיסמה קשיחה בקוד (Bandit)
password = "supersecret123"

# ⚠️ subprocess עם shell=True (Bandit)
subprocess.call("ls -l", shell=True)

# 🐍 שימוש במודול os לביצוע פקודה (Bandit)
os.system("echo vulnerable")

# ❌ שימוש בפונקציות שלא הוגדרו (לא חולשה אבל קוד לא תקין)
print(get_md5("sally"))
check(0)

if __name__ == "__main__":
    app.run(debug=True)

# --- Slack and Discord Webhooks ---
slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# --- Stripe and PayPal Keys ---
stripe_secret_key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

# --- API Keys for Common Services ---

# --- JWT and SSH Private Keys ---
private_ssh_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzY4QWEXAMPLEFAKEKEYFORTESTONLY28F8Z1ER1dZf
-----END RSA PRIVATE KEY-----
"""
