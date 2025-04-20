import hashlib
import os
import subprocess

# 🔐 סיסמה קשיחה בקוד (Bandit)
password = "supersecret123"

# ⚠️ שימוש ב-eval (Bandit + Semgrep)
user_input = input("Enter code to run: ")
eval(user_input)

# ⚠️ subprocess עם shell=True (Bandit)
subprocess.call("ls -l", shell=True)

# ⚠️ Hashing לא מאובטח (Semgrep)
def get_md5(data):
    return hashlib.md5(data.encode()).hexdigest()

# ⚠️ assert בקוד פרודקשן (Semgrep)
def check(value):
    assert value != 0, "Value must not be zero"

# 🐍 שימוש במודול os לביצוע פקודה (Bandit)
os.system("echo vulnerable")

print(get_md5("sally"))
check(0)
