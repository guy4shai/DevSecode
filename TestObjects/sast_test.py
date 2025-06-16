# חוק B101 - assert (יוסר או יומר ל-if)
def check_user(age):
    assert age > 0  # B101

# חוק B102 - exec
def dangerous_exec(cmd):
    exec(cmd)  # B102

# חוק B104 - פתיחה על כל האינטרפייסים
import socket
sock = socket.socket()
sock.bind(("0.0.0.0", 8080))  # B104

# חוק B105 - סיסמה קשיחה
db_password = "SuperSecret123!"  # B105

# חוק B108 - קובץ זמני לא מאובטח
import os
tmp_file = open("/tmp/test.txt", "w")  # B108

# חוק B110 - try/except pass
try:
    1 / 0
except:
    pass  # B110

# חוק B201 - Flask debug=True
from flask import Flask
app = Flask(__name__)
app.run(debug=True)  # B201

# חוק B324 - שימוש ב-hashlib לא בטוח
import hashlib
hashlib.new('md4', b'data')  # B324

# חוק B704 - שימוש ב-markupsafe.Markup
from markupsafe import Markup
output = Markup(user_input)  # B704
