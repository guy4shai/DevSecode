from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to vulnerable app!"

@app.route('/echo', methods=['GET'])
def echo():
    user_input = request.args.get('input')
    return f"You said: {user_input}"

if __name__ == '__main__':
    app.run(debug=True)
