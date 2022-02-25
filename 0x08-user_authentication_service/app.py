#!/usr/bin/env python3
""""""
from flask import Flask, jsonify, abort, request
from auth import Auth
from user import User
from auth import _hash_password
app = Flask(__name__)


AUTH = Auth()
@app.route('/', methods=['GET'])
def hello_app():
    """Home route"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    """Register user route"""
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        if user:
            return jsonify({f"email": {email}, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000", debug=True)
