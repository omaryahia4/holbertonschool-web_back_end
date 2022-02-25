#!/usr/bin/env python3
""""""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth
app = Flask(__name__)


AUTH = Auth()
@app.route('/', methods=['GET'])
def hello_app():
    """Home route"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users() -> str:
    """Register user route"""
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        if user:
            return jsonify({"email": email, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """Sessions route"""
    email = request.form.get('email')
    password = request.form.get('password')
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    res = jsonify({'email': email, 'message': 'logged in'})
    res.set_cookie("session_id", session_id)
    return res


@app.route('/sessions', methods=['DELETE'])
def logout():
    """Delete session route"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user)
        return redirect(url_for('hello_app'))
    else:
        abort(403)

@app.route('/profile', methods=['GET'])
def profile():
    """Profile route"""
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000", debug=True)
