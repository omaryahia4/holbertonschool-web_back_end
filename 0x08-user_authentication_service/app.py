#!/usr/bin/env python3
"""Module"""
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


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token() -> str:
    """reset password route"""
    try:
        email = request.form.get('email')
        if email:
            token = AUTH.get_reset_password_token(email)
            return jsonify({"email": email,
                           "reset_token": token}), 200
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """Update password route"""
    email = request.form.get('email')
    token = request.form.get('reset_token')
    password = request.form.get('new_password')
    try:
        AUTH.update_password(token, password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except Exception:
        abort(403)


if __name__ == "__main__":
    """main function"""
    app.run(host="0.0.0.0", port="5000", debug=True)
