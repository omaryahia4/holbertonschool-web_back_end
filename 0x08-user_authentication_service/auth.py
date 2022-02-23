#!/usr/bin/env python3
"""Auth model"""
import bcrypt
from user import User
from db import DB


def _hash_password(password: str) -> bytes:
    """method that takes in a password
     string arguments and returns bytes"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Method that Registers new users"""
        try:
            user = DB.find_user_by(email)
            if user:
                raise ValueError(f"User {user.email} already exists")
        except Exception:
            password = _hash_password(password)
            user = self._db.add_user(email, password)
            return user
