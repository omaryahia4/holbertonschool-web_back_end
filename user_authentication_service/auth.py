#!/usr/bin/env python3
"""auth module
"""

import bcrypt
import uuid
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Returns the hashed password"""
    bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)

    return hash


def _generate_uuid() -> str:
    """Returns a string representation of a new UUID"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user"""
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(user.email))
        except NoResultFound:
            pass

        hashed_password = _hash_password(password).decode()
        user = self._db.add_user(email, hashed_password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Checks the password. If it matches,
        return True (False otherwise).
        """
        try:
            user = self._db.find_user_by(email=email)
            password = password.encode("utf-8")
            user_password = user.hashed_password.encode("utf-8")
            return bcrypt.checkpw(password, user_password)
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """
        Finds the user corresponding to the email,
        generates a new UUID and stores it in the
        database as the user's session_id.
        Returns the session ID
        """
        try:
            user = self._db.find_user_by(email=email)
            user_id = user.id
            session_id = _generate_uuid()
            self._db.update_user(user_id, session_id=session_id)
            return session_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Returns the corresponding User or None"""
        if not session_id:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session"""
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user_id, session_id=None)
        except Exception:
            return

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a UUID and updates
        the users' reset_token database field
        """
        try:
            user = self._db.find_user_by(email=email)
            user_id = user.id
            reset_token = _generate_uuid()
            self._db.update_user(user_id, reset_token=reset_token)
            return reset_token
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            user_id = user.id
            password = _hash_password(password).decode()
            self._db.update_user(user_id, hashed_password=password,
                                 reset_token=None)
        except Exception:
            raise ValueError
        return None
