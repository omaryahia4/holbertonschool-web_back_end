#!/usr/bin/env python3
"""Auth model"""
import bcrypt
import uuid
from user import User
from db import DB
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """method that takes in a password
     string arguments and returns bytes"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """string representation of a new UUID."""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Method that Registers new users"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {user.email} already exists")
        except NoResultFound:
            password = _hash_password(password)
            user = self._db.add_user(email, password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Credentials validation"""
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
                return True
            return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """create session id"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                user.session_id = _generate_uuid()
                self._db._session.add(user)
                self._db._session.commit()
                return user.session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User or None:
        """ get user by session_id"""
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy session"""
        try:
            user = self._db.find_user_by(id=user_id)
            return setattr(user, 'session_id', None)
        except Exception:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Generate and reset password token"""
        try:
            user = self._db.find_user_by(email=email)
            user.reset_token = _generate_uuid()
            self._db._session.add(user)
            self._db._session.commit()
            return user.reset_token
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Method that Updates password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            if user:
                password = _hash_password(password)
                setattr(user, user.hashed_password, password)
                setattr(user, user.reset_token, None)
        except NoResultFound:
            raise ValueError
