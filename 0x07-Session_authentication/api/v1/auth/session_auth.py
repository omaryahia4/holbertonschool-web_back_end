#!/usr/bin/env python3
""" Session authentication
Module
"""
from api.v1.auth.auth import Auth
import uuid
from models.user import User


class SessionAuth(Auth):
    """Session class"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Method that creates a Session
        ID for a user_id"""
        if user_id is None:
            return None
        if type(user_id) != str:
            return None
        else:
            id = str(uuid.uuid4())
            self.user_id_by_session_id[id] = user_id
            return id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ instance method that returns
        a User ID based on a Session ID"""
        if session_id is None and type(session_id) != str:
            return None
        else:
            return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """ instance method that returns a
        User instance based on a cookie value"""
        val = self.session_cookie(request)
        sess_id = self.user_id_for_session_id(val)
        return User.get(sess_id)

    def destroy_session(self, request=None):
        """ deletes the user session / logout """
        if request is None:
            return False
        id_cookie = self.session_cookie(request)
        if not id_cookie:
            return False
        if not self.user_id_for_session_id(id_cookie):
            return False
        else:
            del self.user_id_by_session_id[id_cookie]
            return True
