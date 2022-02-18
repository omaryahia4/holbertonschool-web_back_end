#!/usr/bin/env python3
""" Session authentication
Module
"""
from api.v1.auth.auth import Auth
import uuid


class SessionAuth(Auth):
    """Session class"""
    def __init__(self) -> None:
        """Constructor"""
        self.user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """"""
        if user_id is None:
            return None
        if type(user_id) != str:
            return None
        else:
            id = str(uuid.uuid4())
            self.user_id_by_session_id[id] = user_id
            return id
        self.user_id_by_session_id[key] = user_id
