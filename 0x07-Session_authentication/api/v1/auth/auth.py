#!/usr/bin/env python3
""" Module of Auth
"""
from typing import List, TypeVar
from flask import request
from os import getenv


class Auth():
    """class to manage the API authentication.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """public method"""
        special_character: str = '/'
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path in excluded_paths:
            return False
        last_item = path[-1]
        if last_item not in special_character:
            path += '/'
            if path in excluded_paths:
                return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """public method that returns
        None - request will be the Flask request object"""
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        else:
            return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """public method  that returns
        None - request will be the Flask request object"""
        return None

    def session_cookie(self, request=None):
        """method that returns a cookie
        value from a request"""
        if request is None:
            return None
        else:
            _my_session_id = request.cookies.get(getenv('SESSION_NAME'))
            return _my_session_id
