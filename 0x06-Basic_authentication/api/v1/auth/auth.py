#!/usr/bin/env python3
""" Module of Auth
"""
from typing import List, TypeVar


class Auth():
    """class to manage the API authentication.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """public method"""
        special_character = '/'
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True
        if path in excluded_paths:
            return False
        last_item = path[-1]
        if last_item not in special_character:
            path += '/'
            if path in excluded_paths:
                return False
        if last_item in special_character:
            if path in excluded_paths:
                return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """public method that returns
        None - request will be the Flask request object"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """public method  that returns
        None - request will be the Flask request object"""
        return None
