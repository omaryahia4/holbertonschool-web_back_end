#!/usr/bin/env python3
""" Module of Auth
"""
from flask import request
from typing import List, TypeVar


class Auth():
    """"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """public method"""
        return False

    def authorization_header(self, request=None) -> str:
        """public method that returns
        None - request will be the Flask request object"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """public method  that returns
        None - request will be the Flask request object"""
        return None
