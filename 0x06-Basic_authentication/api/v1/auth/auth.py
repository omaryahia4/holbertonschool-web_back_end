#!/usr/bin/env python3
""" Module of Auth
"""
from typing import List, TypeVar
from flask import request


class Auth():
    """class to manage the API authentication.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
    ''' require authorithation '''
    if path is None or excluded_paths is None or not len(excluded_paths):
        return True
    if path[-1] != '/':
        path += '/'
    for i in excluded_paths:
        if i.endswith('*'):
            if path.startswith(i[:1]):
                return True
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
