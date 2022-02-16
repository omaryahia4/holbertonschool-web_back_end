#!/usr/bin/env python3
""" Module of BasicAuth
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Basic authentication class
    that inherits from Auth class"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """method that that returns the Base64
        part of the Authorization header for a Basic Authentication:"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if authorization_header.split(' ')[0] != 'Basic':
            return None
        else:
            return authorization_header.split(' ')[1]
