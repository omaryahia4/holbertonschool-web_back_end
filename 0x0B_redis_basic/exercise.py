#!/usr/bin/env python3
"""Redis module"""
import redis
import uuid
from typing import TypeVar


class Cache():
    """Cache class"""
    def __init__(self):
        """Intizializer"""
    _redis = redis.Redis()
    _redis.flushdb()

    def store(self, data: TypeVar) -> str:
        """ method that stores the input data in Redis
        using the random key and returns the key"""
        key = str(uuid.uuid4())
        self._redis.set(key, data)
        return key
