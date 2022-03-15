#!/usr/bin/env python3
"""Redis module"""
from functools import wraps
import redis
import uuid
from typing import Optional, Callable, Union


def count_calls(method: Callable) -> Callable:
    """ Calls counter decorator """
    key = method.__qualname__
    @wraps(method)
    def wrapper(self, *args, **kwds):
        """Incrementation method's wrapper"""
        self._redis.incr(key)
        return method(self, *args, **kwds)
    return wrapper


class Cache():
    """Cache class"""
    def __init__(self):
        """Intizializer"""
        self._redis = redis.Redis()
        self._redis.flushdb()

    @count_calls
    def store(self, data: Union[str, bytes, int, float]) -> str:
        """ method that stores the input data in Redis
        using the random key and returns the key"""
        key = str(uuid.uuid4())
        self._redis.set(key, data)
        return key

    def get(self, key: str, fn: Optional[Callable] = None)\
            -> Union[str, bytes, int, float]:
        """method that converts the data back
        to the desired format."""
        data = self._redis.get(key)
        if fn:
            return fn(data)
        else:
            return data

    def get_str(self, data):
        """method that decodes data"""
        return data.decode("utf-8")

    def get_int(self, data):
        """method that converts data to int"""
        return int(data)
