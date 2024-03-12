#!/usr/bin/env python3
"""Redis module"""

from functools import wraps
import redis
import uuid
from typing import Union, Optional, Callable


def count_calls(method: Callable) -> Callable:
    """ Decortator for counting how many times a function
    has been called """

    key = method.__qualname__

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        """ Wrapper for decorator functionality """
        self._redis.incr(key)
        return method(self, *args, **kwargs)

    return wrapper


def replay(fn: Callable):
    """Display the history of calls of a particular function"""
    r = redis.Redis()
    method_name = fn.__qualname__
    inps = r.lrange(method_name + ":inputs", 0, -1)
    outps = r.lrange(method_name + ":outputs", 0, -1)
    n_calls = int(r.get(method_name))
    if (n_calls == 1):
        print(f'{method_name} was called {n_calls} time:')
    else:
        print(f'{method_name} was called {n_calls} times:')
    for inps, outpts in zip(inps, outps):
        msg = '{}(*{}) -> {}'.format(
            method_name, inps.decode('utf-8'), outpts.decode('utf-8'))
        print(msg)


def call_history(method: Callable) -> Callable:
    """ Decorator to store the history of inputs and
    outputs for a particular function.
    """

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        """ Wrapper for decorator functionality """
        input = str(args)
        self._redis.rpush(method.__qualname__ + ":inputs", input)
        output = str(method(self, *args, **kwargs))
        self._redis.rpush(method.__qualname__ + ":outputs", output)

        return output

    return wrapper


class Cache():
    """Cache class"""
    def __init__(self):
        """Intizializer"""
        self._redis = redis.Redis()
        self._redis.flushdb()

    @call_history
    @count_calls
    def store(self, data: Union[str, bytes, int, float]) -> str:
        """ method that stores the input data in Redis
        using the random key and returns the key"""
        key = str(uuid.uuid4())
        self._redis.set(key, data)
        return key

    def get(self, key: str, fn:
            Optional[Callable] = None) -> Union[str, bytes, int, float]:
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
