#!/usr/bin/env python3
""" Redis exercise """

import requests
import redis
from typing import Callable
from functools import wraps

redis_client = redis.Redis()


def cache_and_count(method: Callable) -> Callable:
    """
    Decorator to store the history of inputs and outputs
    """

    @wraps(method)
    def wrapper(url: str) -> str:
        """
        Wrapper function
        """
        cached_key = f"cached:{url}"
        count_key = f"count:{url}"

        redis_client.incr(count_key)

        cached_response = redis_client.get(cached_key)
        if cached_response:
            return cached_response.decode()

        response = method(url)
        redis_client.setex(cached_key, 10, response)
        return response
    return wrapper


@cache_and_count
def get_page(url: str) -> str:
    """
    Get a page
    """
    response = requests.get(url)
    return response.text
