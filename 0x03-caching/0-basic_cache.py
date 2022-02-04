#!/usr/bin/env python3
"""Basic dictionary"""
from base_caching import BaseCaching


class BasicCache(BaseCaching):
    """Basic cache class that inherits
    from BaseCaching class"""

    def put(self, key, item):
        """Function that add new items to dictionary"""
        if key is None or item is None:
            pass
        else:
            self.cache_data[key] = item

    def get(self, key):
        """Function that gets data from dicitonary"""
        if key is None or key not in self.cache_data:
            return None
        else:
            return self.cache_data[key]
