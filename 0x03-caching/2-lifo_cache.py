#!/usr/bin/env python3
"""LIFO caching"""
from os import remove
from base_caching import BaseCaching


class LIFOCache(BaseCaching):
    """LIFO class"""
    def __init__(self):
        """init function"""
        super().__init__()
        self.remove = ""

    def put(self, key, item):
        """Function that add new items to dictionary"""
        if key and item:
            self.cache_data[key] = item
        if len(self.cache_data) > BaseCaching.MAX_ITEMS:
            self.cache_data.pop(self.remove)
            print("DISCARD: {}".format(self.remove, end=""))
        if key:
            self.remove = key
        else:
            pass

    def get(self, key):
        """Function that gets data from dicitonary"""
        if key is None or key not in self.cache_data:
            return None
        else:
            return self.cache_data[key]
