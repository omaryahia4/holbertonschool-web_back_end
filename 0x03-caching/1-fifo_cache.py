#!/usr/bin/env python3
"""FIFO caching"""
from base_caching import BaseCaching


class FIFOCache(BaseCaching):
    """FIFO class"""
    def __init__(self):
        """init function"""
        super().__init__()

    def put(self, key, item):
        """Function that add new items to dictionary"""
        if key and item:
            self.cache_data[key] = item
        if len(self.cache_data) > BaseCaching.MAX_ITEMS:
            first = list(self.cache_data)[0]
            self.cache_data.pop(first)
            print("DISCARD: {}".format(first, end=""))
        else:
            pass

    def get(self, key):
        """Function that gets data from dicitonary"""
        if key is None or key not in self.cache_data:
            return None
        else:
            return self.cache_data[key]
