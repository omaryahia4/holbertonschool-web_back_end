#!/usr/bin/env python3
"""LRU caching"""
from base_caching import BaseCaching


class LRUCache(BaseCaching):
    """LIFO class"""
    def __init__(self):
        """init function"""
        super().__init__()

    def put(self, key, item):
        """Function that add new items to dictionary"""
        if key and item:
            self.cache_data[key] = item
        if key in self.cache_data:
            self.cache_data.pop(key)
            self.cache_data[key] = item
        if len(self.cache_data) > BaseCaching.MAX_ITEMS:
            first = list(self.cache_data)[0]
            self.cache_data.pop(first)
            print("DISCARD: {}".format(first, end=""))
        if key is None or item is None:
            pass

    def get(self, key):
        """Function that gets data from dicitonary"""
        if key is None or key not in self.cache_data:
            return None
        if key in self.cache_data:
            self.cache_data[key] = self.cache_data.pop(key)
            return self.cache_data[key]
        else:
            return self.cache_data[key]
